const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '20mb' })); // увеличен для видеокружков
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Rate limiting — простой in-memory
const rateLimits = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const entry = rateLimits.get(key) || { count: 0, reset: now + windowMs };
  if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
  entry.count++;
  rateLimits.set(key, entry);
  return entry.count > max;
}
// Чистим rate limit каждые 5 минут
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimits) { if (now > v.reset) rateLimits.delete(k); }
}, 5 * 60 * 1000);

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username     TEXT PRIMARY KEY,
      displayname  TEXT NOT NULL,
      password     TEXT NOT NULL,
      avatar       TEXT,
      bio          TEXT DEFAULT '',
      reg_ip       TEXT DEFAULT 'unknown',
      created_at   BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      username   TEXT NOT NULL,
      created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000
    );
    CREATE TABLE IF NOT EXISTS messages (
      id         SERIAL PRIMARY KEY,
      chat_key   TEXT NOT NULL,
      from_user  TEXT NOT NULL,
      from_dn    TEXT NOT NULL,
      to_user    TEXT NOT NULL,
      text       TEXT NOT NULL,
      type       TEXT DEFAULT 'text',
      ts         BIGINT NOT NULL,
      deleted    BOOLEAN DEFAULT FALSE,
      read_by    TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_key, ts);
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  `);

  // Миграции
  const migrations = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS reg_ip TEXT DEFAULT 'unknown'`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS type TEXT DEFAULT 'text'`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_by TEXT DEFAULT ''`,
    `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS username TEXT`,
  ];
  for (const m of migrations) {
    try { await pool.query(m); } catch(e) {}
  }

  // Чистим старые сессии (>30 дней) при старте
  try {
    await pool.query(`DELETE FROM sessions WHERE created_at < $1`, [Date.now() - 30 * 24 * 60 * 60 * 1000]);
  } catch(e) {}

  console.log('DB ready');
}

initDB().catch(console.error);

function chatKey(a, b) { return [a, b].sort().join(':'); }
function ok(res, data) { res.json(data); }
function err(res, msg, status = 400) { res.status(status).json({ error: msg }); }

// Auth middleware
async function auth(req, res, next) {
  const token = req.headers['x-token'];
  if (!token) return err(res, 'Не авторизован', 401);
  const r = await pool.query('SELECT username FROM sessions WHERE token=$1', [token]);
  if (!r.rows.length) return err(res, 'Сессия истекла', 401);
  req.username = r.rows[0].username;
  next();
}

// REGISTER
app.post('/api/register', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    if (rateLimit(`reg:${ip}`, 5, 60 * 60 * 1000)) return err(res, 'Слишком много попыток, подожди час', 429);

    let { username, password, displayname } = req.body;
    username = (username || '').toLowerCase().trim();
    displayname = (displayname || '').trim();
    if (!username || !password || !displayname) return err(res, 'Заполните все поля');
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return err(res, 'Username: a-z, 0-9, _ (3–20 символов)');
    if (password.length < 6) return err(res, 'Пароль минимум 6 символов');
    if (displayname.length > 50) return err(res, 'Имя слишком длинное');

    const ipCheck = await pool.query('SELECT COUNT(*) FROM users WHERE reg_ip=$1', [ip]);
    if (parseInt(ipCheck.rows[0].count) >= 3) return err(res, 'Максимум 3 аккаунта с одного IP', 403);

    const existing = await pool.query('SELECT username FROM users WHERE username=$1', [username]);
    if (existing.rows.length > 0) return err(res, 'Username уже занят', 409);
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, displayname, password, reg_ip) VALUES ($1, $2, $3, $4)',
      [username, displayname, hash, ip]);
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (token, username) VALUES ($1, $2)', [token, username]);
    ok(res, { user: { username, displayname }, token });
  } catch (e) { err(res, e.message, 500); }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    let { username, password } = req.body;
    username = (username || '').toLowerCase().trim();
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    if (rateLimit(`login:${ip}`, 10, 15 * 60 * 1000)) return err(res, 'Слишком много попыток, подожди 15 минут', 429);

    if (!username || !password) return err(res, 'Заполните все поля');
    const result = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!result.rows.length) return err(res, 'Пользователь не найден', 401);
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return err(res, 'Неверный пароль', 401);
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (token, username) VALUES ($1, $2)', [token, username]);
    ok(res, { user: { username: user.username, displayname: user.displayname, avatar: user.avatar, bio: user.bio }, token });
  } catch (e) { err(res, e.message, 500); }
});

// LOGOUT
app.post('/api/logout', auth, async (req, res) => {
  const token = req.headers['x-token'];
  await pool.query('DELETE FROM sessions WHERE token=$1', [token]);
  ok(res, { ok: true });
});

// GET PROFILE
app.get('/api/profile/:username', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT username, displayname, avatar, bio FROM users WHERE username=$1', [req.params.username]);
    if (!r.rows.length) return err(res, 'Не найден', 404);
    ok(res, { user: r.rows[0] });
  } catch (e) { err(res, e.message, 500); }
});

// UPDATE PROFILE
app.post('/api/profile', auth, async (req, res) => {
  try {
    const { displayname, bio, avatar, newUsername } = req.body;
    const dn = (displayname || '').trim();
    if (!dn) return err(res, 'Имя не может быть пустым');
    if (dn.length > 50) return err(res, 'Имя слишком длинное');

    let finalUsername = req.username;

    if (newUsername) {
      const nu = newUsername.toLowerCase().trim();
      if (!/^[a-z0-9_]{3,20}$/.test(nu)) return err(res, 'Username: a-z, 0-9, _ (3–20 символов)');
      if (nu !== req.username) {
        const ex = await pool.query('SELECT username FROM users WHERE username=$1', [nu]);
        if (ex.rows.length) return err(res, 'Username уже занят', 409);
        await pool.query('UPDATE messages SET from_user=$1 WHERE from_user=$2', [nu, req.username]);
        await pool.query('UPDATE messages SET to_user=$1 WHERE to_user=$2', [nu, req.username]);
        await pool.query('UPDATE messages SET from_dn=$1 WHERE from_user=$2', [dn, nu]);
        await pool.query('UPDATE sessions SET username=$1 WHERE username=$2', [nu, req.username]);
        const msgs = await pool.query('SELECT DISTINCT chat_key FROM messages WHERE from_user=$1 OR to_user=$1', [nu]);
        for (const row of msgs.rows) {
          const parts = row.chat_key.split(':');
          const newKey = parts.map(p => p === req.username ? nu : p).sort().join(':');
          if (newKey !== row.chat_key) {
            await pool.query('UPDATE messages SET chat_key=$1 WHERE chat_key=$2', [newKey, row.chat_key]);
          }
        }
        await pool.query('UPDATE users SET username=$1, displayname=$2, bio=$3, avatar=$4 WHERE username=$5',
          [nu, dn, (bio||'').slice(0,200), avatar||null, req.username]);
        finalUsername = nu;
      }
    }

    if (finalUsername === req.username) {
      await pool.query('UPDATE users SET displayname=$1, bio=$2, avatar=$3 WHERE username=$4',
        [dn, (bio || '').slice(0, 200), avatar || null, req.username]);
    }

    ok(res, { ok: true, displayname: dn, username: finalUsername });
  } catch (e) { err(res, e.message, 500); }
});

// SEARCH
app.get('/api/search', auth, async (req, res) => {
  try {
    const q = (req.query.q || '').toLowerCase().trim();
    if (!q) return ok(res, { users: [] });
    if (rateLimit(`search:${req.username}`, 30, 60 * 1000)) return ok(res, { users: [] });
    const result = await pool.query(
      `SELECT username, displayname, avatar FROM users WHERE username != $1 AND (username ILIKE $2 OR displayname ILIKE $2) LIMIT 10`,
      [req.username, `%${q}%`]
    );
    ok(res, { users: result.rows });
  } catch (e) { err(res, e.message, 500); }
});

// SEND MESSAGE (text or video)
app.post('/api/send', auth, async (req, res) => {
  try {
    const { to, text, type } = req.body;
    const msgType = type === 'video' ? 'video' : 'text';
    if (!to || !text?.trim()) return err(res, 'Неверные данные');

    // Лимит на сообщения — 60 в минуту
    if (rateLimit(`msg:${req.username}`, 60, 60 * 1000)) return err(res, 'Слишком много сообщений', 429);

    // Размер видео — не больше 15MB (base64)
    if (msgType === 'video' && text.length > 20 * 1024 * 1024) return err(res, 'Видео слишком большое', 400);

    const userRes = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    if (!userRes.rows.length) return err(res, 'Пользователь не найден', 404);
    const fromDn = userRes.rows[0].displayname;
    const key = chatKey(req.username, to);
    const ts = Date.now();
    const r = await pool.query(
      'INSERT INTO messages (chat_key, from_user, from_dn, to_user, text, type, ts) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [key, req.username, fromDn, to, text.trim(), msgType, ts]
    );
    ok(res, { ok: true, id: r.rows[0].id });
  } catch (e) { err(res, e.message, 500); }
});

// MARK AS READ
app.post('/api/read', auth, async (req, res) => {
  try {
    const { other } = req.body;
    if (!other) return err(res, 'Нужен other');
    const key = chatKey(req.username, other);
    // Помечаем как прочитанные сообщения от other к нам
    await pool.query(`
      UPDATE messages SET read_by = CASE
        WHEN read_by = '' THEN $1
        WHEN read_by NOT LIKE '%' || $1 || '%' THEN read_by || ',' || $1
        ELSE read_by
      END
      WHERE chat_key=$2 AND from_user=$3 AND to_user=$4 AND NOT deleted
    `, [req.username, key, other, req.username]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// DELETE MESSAGE
app.delete('/api/message/:id', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT from_user FROM messages WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    if (r.rows[0].from_user !== req.username) return err(res, 'Нет прав', 403);
    await pool.query('UPDATE messages SET deleted=TRUE, text=$1 WHERE id=$2', ['Сообщение удалено', req.params.id]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// DELETE CHAT
app.delete('/api/chat/:other', auth, async (req, res) => {
  try {
    const key = chatKey(req.username, req.params.other);
    await pool.query('DELETE FROM messages WHERE chat_key=$1', [key]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// GET MESSAGES
app.get('/api/messages', auth, async (req, res) => {
  try {
    const b = req.query.b;
    const since = parseInt(req.query.since || '0');
    if (!b) return err(res, 'Нужен b');
    const key = chatKey(req.username, b);
    const result = await pool.query(
      `SELECT id, from_user as "from", from_dn as displayname, text, type, ts, deleted,
       read_by LIKE '%' || $3 || '%' as read
       FROM messages WHERE chat_key=$1 AND ts>$2 ORDER BY ts ASC LIMIT 200`,
      [key, since, req.username]  // req.username тут НЕ используется для read (это отправитель) — поправлено ниже
    );
    // Правильно: read = кто читал = собеседник
    const rows = result.rows.map(r => ({
      ...r,
      ts: parseInt(r.ts),
      read: (r.read_by || '').includes(b) // прочитал ли собеседник (b)
    }));
    ok(res, { messages: rows });
  } catch (e) { err(res, e.message, 500); }
});

// GET CHATS LIST
app.get('/api/chats', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        chat_key,
        CASE WHEN from_user = $1 THEN to_user ELSE from_user END AS other_username,
        text AS last_message,
        type AS last_type,
        ts AS last_ts,
        deleted,
        from_user AS last_from
      FROM messages m
      WHERE (from_user = $1 OR to_user = $1)
        AND ts = (SELECT MAX(ts) FROM messages m2 WHERE m2.chat_key = m.chat_key)
      ORDER BY ts DESC
    `, [req.username]);

    // Получаем непрочитанные одним запросом
    const unreadResult = await pool.query(`
      SELECT from_user, COUNT(*) as cnt
      FROM messages
      WHERE to_user=$1 AND NOT deleted AND read_by NOT LIKE '%' || $1 || '%'
      GROUP BY from_user
    `, [req.username]);
    const unreadMap = {};
    for (const r of unreadResult.rows) unreadMap[r.from_user] = parseInt(r.cnt);

    // Получаем данные всех собеседников одним запросом
    const seen = new Set();
    const otherUsernames = [];
    for (const row of result.rows) {
      const other = row.other_username;
      if (!other || seen.has(other)) continue;
      seen.add(other);
      otherUsernames.push(other);
    }

    let usersMap = {};
    if (otherUsernames.length > 0) {
      const placeholders = otherUsernames.map((_, i) => `$${i+1}`).join(',');
      const uRes = await pool.query(
        `SELECT username, displayname, avatar FROM users WHERE username IN (${placeholders})`,
        otherUsernames
      );
      for (const u of uRes.rows) usersMap[u.username] = u;
    }

    const seenFinal = new Set();
    const chats = [];
    for (const row of result.rows) {
      const other = row.other_username;
      if (!other || seenFinal.has(other)) continue;
      seenFinal.add(other);
      const u = usersMap[other] || {};
      let preview = row.deleted ? 'Сообщение удалено' : row.last_message;
      if (!row.deleted && row.last_type === 'video') preview = '🎥 Видеосообщение';
      chats.push({
        otherUsername: other,
        otherDisplayname: u.displayname || other,
        otherAvatar: u.avatar || null,
        lastMessage: preview,
        lastTs: parseInt(row.last_ts),
        unread: unreadMap[other] || 0
      });
    }
    ok(res, { chats });
  } catch (e) { err(res, e.message, 500); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Wavr running on port ${PORT}`));
