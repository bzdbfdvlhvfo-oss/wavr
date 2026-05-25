const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// Rate limiting
const rl = new Map();
function rateLimit(key, max, ms) {
  const now = Date.now();
  const e = rl.get(key) || { n: 0, r: now + ms };
  if (now > e.r) { e.n = 0; e.r = now + ms; }
  e.n++; rl.set(key, e);
  return e.n > max;
}
setInterval(() => { const now = Date.now(); for (const [k,v] of rl) if (now > v.r) rl.delete(k); }, 5*60*1000);

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username    TEXT PRIMARY KEY,
      displayname TEXT NOT NULL,
      password    TEXT NOT NULL,
      avatar      TEXT,
      bio         TEXT DEFAULT '',
      reg_ip      TEXT DEFAULT 'unknown',
      created_at  BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())*1000
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      username   TEXT NOT NULL,
      created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())*1000
    );
    CREATE TABLE IF NOT EXISTS messages (
      id        SERIAL PRIMARY KEY,
      chat_key  TEXT NOT NULL,
      from_user TEXT NOT NULL,
      from_dn   TEXT NOT NULL,
      to_user   TEXT NOT NULL,
      text      TEXT NOT NULL,
      type      TEXT DEFAULT 'text',
      ts        BIGINT NOT NULL,
      deleted   BOOLEAN DEFAULT FALSE,
      read_at   BIGINT DEFAULT 0,
      reactions TEXT DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_msg_chat ON messages(chat_key, ts);
    CREATE INDEX IF NOT EXISTS idx_sessions  ON sessions(token);
  `);

  const migs = [
    `ALTER TABLE users    ADD COLUMN IF NOT EXISTS avatar     TEXT`,
    `ALTER TABLE users    ADD COLUMN IF NOT EXISTS bio        TEXT DEFAULT ''`,
    `ALTER TABLE users    ADD COLUMN IF NOT EXISTS reg_ip     TEXT DEFAULT 'unknown'`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted    BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS type       TEXT DEFAULT 'text'`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at    BIGINT DEFAULT 0`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS reactions  TEXT DEFAULT '{}'`,
    `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS username   TEXT`,
  ];
  for (const m of migs) { try { await pool.query(m); } catch(e) {} }
  try { await pool.query(`DELETE FROM sessions WHERE created_at < $1`, [Date.now() - 30*24*3600*1000]); } catch(e){}
  console.log('DB ready');
}
initDB().catch(console.error);

const chatKey = (a, b) => [a, b].sort().join(':');
const ok  = (res, d) => res.json(d);
const err = (res, msg, s=400) => res.status(s).json({ error: msg });

async function auth(req, res, next) {
  const t = req.headers['x-token'];
  if (!t) return err(res, 'Не авторизован', 401);
  const r = await pool.query('SELECT username FROM sessions WHERE token=$1', [t]);
  if (!r.rows.length) return err(res, 'Сессия истекла', 401);
  req.username = r.rows[0].username;
  next();
}

// REGISTER
app.post('/api/register', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    if (rateLimit(`reg:${ip}`, 5, 3600*1000)) return err(res, 'Слишком много попыток', 429);
    let { username, password, displayname } = req.body;
    username = (username||'').toLowerCase().trim();
    displayname = (displayname||'').trim();
    if (!username||!password||!displayname) return err(res, 'Заполните все поля');
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return err(res, 'Username: a-z 0-9 _ (3–20 символов)');
    if (password.length < 6) return err(res, 'Пароль минимум 6 символов');
    if (displayname.length > 50) return err(res, 'Имя слишком длинное');
    const ipCnt = await pool.query('SELECT COUNT(*) FROM users WHERE reg_ip=$1', [ip]);
    if (parseInt(ipCnt.rows[0].count) >= 3) return err(res, 'Максимум 3 аккаунта с одного IP', 403);
    const ex = await pool.query('SELECT username FROM users WHERE username=$1', [username]);
    if (ex.rows.length) return err(res, 'Username уже занят', 409);
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username,displayname,password,reg_ip) VALUES ($1,$2,$3,$4)', [username,displayname,hash,ip]);
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (token,username) VALUES ($1,$2)', [token,username]);
    ok(res, { user: { username, displayname }, token });
  } catch(e) { err(res, e.message, 500); }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    if (rateLimit(`login:${ip}`, 10, 15*60*1000)) return err(res, 'Слишком много попыток', 429);
    let { username, password } = req.body;
    username = (username||'').toLowerCase().trim();
    if (!username||!password) return err(res, 'Заполните все поля');
    const r = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!r.rows.length) return err(res, 'Пользователь не найден', 401);
    const u = r.rows[0];
    if (!await bcrypt.compare(password, u.password)) return err(res, 'Неверный пароль', 401);
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (token,username) VALUES ($1,$2)', [token,username]);
    ok(res, { user: { username: u.username, displayname: u.displayname, avatar: u.avatar, bio: u.bio }, token });
  } catch(e) { err(res, e.message, 500); }
});

// LOGOUT
app.post('/api/logout', auth, async (req, res) => {
  await pool.query('DELETE FROM sessions WHERE token=$1', [req.headers['x-token']]);
  ok(res, { ok: true });
});

// GET PROFILE
app.get('/api/profile/:username', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT username,displayname,avatar,bio FROM users WHERE username=$1', [req.params.username]);
    if (!r.rows.length) return err(res, 'Не найден', 404);
    ok(res, { user: r.rows[0] });
  } catch(e) { err(res, e.message, 500); }
});

// UPDATE PROFILE
app.post('/api/profile', auth, async (req, res) => {
  try {
    const { displayname, bio, avatar, newUsername } = req.body;
    const dn = (displayname||'').trim();
    if (!dn) return err(res, 'Имя не может быть пустым');
    let finalUsername = req.username;
    if (newUsername) {
      const nu = newUsername.toLowerCase().trim();
      if (!/^[a-z0-9_]{3,20}$/.test(nu)) return err(res, 'Username: a-z 0-9 _ (3–20 символов)');
      if (nu !== req.username) {
        const ex = await pool.query('SELECT username FROM users WHERE username=$1', [nu]);
        if (ex.rows.length) return err(res, 'Username уже занят', 409);
        await pool.query('UPDATE messages SET from_user=$1 WHERE from_user=$2', [nu, req.username]);
        await pool.query('UPDATE messages SET to_user=$1   WHERE to_user=$2',   [nu, req.username]);
        await pool.query('UPDATE messages SET from_dn=$1  WHERE from_user=$2',  [dn, nu]);
        await pool.query('UPDATE sessions  SET username=$1 WHERE username=$2',  [nu, req.username]);
        const rows = await pool.query('SELECT DISTINCT chat_key FROM messages WHERE from_user=$1 OR to_user=$1', [nu]);
        for (const row of rows.rows) {
          const nk = row.chat_key.split(':').map(p=>p===req.username?nu:p).sort().join(':');
          if (nk !== row.chat_key) await pool.query('UPDATE messages SET chat_key=$1 WHERE chat_key=$2', [nk, row.chat_key]);
        }
        await pool.query('UPDATE users SET username=$1,displayname=$2,bio=$3,avatar=$4 WHERE username=$5',
          [nu, dn, (bio||'').slice(0,200), avatar||null, req.username]);
        finalUsername = nu;
      }
    }
    if (finalUsername === req.username) {
      await pool.query('UPDATE users SET displayname=$1,bio=$2,avatar=$3 WHERE username=$4',
        [dn, (bio||'').slice(0,200), avatar||null, req.username]);
    }
    ok(res, { ok: true, displayname: dn, username: finalUsername });
  } catch(e) { err(res, e.message, 500); }
});

// SEARCH
app.get('/api/search', auth, async (req, res) => {
  try {
    const q = (req.query.q||'').trim();
    if (!q) return ok(res, { users: [] });
    if (rateLimit(`search:${req.username}`, 30, 60*1000)) return ok(res, { users: [] });
    const r = await pool.query(
      `SELECT username,displayname,avatar FROM users WHERE username!=$1 AND (username ILIKE $2 OR displayname ILIKE $2) LIMIT 10`,
      [req.username, `%${q}%`]
    );
    ok(res, { users: r.rows });
  } catch(e) { err(res, e.message, 500); }
});

// SEND MESSAGE
app.post('/api/send', auth, async (req, res) => {
  try {
    const { to, text, type } = req.body;
    const msgType = ['text','image'].includes(type) ? type : 'text';
    if (!to || !text?.trim()) return err(res, 'Неверные данные');
    if (rateLimit(`msg:${req.username}`, 60, 60*1000)) return err(res, 'Слишком много сообщений', 429);
    if (msgType === 'image' && text.length > 22*1024*1024) return err(res, 'Файл слишком большой', 400);
    const ur = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    if (!ur.rows.length) return err(res, 'Пользователь не найден', 404);
    const key = chatKey(req.username, to);
    const ts = Date.now();
    const r = await pool.query(
      'INSERT INTO messages (chat_key,from_user,from_dn,to_user,text,type,ts) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,ts',
      [key, req.username, ur.rows[0].displayname, to, text.trim(), msgType, ts]
    );
    ok(res, { ok: true, id: r.rows[0].id, ts: parseInt(r.rows[0].ts) });
  } catch(e) { err(res, e.message, 500); }
});

// REACT TO MESSAGE
app.post('/api/react', auth, async (req, res) => {
  try {
    const { id, emoji } = req.body;
    if (!id || !emoji) return err(res, 'Нужен id и emoji');
    if ([...emoji].length > 2) return err(res, 'Слишком длинный emoji');
    const r = await pool.query('SELECT reactions, chat_key FROM messages WHERE id=$1', [id]);
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    // Проверяем что пользователь участник чата
    const key = r.rows[0].chat_key;
    const parts = key.split(':');
    if (!parts.includes(req.username)) return err(res, 'Нет прав', 403);
    let reactions = {};
    try { reactions = JSON.parse(r.rows[0].reactions || '{}'); } catch(e) {}
    if (!reactions[emoji]) reactions[emoji] = [];
    const idx = reactions[emoji].indexOf(req.username);
    if (idx >= 0) {
      reactions[emoji].splice(idx, 1); // убрать реакцию
      if (!reactions[emoji].length) delete reactions[emoji];
    } else {
      reactions[emoji].push(req.username); // добавить
    }
    await pool.query('UPDATE messages SET reactions=$1 WHERE id=$2', [JSON.stringify(reactions), id]);
    ok(res, { ok: true, reactions });
  } catch(e) { err(res, e.message, 500); }
});

// MARK AS READ
app.post('/api/read', auth, async (req, res) => {
  try {
    const { other } = req.body;
    if (!other) return err(res, 'Нужен other');
    const key = chatKey(req.username, other);
    const now = Date.now();
    await pool.query(
      `UPDATE messages SET read_at=$1 WHERE chat_key=$2 AND from_user=$3 AND to_user=$4 AND NOT deleted AND read_at=0`,
      [now, key, other, req.username]
    );
    ok(res, { ok: true });
  } catch(e) { err(res, e.message, 500); }
});

// DELETE MESSAGE
app.delete('/api/message/:id', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT from_user FROM messages WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    if (r.rows[0].from_user !== req.username) return err(res, 'Нет прав', 403);
    await pool.query('UPDATE messages SET deleted=TRUE,text=$1 WHERE id=$2', ['Сообщение удалено', req.params.id]);
    ok(res, { ok: true });
  } catch(e) { err(res, e.message, 500); }
});

// DELETE CHAT
app.delete('/api/chat/:other', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM messages WHERE chat_key=$1', [chatKey(req.username, req.params.other)]);
    ok(res, { ok: true });
  } catch(e) { err(res, e.message, 500); }
});

// GET MESSAGES
app.get('/api/messages', auth, async (req, res) => {
  try {
    const { b, since } = req.query;
    if (!b) return err(res, 'Нужен b');
    const key = chatKey(req.username, b);
    const sinceTs = parseInt(since || '0');
    const r = await pool.query(
      `SELECT id, from_user as "from", from_dn as displayname, text, type, ts, deleted, read_at, reactions
       FROM messages WHERE chat_key=$1 AND ts>$2 ORDER BY ts ASC LIMIT 300`,
      [key, sinceTs]
    );
    ok(res, { messages: r.rows.map(m => ({
      ...m,
      ts: parseInt(m.ts),
      read_at: parseInt(m.read_at || 0),
      reactions: (() => { try { return JSON.parse(m.reactions||'{}'); } catch(e) { return {}; } })()
    }))});
  } catch(e) { err(res, e.message, 500); }
});

// GET MESSAGES UPDATES (только изменения — реакции, прочтение)
app.get('/api/updates', auth, async (req, res) => {
  try {
    const { b, ids } = req.query;
    if (!b || !ids) return ok(res, { updates: [] });
    const idList = ids.split(',').map(Number).filter(Boolean);
    if (!idList.length) return ok(res, { updates: [] });
    const key = chatKey(req.username, b);
    const placeholders = idList.map((_,i)=>`$${i+2}`).join(',');
    const r = await pool.query(
      `SELECT id, read_at, reactions FROM messages WHERE chat_key=$1 AND id IN (${placeholders})`,
      [key, ...idList]
    );
    ok(res, { updates: r.rows.map(m => ({
      id: m.id,
      read_at: parseInt(m.read_at||0),
      reactions: (() => { try { return JSON.parse(m.reactions||'{}'); } catch(e) { return {}; } })()
    }))});
  } catch(e) { err(res, e.message, 500); }
});

// GET CHATS LIST
app.get('/api/chats', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DISTINCT ON (chat_key)
        chat_key,
        CASE WHEN from_user=$1 THEN to_user ELSE from_user END AS other_username,
        text AS last_message, type AS last_type, ts AS last_ts, deleted
      FROM messages
      WHERE from_user=$1 OR to_user=$1
      ORDER BY chat_key, ts DESC
    `, [req.username]);

    // Unread: сообщения от других к нам где read_at=0
    const unreadR = await pool.query(`
      SELECT from_user, COUNT(*) as cnt FROM messages
      WHERE to_user=$1 AND NOT deleted AND read_at=0
      GROUP BY from_user
    `, [req.username]);
    const unreadMap = {};
    for (const r of unreadR.rows) unreadMap[r.from_user] = parseInt(r.cnt);

    // Все собеседники одним запросом
    const others = [...new Set(result.rows.map(r=>r.other_username).filter(Boolean))];
    let usersMap = {};
    if (others.length) {
      const ph = others.map((_,i)=>`$${i+1}`).join(',');
      const ur = await pool.query(`SELECT username,displayname,avatar FROM users WHERE username IN (${ph})`, others);
      for (const u of ur.rows) usersMap[u.username] = u;
    }

    // Сортируем по lastTs и берём уникальных
    const seen = new Set();
    const chats = [];
    // Сначала сортируем по ts desc
    const sorted = [...result.rows].sort((a,b) => parseInt(b.last_ts) - parseInt(a.last_ts));
    for (const row of sorted) {
      const other = row.other_username;
      if (!other || seen.has(other)) continue;
      seen.add(other);
      const u = usersMap[other] || {};
      let preview = row.deleted ? '🗑 Сообщение удалено' : row.last_message;
      if (!row.deleted && row.last_type === 'image') preview = '📷 Фото';
      // Обрезаем превью
      if (preview && preview.length > 60) preview = preview.slice(0, 60) + '…';
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
  } catch(e) { err(res, e.message, 500); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Wavr on port ${PORT}`));
