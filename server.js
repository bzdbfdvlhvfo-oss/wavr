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
  e.n++;
  rl.set(key, e);
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
    `ALTER TABLE users    ADD COLUMN IF NOT EXISTS avatar    TEXT`,
    `ALTER TABLE users    ADD COLUMN IF NOT EXISTS bio       TEXT DEFAULT ''`,
    `ALTER TABLE users    ADD COLUMN IF NOT EXISTS reg_ip    TEXT DEFAULT 'unknown'`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted   BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS type      TEXT DEFAULT 'text'`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at   BIGINT DEFAULT 0`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS reactions TEXT DEFAULT '{}'`,
    `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS username  TEXT`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_name TEXT`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_size BIGINT DEFAULT 0`,
  ];
  for (const m of migs) { try { await pool.query(m); } catch(e) {} }
  // Чистим старые сессии
  try { await pool.query(`DELETE FROM sessions WHERE created_at < $1`, [Date.now() - 30*24*3600*1000]); } catch(e){}
  console.log('DB ready');
}
initDB().catch(console.error);

const chatKey = (a, b) => [a, b].sort().join(':');
const ok  = (res, d) => res.json(d);
const err = (res, msg, s=400) => res.status(s).json({ error: msg });
const parseReactions = (raw) => { try { return JSON.parse(raw || '{}'); } catch(e) { return {}; } };

const OWNER = 'timur';
async function adminOnly(req, res, next) {
  if (req.username !== OWNER) return err(res, 'Нет прав', 403);
  next();
}

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
    if (u.bio === '__BANNED__') return err(res, 'Аккаунт заблокирован', 403);
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

// SEND MESSAGE (text / image / video / file)
app.post('/api/send', auth, async (req, res) => {
  try {
    const { to, text, type, fileName, fileSize } = req.body;
    const allowedTypes = ['text','image','video','file'];
    const msgType = allowedTypes.includes(type) ? type : 'text';
    if (!to || !text?.trim()) return err(res, 'Неверные данные');
    if (rateLimit(`msg:${req.username}`, 60, 60*1000)) return err(res, 'Слишком много сообщений', 429);
    if (msgType !== 'text' && text.length > 22*1024*1024) return err(res, 'Файл слишком большой', 400);
    const ur = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    if (!ur.rows.length) return err(res, 'Пользователь не найден', 404);
    const key = chatKey(req.username, to);
    const ts = Date.now();
    const storeText = msgType === 'text' ? text.trim() : text;
    const r = await pool.query(
      'INSERT INTO messages (chat_key,from_user,from_dn,to_user,text,type,ts,file_name,file_size) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,ts',
      [key, req.username, ur.rows[0].displayname, to, storeText, msgType, ts, fileName||null, fileSize||0]
    );
    ok(res, { ok: true, id: r.rows[0].id, ts: parseInt(r.rows[0].ts) });
  } catch(e) { err(res, e.message, 500); }
});

// REACT TO MESSAGE
app.post('/api/react', auth, async (req, res) => {
  try {
    const { id, emoji } = req.body;
    if (!id || !emoji) return err(res, 'Нужен id и emoji');
    const em = (emoji||'').trim();
    if (!em) return err(res, 'Пустой emoji');
    // Проверяем длину (макс 2 кодовых точки для стандартных эмодзи)
    if ([...em].length > 4) return err(res, 'Слишком длинный emoji');
    const r = await pool.query('SELECT reactions, chat_key FROM messages WHERE id=$1', [id]);
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    const key = r.rows[0].chat_key;
    const parts = key.split(':');
    if (!parts.includes(req.username)) return err(res, 'Нет прав', 403);
    let reactions = parseReactions(r.rows[0].reactions);
    if (!reactions[em]) reactions[em] = [];
    const idx = reactions[em].indexOf(req.username);
    if (idx >= 0) {
      reactions[em].splice(idx, 1);
      if (!reactions[em].length) delete reactions[em];
    } else {
      reactions[em].push(req.username);
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
      `SELECT id, from_user as "from", from_dn as displayname, text, type, ts, deleted, read_at, reactions, file_name, file_size
       FROM messages WHERE chat_key=$1 AND ts>$2 ORDER BY ts ASC LIMIT 300`,
      [key, sinceTs]
    );
    ok(res, { messages: r.rows.map(m => ({
      ...m,
      ts: parseInt(m.ts),
      read_at: parseInt(m.read_at || 0),
      file_size: parseInt(m.file_size || 0),
      reactions: parseReactions(m.reactions)
    }))});
  } catch(e) { err(res, e.message, 500); }
});

// POLL — только обновления существующих сообщений (реакции, read_at)
app.get('/api/poll', auth, async (req, res) => {
  try {
    const { b, since } = req.query;
    if (!b) return ok(res, { messages: [], updates: [] });
    const key = chatKey(req.username, b);
    const sinceTs = parseInt(since || '0');

    // Новые сообщения
    const newMsgs = await pool.query(
      `SELECT id, from_user as "from", from_dn as displayname, text, type, ts, deleted, read_at, reactions, file_name, file_size
       FROM messages WHERE chat_key=$1 AND ts>$2 ORDER BY ts ASC LIMIT 100`,
      [key, sinceTs]
    );

    // Обновления read_at для своих сообщений (без text — экономим трафик)
    const readUpdates = await pool.query(
      `SELECT id, read_at FROM messages WHERE chat_key=$1 AND from_user=$2 AND read_at>0 AND ts>$3-86400000`,
      [key, req.username, sinceTs]
    );

    // Обновления реакций для сообщений чата за последние 5 минут
    const reactionUpdates = await pool.query(
      `SELECT id, reactions FROM messages WHERE chat_key=$1 AND NOT deleted AND ts > $2 - 300000`,
      [key, Date.now()]
    );

    ok(res, {
      messages: newMsgs.rows.map(m => ({
        ...m,
        ts: parseInt(m.ts),
        read_at: parseInt(m.read_at || 0),
        file_size: parseInt(m.file_size || 0),
        reactions: parseReactions(m.reactions)
      })),
      readUpdates: readUpdates.rows.map(r => ({ id: r.id, read_at: parseInt(r.read_at) })),
      reactionUpdates: reactionUpdates.rows.map(r => ({ id: r.id, reactions: parseReactions(r.reactions) }))
    });
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

    const unreadR = await pool.query(`
      SELECT from_user, COUNT(*) as cnt FROM messages
      WHERE to_user=$1 AND NOT deleted AND read_at=0
      GROUP BY from_user
    `, [req.username]);
    const unreadMap = {};
    for (const r of unreadR.rows) unreadMap[r.from_user] = parseInt(r.cnt);

    const others = [...new Set(result.rows.map(r=>r.other_username).filter(Boolean))];
    let usersMap = {};
    if (others.length) {
      const ph = others.map((_,i)=>`$${i+1}`).join(',');
      const ur = await pool.query(`SELECT username,displayname,avatar FROM users WHERE username IN (${ph})`, others);
      for (const u of ur.rows) usersMap[u.username] = u;
    }

    const seen = new Set();
    const chats = [];
    const sorted = [...result.rows].sort((a,b) => parseInt(b.last_ts) - parseInt(a.last_ts));
    for (const row of sorted) {
      const other = row.other_username;
      if (!other || seen.has(other)) continue;
      seen.add(other);
      const u = usersMap[other] || {};
      let preview = row.deleted ? '🗑 Удалено' : row.last_message;
      if (!row.deleted) {
        if (row.last_type === 'image') preview = '📷 Фото';
        else if (row.last_type === 'video') preview = '🎬 Видео';
        else if (row.last_type === 'file') preview = '📎 Файл';
        else if (preview && preview.length > 60) preview = preview.slice(0,60)+'…';
      }
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

// ── ADMIN: список всех пользователей
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT username, displayname, bio, reg_ip, created_at,
        (SELECT COUNT(*) FROM messages WHERE from_user=users.username) as msg_count,
        (SELECT COUNT(*) FROM sessions WHERE username=users.username) as session_count
       FROM users ORDER BY created_at DESC`
    );
    ok(res, { users: r.rows.map(u => ({
      ...u,
      created_at: parseInt(u.created_at),
      msg_count: parseInt(u.msg_count),
      session_count: parseInt(u.session_count)
    }))});
  } catch(e) { err(res, e.message, 500); }
});

// ── ADMIN: удалить аккаунт
app.delete('/api/admin/user/:username', auth, adminOnly, async (req, res) => {
  try {
    const u = req.params.username;
    if (u === OWNER) return err(res, 'Нельзя удалить владельца', 403);
    await pool.query('DELETE FROM sessions WHERE username=$1', [u]);
    await pool.query('DELETE FROM messages WHERE from_user=$1 OR to_user=$1', [u]);
    await pool.query('DELETE FROM users WHERE username=$1', [u]);
    ok(res, { ok: true });
  } catch(e) { err(res, e.message, 500); }
});

// ── ADMIN: кик (удалить все сессии = разлогинить)
app.post('/api/admin/kick/:username', auth, adminOnly, async (req, res) => {
  try {
    const u = req.params.username;
    if (u === OWNER) return err(res, 'Нельзя кикнуть владельца', 403);
    await pool.query('DELETE FROM sessions WHERE username=$1', [u]);
    ok(res, { ok: true });
  } catch(e) { err(res, e.message, 500); }
});

// ── ADMIN: забанить (удалить сессии + записать в banned список)
app.post('/api/admin/ban/:username', auth, adminOnly, async (req, res) => {
  try {
    const u = req.params.username;
    if (u === OWNER) return err(res, 'Нельзя забанить владельца', 403);
    // Храним бан как пустой bio с маркером — простой способ без новой таблицы
    await pool.query('UPDATE users SET bio=$1 WHERE username=$2', ['__BANNED__', u]);
    await pool.query('DELETE FROM sessions WHERE username=$1', [u]);
    ok(res, { ok: true });
  } catch(e) { err(res, e.message, 500); }
});

// ── ADMIN: разбанить
app.post('/api/admin/unban/:username', auth, adminOnly, async (req, res) => {
  try {
    await pool.query("UPDATE users SET bio='' WHERE username=$1", [req.params.username]);
    ok(res, { ok: true });
  } catch(e) { err(res, e.message, 500); }
});

// ── ADMIN: статистика
app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const users = await pool.query('SELECT COUNT(*) as c FROM users');
    const msgs  = await pool.query('SELECT COUNT(*) as c FROM messages');
    const sess  = await pool.query('SELECT COUNT(*) as c FROM sessions');
    const today = await pool.query('SELECT COUNT(*) as c FROM messages WHERE ts > $1', [Date.now()-86400000]);
    ok(res, {
      users: parseInt(users.rows[0].c),
      messages: parseInt(msgs.rows[0].c),
      sessions: parseInt(sess.rows[0].c),
      today: parseInt(today.rows[0].c)
    });
  } catch(e) { err(res, e.message, 500); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Wavr on port ${PORT}`));
