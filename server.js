const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username     TEXT PRIMARY KEY,
      displayname  TEXT NOT NULL,
      password     TEXT NOT NULL,
      avatar       TEXT,
      bio          TEXT DEFAULT '',
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
      ts         BIGINT NOT NULL,
      deleted    BOOLEAN DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_key, ts);
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  `);

  // Add missing columns if upgrading
  try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT`); } catch(e) {}
  try { await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT ''`); } catch(e) {}
  try { await pool.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted BOOLEAN DEFAULT FALSE`); } catch(e) {}
  try { await pool.query(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS username TEXT`); } catch(e) {}

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
    let { username, password, displayname } = req.body;
    username = (username || '').toLowerCase().trim();
    displayname = (displayname || '').trim();
    if (!username || !password || !displayname) return err(res, 'Заполните все поля');
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return err(res, 'Username: a-z, 0-9, _ (3–20 символов)');
    if (password.length < 6) return err(res, 'Пароль минимум 6 символов');
    const existing = await pool.query('SELECT username FROM users WHERE username=$1', [username]);
    if (existing.rows.length > 0) return err(res, 'Username уже занят', 409);
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, displayname, password) VALUES ($1, $2, $3)', [username, displayname, hash]);
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
    const { displayname, bio, avatar } = req.body;
    const dn = (displayname || '').trim();
    if (!dn) return err(res, 'Имя не может быть пустым');
    await pool.query('UPDATE users SET displayname=$1, bio=$2, avatar=$3 WHERE username=$4',
      [dn, (bio || '').slice(0, 200), avatar || null, req.username]);
    ok(res, { ok: true, displayname: dn });
  } catch (e) { err(res, e.message, 500); }
});

// SEARCH
app.get('/api/search', auth, async (req, res) => {
  try {
    const q = (req.query.q || '').toLowerCase().trim();
    if (!q) return ok(res, { users: [] });
    const result = await pool.query(
      `SELECT username, displayname, avatar FROM users WHERE username != $1 AND (username ILIKE $2 OR displayname ILIKE $2) LIMIT 10`,
      [req.username, `%${q}%`]
    );
    ok(res, { users: result.rows });
  } catch (e) { err(res, e.message, 500); }
});

// SEND MESSAGE
app.post('/api/send', auth, async (req, res) => {
  try {
    const { to, text } = req.body;
    if (!to || !text?.trim()) return err(res, 'Неверные данные');
    const userRes = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    const fromDn = userRes.rows[0]?.displayname || req.username;
    const key = chatKey(req.username, to);
    const ts = Date.now();
    const r = await pool.query(
      'INSERT INTO messages (chat_key, from_user, from_dn, to_user, text, ts) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
      [key, req.username, fromDn, to, text.trim(), ts]
    );
    ok(res, { ok: true, id: r.rows[0].id });
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
      'SELECT id, from_user as "from", from_dn as displayname, text, ts, deleted FROM messages WHERE chat_key=$1 AND ts>$2 ORDER BY ts ASC LIMIT 200',
      [key, since]
    );
    ok(res, { messages: result.rows.map(r => ({ ...r, ts: parseInt(r.ts) })) });
  } catch (e) { err(res, e.message, 500); }
});

// GET CHATS LIST
app.get('/api/chats', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DISTINCT ON (chat_key)
        chat_key,
        CASE WHEN from_user = $1 THEN to_user ELSE from_user END AS other_username,
        text AS last_message, ts AS last_ts, deleted
      FROM messages
      WHERE from_user = $1 OR to_user = $1
      ORDER BY chat_key, ts DESC
    `, [req.username]);

    const chats = [];
    for (const row of result.rows) {
      const uRes = await pool.query('SELECT displayname, avatar FROM users WHERE username=$1', [row.other_username]);
      const u = uRes.rows[0];
      chats.push({
        otherUsername: row.other_username,
        otherDisplayname: u?.displayname || row.other_username,
        otherAvatar: u?.avatar || null,
        lastMessage: row.deleted ? 'Сообщение удалено' : row.last_message,
        lastTs: parseInt(row.last_ts),
        unread: 0
      });
    }
    chats.sort((a, b) => b.lastTs - a.lastTs);
    ok(res, { chats });
  } catch (e) { err(res, e.message, 500); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Wavr running on port ${PORT}`));
