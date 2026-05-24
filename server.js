const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── DATABASE ───────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create tables on startup
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username     TEXT PRIMARY KEY,
      displayname  TEXT NOT NULL,
      password     TEXT NOT NULL,
      created_at   BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000
    );

    CREATE TABLE IF NOT EXISTS messages (
      id         SERIAL PRIMARY KEY,
      chat_key   TEXT NOT NULL,
      from_user  TEXT NOT NULL,
      from_dn    TEXT NOT NULL,
      to_user    TEXT NOT NULL,
      text       TEXT NOT NULL,
      ts         BIGINT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_key, ts);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  `);
  console.log('DB ready');
}

initDB().catch(console.error);

// ─── HELPERS ────────────────────────────────────────────────
function chatKey(a, b) {
  return [a, b].sort().join(':');
}

function ok(res, data) {
  res.json(data);
}

function err(res, msg, status = 400) {
  res.status(status).json({ error: msg });
}

// ─── REGISTER ───────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    let { username, password, displayname } = req.body;
    username = (username || '').toLowerCase().trim();
    displayname = (displayname || '').trim();

    if (!username || !password || !displayname)
      return err(res, 'Заполните все поля');
    if (!/^[a-z0-9_]{3,20}$/.test(username))
      return err(res, 'Username: a-z, 0-9, _ (3–20 символов)');
    if (password.length < 6)
      return err(res, 'Пароль минимум 6 символов');

    const existing = await pool.query('SELECT username FROM users WHERE username=$1', [username]);
    if (existing.rows.length > 0)
      return err(res, 'Username уже занят', 409);

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, displayname, password) VALUES ($1, $2, $3)',
      [username, displayname, hash]
    );

    ok(res, { user: { username, displayname } });
  } catch (e) {
    err(res, e.message, 500);
  }
});

// ─── LOGIN ──────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    let { username, password } = req.body;
    username = (username || '').toLowerCase().trim();

    if (!username || !password)
      return err(res, 'Заполните все поля');

    const result = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!result.rows.length)
      return err(res, 'Пользователь не найден', 401);

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return err(res, 'Неверный пароль', 401);

    ok(res, { user: { username: user.username, displayname: user.displayname } });
  } catch (e) {
    err(res, e.message, 500);
  }
});

// ─── SEARCH ─────────────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  try {
    const q = (req.query.q || '').toLowerCase().trim();
    const me = (req.query.me || '').toLowerCase();

    if (!q) return ok(res, { users: [] });

    const result = await pool.query(
      `SELECT username, displayname FROM users
       WHERE username != $1
         AND (username ILIKE $2 OR displayname ILIKE $2)
       LIMIT 10`,
      [me, `%${q}%`]
    );

    ok(res, { users: result.rows });
  } catch (e) {
    err(res, e.message, 500);
  }
});

// ─── SEND MESSAGE ───────────────────────────────────────────
app.post('/api/send', async (req, res) => {
  try {
    const { from, fromDisplayname, to, text } = req.body;

    if (!from || !to || !text?.trim())
      return err(res, 'Неверные данные');

    const key = chatKey(from, to);
    const ts = Date.now();

    await pool.query(
      'INSERT INTO messages (chat_key, from_user, from_dn, to_user, text, ts) VALUES ($1,$2,$3,$4,$5,$6)',
      [key, from, fromDisplayname || from, to, text.trim(), ts]
    );

    ok(res, { ok: true });
  } catch (e) {
    err(res, e.message, 500);
  }
});

// ─── GET MESSAGES ───────────────────────────────────────────
app.get('/api/messages', async (req, res) => {
  try {
    const a = req.query.a;
    const b = req.query.b;
    const since = parseInt(req.query.since || '0');

    if (!a || !b) return err(res, 'Нужны a и b');

    const key = chatKey(a, b);
    const result = await pool.query(
      'SELECT from_user as "from", from_dn as displayname, text, ts FROM messages WHERE chat_key=$1 AND ts>$2 ORDER BY ts ASC LIMIT 200',
      [key, since]
    );

    ok(res, { messages: result.rows.map(r => ({ ...r, ts: parseInt(r.ts) })) });
  } catch (e) {
    err(res, e.message, 500);
  }
});

// ─── GET CHATS LIST ─────────────────────────────────────────
app.get('/api/chats', async (req, res) => {
  try {
    const username = req.query.username;
    if (!username) return err(res, 'Нужен username');

    // Get all unique chat partners with last message
    const result = await pool.query(`
      SELECT DISTINCT ON (chat_key)
        chat_key,
        CASE WHEN from_user = $1 THEN to_user ELSE from_user END AS other_username,
        text AS last_message,
        ts AS last_ts
      FROM messages
      WHERE from_user = $1 OR to_user = $1
      ORDER BY chat_key, ts DESC
    `, [username]);

    // Get displaynames for all partners
    const chats = [];
    for (const row of result.rows) {
      const uRes = await pool.query('SELECT displayname FROM users WHERE username=$1', [row.other_username]);
      const displayname = uRes.rows[0]?.displayname || row.other_username;

      // Count unread
      const unreadRes = await pool.query(
        'SELECT COUNT(*) FROM messages WHERE chat_key=$1 AND to_user=$2 AND ts>$3',
        [row.chat_key, username, parseInt(req.query.last_seen || '0')]
      );

      chats.push({
        otherUsername: row.other_username,
        otherDisplayname: displayname,
        lastMessage: row.last_message,
        lastTs: parseInt(row.last_ts),
        unread: 0
      });
    }

    // Sort by last message time
    chats.sort((a, b) => b.lastTs - a.lastTs);
    ok(res, { chats });
  } catch (e) {
    err(res, e.message, 500);
  }
});

// ─── SERVE FRONTEND ─────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Wavr running on port ${PORT}`));