const express = require('express');
process.env.STARTED_AT = process.env.STARTED_AT || String(Math.floor(Date.now() / 1000));
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const { WebSocketServer } = require('ws');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');

const app = express();
const server = http.createServer(app);

app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Security headers via helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "data:", "blob:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "wss:"]
    }
  },
  crossOriginResourcePolicy: { policy: 'same-origin' }
}));

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Слишком много попыток' },
  standardHeaders: true,
  legacyHeaders: false
});

const regLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { error: 'Слишком много попыток' },
  standardHeaders: true,
  legacyHeaders: false
});

// Send rate limiter
app.use('/api/send', rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Слишком много сообщений' },
  standardHeaders: true,
  legacyHeaders: false
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

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
      created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())*1000,
      expires_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000 + 2592000000),
      user_agent TEXT DEFAULT '',
      last_seen  BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())*1000
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
    `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS username   TEXT`,
    `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expires_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000 + 2592000000)`,
    `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT DEFAULT ''`,
    `ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen  BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())*1000`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_name TEXT`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_size BIGINT DEFAULT 0`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to  INT DEFAULT NULL`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_preview TEXT DEFAULT NULL`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited     BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE messages ADD COLUMN IF NOT EXISTS pinned     BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_premium BOOLEAN DEFAULT FALSE`,
    `CREATE TABLE IF NOT EXISTS chat_hidden (username TEXT NOT NULL, chat_key TEXT NOT NULL, hidden_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000), PRIMARY KEY (username, chat_key))`,
    `CREATE TABLE IF NOT EXISTS blocked (username TEXT NOT NULL, blocked TEXT NOT NULL, ts BIGINT, PRIMARY KEY (username, blocked))`,
  ];
  for (const m of migs) { try { await pool.query(m); } catch (e) { } }
  try { await pool.query(`DELETE FROM sessions WHERE expires_at < $1`, [Date.now()]); } catch (e) { }
  console.log('DB ready');
}
initDB().catch(console.error);

// ── Helpers ──
const chatKey = (a, b) => [a, b].sort().join(':');
const ok = (res, d) => res.json(d);
const err = (res, msg, s = 400) => res.status(s).json({ error: msg });
const parseReactions = (raw) => { try { return JSON.parse(raw || '{}'); } catch (e) { return {}; } };
const sanitize = (s) => typeof s === 'string' ? xss(s, { whiteList: {}, stripIgnoreTag: true }) : s;

const OWNER = 'timur';

function adminOnly(req, res, next) {
  if (req.username !== OWNER) return err(res, 'Нет прав', 403);
  next();
}

async function auth(req, res, next) {
  const t = req.headers['x-token'];
  if (!t) return err(res, 'Не авторизован', 401);
  const r = await pool.query('SELECT username, expires_at FROM sessions WHERE token=$1', [t]);
  if (!r.rows.length) return err(res, 'Сессия истекла', 401);
  const sess = r.rows[0];
  if (sess.expires_at && Date.now() > parseInt(sess.expires_at)) {
    await pool.query('DELETE FROM sessions WHERE token=$1', [t]);
    return err(res, 'Сессия истекла', 401);
  }
  req.username = sess.username;
  pool.query('UPDATE sessions SET last_seen=$1 WHERE token=$2', [Date.now(), t]).catch(() => {});
  next();
}

// ── WebSocket ──
const wsClients = new Map(); // username → Set<WebSocket>

const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
  const params = new URL(req.url, 'http://localhost').searchParams;
  const token = params.get('token');
  if (!token) { ws.close(4001, 'No token'); return; }

  (async () => {
    const r = await pool.query('SELECT username FROM sessions WHERE token=$1', [token]);
    if (!r.rows.length) { ws.close(4001, 'Invalid token'); return; }
    const username = r.rows[0].username;
    ws.username = username;

    if (!wsClients.has(username)) wsClients.set(username, new Set());
    wsClients.get(username).add(ws);
    ws.isAlive = true;

    ws.on('pong', () => { ws.isAlive = true; });
    ws.on('close', () => {
      const set = wsClients.get(username);
      if (set) { set.delete(ws); if (!set.size) wsClients.delete(username); }
    });
    ws.on('error', () => {});

    // Send auth success
    ws.send(JSON.stringify({ type: 'connected', username }));
  })().catch(() => ws.close(4001, 'Auth failed'));
});

// WebSocket heartbeat every 30s
setInterval(() => {
  for (const [uname, set] of wsClients) {
    for (const ws of set) {
      if (ws.isAlive === false) { ws.terminate(); set.delete(ws); continue; }
      ws.isAlive = false;
      ws.ping();
    }
    if (!set.size) wsClients.delete(uname);
  }
}, 30000);

// Broadcast helper
function wsBroadcast(username, data) {
  const set = wsClients.get(username);
  if (!set) return;
  const msg = JSON.stringify(data);
  for (const ws of set) {
    if (ws.readyState === 1) ws.send(msg);
  }
}

// Helper to send push to chat participants
function wsPushToChat(chatKey, sender, data) {
  const parts = chatKey.split(':');
  for (const p of parts) {
    if (p !== sender) wsBroadcast(p, data);
  }
  // Also send to sender for multi-device sync
  wsBroadcast(sender, data);
}

// ── Poll tracking ──
const pollTs = new Map(); // `${username}:${chatKey}` → lastPollTimestamp (server-side)
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pollTs) if (now - v > 120000) pollTs.delete(k);
}, 60000);

// ── Routes ──

// REGISTER
app.post('/api/register', regLimiter, async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    let { username, password, displayname } = req.body;
    username = (username || '').toLowerCase().trim();
    displayname = (displayname || '').trim();
    if (!username || !password || !displayname) return err(res, 'Заполните все поля');
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return err(res, 'Username: a-z 0-9 _ (3-20 символов)');
    if (password.length < 6) return err(res, 'Пароль минимум 6 символов');
    if (displayname.length > 50) return err(res, 'Имя слишком длинное');
    displayname = sanitize(displayname);
    const ipCnt = await pool.query('SELECT COUNT(*) FROM users WHERE reg_ip=$1', [ip]);
    if (parseInt(ipCnt.rows[0].count) >= 3) return err(res, 'Максимум 3 аккаунта с одного IP', 403);
    const ex = await pool.query('SELECT username FROM users WHERE username=$1', [username]);
    if (ex.rows.length) return err(res, 'Username уже занят', 409);
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username,displayname,password,reg_ip) VALUES ($1,$2,$3,$4)', [username, displayname, hash, ip]);
    const ua = (req.headers['user-agent'] || '').slice(0, 200);
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 30 * 24 * 3600 * 1000;
    await pool.query('INSERT INTO sessions (token,username,expires_at,user_agent) VALUES ($1,$2,$3,$4)', [token, username, expires, ua]);
    ok(res, { user: { username, displayname }, token });
  } catch (e) { err(res, e.message, 500); }
});

// LOGIN
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    let { username, password } = req.body;
    username = (username || '').toLowerCase().trim();
    if (!username || !password) return err(res, 'Заполните все поля');
    const r = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!r.rows.length) return err(res, 'Пользователь не найден', 401);
    const u = r.rows[0];
    if (u.bio === '__BANNED__') return err(res, 'Аккаунт заблокирован', 403);
    if (!await bcrypt.compare(password, u.password)) return err(res, 'Неверный пароль', 401);
    const existing = await pool.query('SELECT token FROM sessions WHERE username=$1 ORDER BY created_at ASC', [username]);
    if (existing.rows.length >= 3) {
      const toDelete = existing.rows.slice(0, existing.rows.length - 2);
      for (const s of toDelete) await pool.query('DELETE FROM sessions WHERE token=$1', [s.token]);
    }
    const ua = (req.headers['user-agent'] || '').slice(0, 200);
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 30 * 24 * 3600 * 1000;
    await pool.query('INSERT INTO sessions (token,username,expires_at,user_agent) VALUES ($1,$2,$3,$4)', [token, username, expires, ua]);
    ok(res, { user: { username: u.username, displayname: u.displayname, avatar: u.avatar, bio: u.bio, is_premium: u.is_premium || false }, token });
  } catch (e) { err(res, e.message, 500); }
});

// LOGOUT
app.post('/api/logout', auth, async (req, res) => {
  await pool.query('DELETE FROM sessions WHERE token=$1', [req.headers['x-token']]);
  ok(res, { ok: true });
});

// GET PROFILE
app.get('/api/profile/:username', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT username,displayname,avatar,bio,created_at,is_premium FROM users WHERE username=$1', [sanitize(req.params.username)]);
    if (!r.rows.length) return err(res, 'Не найден', 404);
    ok(res, { user: r.rows[0] });
  } catch (e) { err(res, e.message, 500); }
});

// UPDATE PROFILE
app.post('/api/profile', auth, async (req, res) => {
  try {
    const { displayname, bio, avatar, newUsername } = req.body;
    const dn = sanitize((displayname || '').trim());
    if (!dn) return err(res, 'Имя не может быть пустым');
    let finalUsername = req.username;
    if (newUsername) {
      const nu = newUsername.toLowerCase().trim();
      if (!/^[a-z0-9_]{3,20}$/.test(nu)) return err(res, 'Username: a-z 0-9 _ (3-20 символов)');
      if (nu !== req.username) {
        const ex = await pool.query('SELECT username FROM users WHERE username=$1', [nu]);
        if (ex.rows.length) return err(res, 'Username уже занят', 409);
        await pool.query('UPDATE messages SET from_user=$1 WHERE from_user=$2', [nu, req.username]);
        await pool.query('UPDATE messages SET to_user=$1   WHERE to_user=$2', [nu, req.username]);
        await pool.query('UPDATE messages SET from_dn=$1  WHERE from_user=$2', [dn, nu]);
        await pool.query('UPDATE sessions  SET username=$1 WHERE username=$2', [nu, req.username]);
        const rows = await pool.query('SELECT DISTINCT chat_key FROM messages WHERE from_user=$1 OR to_user=$1', [nu]);
        for (const row of rows.rows) {
          const nk = row.chat_key.split(':').map(p => p === req.username ? nu : p).sort().join(':');
          if (nk !== row.chat_key) await pool.query('UPDATE messages SET chat_key=$1 WHERE chat_key=$2', [nk, row.chat_key]);
        }
        await pool.query('UPDATE users SET username=$1,displayname=$2,bio=$3,avatar=$4 WHERE username=$5',
          [nu, dn, sanitize((bio || '').slice(0, 200)), avatar || null, req.username]);
        finalUsername = nu;
      }
    }
    if (finalUsername === req.username) {
      await pool.query('UPDATE users SET displayname=$1,bio=$2,avatar=$3 WHERE username=$4',
        [dn, sanitize((bio || '').slice(0, 200)), avatar || null, req.username]);
    }
    ok(res, { ok: true, displayname: dn, username: finalUsername });
  } catch (e) { err(res, e.message, 500); }
});

// SEARCH
app.get('/api/search', auth, async (req, res) => {
  try {
    const q = sanitize((req.query.q || '').trim());
    if (!q) return ok(res, { users: [] });
    const r = await pool.query(
      `SELECT username,displayname,avatar FROM users WHERE username!=$1 AND (username ILIKE $2 OR displayname ILIKE $2) LIMIT 10`,
      [req.username, `%${q}%`]
    );
    ok(res, { users: r.rows });
  } catch (e) { err(res, e.message, 500); }
});

// SEND MESSAGE
app.post('/api/send', auth, async (req, res) => {
  try {
    const { to, text, type, fileName, fileSize, replyTo } = req.body;
    const allowedTypes = ['text', 'image', 'video', 'file'];
    const msgType = allowedTypes.includes(type) ? type : 'text';
    if (msgType === 'text' && !text?.trim()) return err(res, 'Неверные данные');
    if (msgType !== 'text' && !text) return err(res, 'Неверные данные');
    if (!to) return err(res, 'Неверные данные');
    if (msgType !== 'text' && text.length > 22 * 1024 * 1024) return err(res, 'Файл слишком большой', 400);

    const blk = await pool.query('SELECT 1 FROM blocked WHERE username=$1 AND blocked=$2', [to, req.username]);
    if (blk.rows.length) return err(res, 'Пользователь заблокировал вас', 403);
    const ur = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    if (!ur.rows.length) return err(res, 'Пользователь не найден', 404);
    const key = chatKey(req.username, to);
    const ts = Date.now();
    const storeText = msgType === 'text' ? sanitize(text.trim()) : text;

    let replyToId = null, replyPreview = null;
    const rpId = parseInt(replyTo || 0);
    if (rpId) {
      const rr = await pool.query('SELECT id, text, type, from_dn, from_user FROM messages WHERE id=$1 AND chat_key=$2', [rpId, key]);
      if (rr.rows.length) {
        replyToId = rpId;
        const rm = rr.rows[0];
        const pv = rm.type === 'image' ? 'Фото' : rm.type === 'video' ? 'Видео' : rm.type === 'file' ? 'Файл' : sanitize((rm.text || '').slice(0, 80));
        replyPreview = JSON.stringify({ from: rm.from_dn || rm.from_user, text: pv });
      }
    }

    const r = await pool.query(
      'INSERT INTO messages (chat_key,from_user,from_dn,to_user,text,type,ts,file_name,file_size,reply_to,reply_preview) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,ts',
      [key, req.username, ur.rows[0].displayname, to, storeText, msgType, ts, fileName || null, fileSize || 0, replyToId, replyPreview]
    );
    const msgRow = r.rows[0];
    // Broadcast via WebSocket
    const payload = {
      type: 'message',
      id: parseInt(msgRow.id),
      chatKey: key,
      from: req.username,
      displayname: ur.rows[0].displayname,
      text: msgType === 'text' ? storeText : msgType === 'image' ? null : null,
      msgType,
      ts: parseInt(msgRow.ts),
      fileName: fileName || null,
      fileSize: fileSize || 0,
      replyTo: replyToId,
      replyPreview
    };
    wsPushToChat(key, '', payload); // Send to both participants
    ok(res, { ok: true, id: parseInt(msgRow.id), ts: parseInt(msgRow.ts) });
  } catch (e) { err(res, e.message, 500); }
});

// BLOCK / UNBLOCK
app.post('/api/block/:username', auth, async (req, res) => {
  try {
    if (req.params.username === req.username) return err(res, 'Нельзя заблокировать себя');
    const u = await pool.query('SELECT 1 FROM users WHERE username=$1', [sanitize(req.params.username)]);
    if (!u.rows.length) return err(res, 'Пользователь не найден', 404);
    await pool.query('INSERT INTO blocked (username,blocked,ts) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [req.username, req.params.username, Date.now()]);
    ok(res, { ok: true, blocked: true });
  } catch (e) { err(res, e.message, 500); }
});
app.post('/api/unblock/:username', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM blocked WHERE username=$1 AND blocked=$2', [req.username, sanitize(req.params.username)]);
    ok(res, { ok: true, blocked: false });
  } catch (e) { err(res, e.message, 500); }
});
app.get('/api/blocked', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT blocked, ts FROM blocked WHERE username=$1 ORDER BY ts DESC', [req.username]);
    ok(res, { blocked: r.rows.map(x => ({ username: x.blocked, ts: parseInt(x.ts) })) });
  } catch (e) { err(res, e.message, 500); }
});

// REACT TO MESSAGE
app.post('/api/react', auth, async (req, res) => {
  try {
    const { id, emoji } = req.body;
    if (!id || !emoji) return err(res, 'Нужен id и emoji');
    const em = (emoji || '').trim();
    if (!em) return err(res, 'Пустой emoji');
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
    // Broadcast reaction via WS
    wsPushToChat(key, req.username, { type: 'reaction', id: parseInt(id), reactions });
    ok(res, { ok: true, reactions });
  } catch (e) { err(res, e.message, 500); }
});

// MARK AS READ
app.post('/api/read', auth, async (req, res) => {
  try {
    const { other } = req.body;
    if (!other) return err(res, 'Нужен other');
    const key = chatKey(req.username, other);
    const now = Date.now();
    const upd = await pool.query(
      `UPDATE messages SET read_at=$1 WHERE chat_key=$2 AND from_user=$3 AND to_user=$4 AND NOT deleted AND read_at=0 RETURNING id`,
      [now, key, other, req.username]
    );
    // Push read updates via WS
    for (const row of upd.rows) {
      wsBroadcast(other, { type: 'read', id: row.id, read_at: now });
    }
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// DELETE MESSAGE
app.delete('/api/message/:id', auth, async (req, res) => {
  try {
    const { everyone } = req.query;
    const r = await pool.query('SELECT from_user, chat_key FROM messages WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    if (r.rows[0].from_user !== req.username) return err(res, 'Нет прав', 403);
    const key = r.rows[0].chat_key;
    if (everyone) {
      await pool.query('DELETE FROM messages WHERE id=$1', [req.params.id]);
      wsPushToChat(key, req.username, { type: 'delete', id: parseInt(req.params.id), everyone: true });
    } else {
      await pool.query('UPDATE messages SET deleted=TRUE,text=$1 WHERE id=$2', ['Сообщение удалено', req.params.id]);
      wsPushToChat(key, req.username, { type: 'delete', id: parseInt(req.params.id), everyone: false });
    }
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// EDIT MESSAGE
app.patch('/api/message/:id', auth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return err(res, 'Пустой текст');
    const r = await pool.query('SELECT from_user, deleted, chat_key FROM messages WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    if (r.rows[0].from_user !== req.username) return err(res, 'Нет прав', 403);
    if (r.rows[0].deleted) return err(res, 'Сообщение удалено', 400);
    const newText = sanitize(text.trim());
    await pool.query('UPDATE messages SET text=$1,edited=TRUE WHERE id=$2', [newText, req.params.id]);
    const key = r.rows[0].chat_key;
    wsPushToChat(key, req.username, { type: 'edit', id: parseInt(req.params.id), text: newText });
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// DELETE CHAT
app.delete('/api/chat/:other', auth, async (req, res) => {
  try {
    const key = chatKey(req.username, req.params.other);
    const { everyone } = req.query;
    if (everyone) {
      await pool.query('DELETE FROM messages WHERE chat_key=$1', [key]);
      await pool.query('DELETE FROM chat_hidden WHERE chat_key=$1', [key]);
    } else {
      await pool.query('INSERT INTO chat_hidden (username,chat_key,hidden_at) VALUES ($1,$2,$3) ON CONFLICT (username,chat_key) DO UPDATE SET hidden_at=EXCLUDED.hidden_at', [req.username, key, Date.now()]);
    }
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// PIN / UNPIN
app.post('/api/pin/:id', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT chat_key FROM messages WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    const parts = r.rows[0].chat_key.split(':');
    if (!parts.includes(req.username)) return err(res, 'Нет прав', 403);
    const m = await pool.query('SELECT pinned, from_user, to_user FROM messages WHERE id=$1', [req.params.id]);
    const wasPinned = m.rows[0].pinned;
    if (!wasPinned) {
      await pool.query('UPDATE messages SET pinned=FALSE WHERE chat_key=$1 AND pinned=TRUE', [r.rows[0].chat_key]);
    }
    await pool.query('UPDATE messages SET pinned=$1 WHERE id=$2', [!wasPinned, req.params.id]);
    const newPinned = !wasPinned;
    wsPushToChat(r.rows[0].chat_key, req.username, { type: 'pin', id: parseInt(req.params.id), pinned: newPinned });
    ok(res, { ok: true, pinned: newPinned });
  } catch (e) { err(res, e.message, 500); }
});

// ── Typing indicator (in-memory) ──
const typingMap = new Map();
app.post('/api/typing', auth, async (req, res) => {
  try {
    const { to } = req.body;
    if (!to) return err(res, 'Нужен to');
    const key = chatKey(req.username, to);
    typingMap.set(key, { username: req.username, ts: Date.now() });
    wsBroadcast(to, { type: 'typing', from: req.username });
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});
app.get('/api/typing', auth, async (req, res) => {
  try {
    const { b } = req.query;
    if (!b) return ok(res, { typing: false });
    const key = chatKey(req.username, b);
    const entry = typingMap.get(key);
    if (entry && entry.username !== req.username && Date.now() - entry.ts < 4000) {
      return ok(res, { typing: true, username: entry.username });
    }
    ok(res, { typing: false });
  } catch (e) { err(res, e.message, 500); }
});
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of typingMap) if (now - v.ts > 5000) typingMap.delete(k);
}, 10000);

// PING
app.post('/api/ping', auth, async (req, res) => {
  ok(res, { ok: true });
});

// ONLINE STATUS
app.get('/api/online/:username', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT MAX(last_seen) as last_seen FROM sessions WHERE username=$1', [sanitize(req.params.username)]);
    const lastSeen = r.rows[0]?.last_seen ? parseInt(r.rows[0].last_seen) : 0;
    const online = lastSeen > 0 && Date.now() - lastSeen < 300000;
    ok(res, { online, last_seen: lastSeen });
  } catch (e) { err(res, e.message, 500); }
});

// GET MESSAGES
app.get('/api/messages', auth, async (req, res) => {
  try {
    const { b, since, before } = req.query;
    if (!b) return err(res, 'Нужен b');
    const key = chatKey(req.username, b);
    const sinceTs = parseInt(since || '0');
    const beforeTs = parseInt(before || '0');
    const hid = await pool.query(
      'SELECT hidden_at FROM chat_hidden WHERE username=$1 AND chat_key=$2',
      [req.username, key]
    );
    const hiddenAt = hid.rows.length ? parseInt(hid.rows[0].hidden_at) : 0;
    let rows;
    if (beforeTs > 0) {
      const r = await pool.query(
        `SELECT id, from_user as "from", from_dn as displayname, text, type, ts, deleted, read_at, reactions, file_name, file_size, reply_to, reply_preview, edited, pinned
         FROM messages WHERE chat_key=$1 AND ts<$2 AND ts>$3 AND NOT deleted ORDER BY ts DESC LIMIT 100`,
        [key, beforeTs, hiddenAt]
      );
      rows = r.rows.reverse();
    } else {
      const r = await pool.query(
        `SELECT id, from_user as "from", from_dn as displayname, text, type, ts, deleted, read_at, reactions, file_name, file_size, reply_to, reply_preview, edited, pinned
         FROM messages WHERE chat_key=$1 AND ts>$2 AND ts>$3 ORDER BY ts ASC LIMIT 100`,
          [key, sinceTs, hiddenAt]
      );
      rows = r.rows;
    }
    ok(res, {
      messages: rows.map(m => ({
        ...m,
        ts: parseInt(m.ts),
        read_at: parseInt(m.read_at || 0),
        file_size: parseInt(m.file_size || 0),
        reactions: parseReactions(m.reactions),
        reply_to: m.reply_to || null,
        reply_preview: m.reply_preview || null
      }))
    });
  } catch (e) { err(res, e.message, 500); }
});

// GET MEDIA
app.get('/api/media/:id', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, text, type, chat_key FROM messages WHERE id=$1 AND type!='text' AND NOT deleted`,
      [req.params.id]
    );
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    const parts = r.rows[0].chat_key.split(':');
    if (!parts.includes(req.username)) return err(res, 'Нет прав', 403);
    ok(res, { id: r.rows[0].id, text: r.rows[0].text, type: r.rows[0].type });
  } catch (e) { err(res, e.message, 500); }
});

// POLL
app.get('/api/poll', auth, async (req, res) => {
  try {
    const { b, since } = req.query;
    if (!b) return ok(res, { messages: [], readUpdates: [], reactionUpdates: [] });
    const key = chatKey(req.username, b);
    const sinceTs = parseInt(since || '0');

    // Track last poll ts to avoid repeat read/reaction queries
    const pollKey = `${req.username}:${key}`;
    const lastPoll = pollTs.get(pollKey) || 0;
    pollTs.set(pollKey, Date.now());

    // New messages
    const newMsgs = await pool.query(
      `SELECT id, from_user as "from", from_dn as displayname,
              CASE WHEN type='text' OR deleted THEN text ELSE NULL END as text,
              type, ts, deleted, read_at, reactions, file_name, file_size, reply_to, reply_preview, edited, pinned
       FROM messages WHERE chat_key=$1 AND ts>$2 ORDER BY ts ASC LIMIT 100`,
      [key, sinceTs]
    );

    // Read updates - only since last poll or last 5 min (whichever is smaller)
    const readSince = Math.max(lastPoll, Date.now() - 300000);
    const readUpdates = await pool.query(
      `SELECT id, read_at FROM messages WHERE chat_key=$1 AND from_user=$2 AND read_at>$3`,
      [key, req.username, readSince]
    );

    // Reaction updates - only since last poll
    const reactionUpdates = await pool.query(
      `SELECT id, reactions FROM messages WHERE chat_key=$1 AND NOT deleted AND ts > $2`,
      [key, readSince]
    );

    ok(res, {
      messages: newMsgs.rows.map(m => ({
        ...m,
        ts: parseInt(m.ts),
        read_at: parseInt(m.read_at || 0),
        file_size: parseInt(m.file_size || 0),
        reactions: parseReactions(m.reactions),
        reply_to: m.reply_to || null,
        reply_preview: m.reply_preview || null
      })),
      readUpdates: readUpdates.rows.map(r => ({ id: r.id, read_at: parseInt(r.read_at) })),
      reactionUpdates: reactionUpdates.rows.map(r => ({ id: r.id, reactions: parseReactions(r.reactions) }))
    });
  } catch (e) { err(res, e.message, 500); }
});

// GET CHATS
app.get('/api/chats', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT m.chat_key,
        CASE WHEN m.from_user=$1 THEN m.to_user ELSE m.from_user END AS other_username,
        m.text AS last_message, m.type AS last_type, m.ts AS last_ts, m.deleted
      FROM messages m
      LEFT JOIN chat_hidden hc ON hc.username=$1 AND hc.chat_key=m.chat_key
      INNER JOIN (
        SELECT chat_key, MAX(ts) AS max_ts
        FROM messages
        WHERE (from_user=$1 OR to_user=$1)
        GROUP BY chat_key
      ) latest ON m.chat_key = latest.chat_key AND m.ts = latest.max_ts
      WHERE (m.from_user=$1 OR m.to_user=$1)
        AND (hc.hidden_at IS NULL OR m.ts > hc.hidden_at)
      ORDER BY m.ts DESC
    `, [req.username]);

    const unreadR = await pool.query(`
      SELECT from_user, COUNT(*) as cnt FROM messages
      WHERE to_user=$1 AND NOT deleted AND read_at=0
      GROUP BY from_user
    `, [req.username]);
    const unreadMap = {};
    for (const r of unreadR.rows) unreadMap[r.from_user] = parseInt(r.cnt);

    const others = [...new Set(result.rows.map(r => r.other_username).filter(Boolean))];
    let usersMap = {};
    if (others.length) {
      const ph = others.map((_, i) => `$${i + 1}`).join(',');
      const ur = await pool.query(`SELECT username,displayname,avatar FROM users WHERE username IN (${ph})`, others);
      for (const u of ur.rows) usersMap[u.username] = u;
    }
    let lastSeenMap = {};
    if (others.length) {
      const ph = others.map((_, i) => `$${i + 1}`).join(',');
      const ls = await pool.query(`SELECT username, MAX(last_seen) as last_seen FROM sessions WHERE username IN (${ph}) GROUP BY username`, others);
      for (const s of ls.rows) lastSeenMap[s.username] = parseInt(s.last_seen || 0);
    }

    const seen = new Set();
    const chats = [];
    const sorted = [...result.rows].sort((a, b) => parseInt(b.last_ts) - parseInt(a.last_ts));
    for (const row of sorted) {
      const other = row.other_username;
      if (!other || seen.has(other)) continue;
      seen.add(other);
      const u = usersMap[other] || {};
      let preview = row.deleted ? 'Удалено' : row.last_message;
      if (!row.deleted) {
        if (row.last_type === 'image') preview = 'Фото';
        else if (row.last_type === 'video') preview = 'Видео';
        else if (row.last_type === 'file') preview = 'Файл';
        else if (preview && preview.length > 60) preview = preview.slice(0, 60) + '…';
      }
      chats.push({
        otherUsername: other,
        otherDisplayname: u.displayname || other,
        otherAvatar: u.avatar || null,
        lastMessage: preview,
        lastTs: parseInt(row.last_ts),
        unread: unreadMap[other] || 0,
        lastSeen: lastSeenMap[other] || 0
      });
    }
    ok(res, { chats });
  } catch (e) { err(res, e.message, 500); }
});

// SESSIONS
app.get('/api/sessions', auth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT token, created_at, expires_at, user_agent, last_seen FROM sessions WHERE username=$1 ORDER BY last_seen DESC',
      [req.username]
    );
    const currentToken = req.headers['x-token'];
    ok(res, {
      sessions: r.rows.map(s => ({
        token: s.token,
        token_display: s.token.slice(0, 8) + '…',
        is_current: s.token === currentToken,
        created_at: parseInt(s.created_at),
        expires_at: parseInt(s.expires_at || 0),
        last_seen: parseInt(s.last_seen || 0),
        user_agent: s.user_agent || ''
      }))
    });
  } catch (e) { err(res, e.message, 500); }
});
app.delete('/api/sessions/:token', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM sessions WHERE token=$1 AND username=$2', [req.params.token, req.username]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});
app.post('/api/sessions/revoke-others', auth, async (req, res) => {
  try {
    const currentToken = req.headers['x-token'];
    await pool.query('DELETE FROM sessions WHERE username=$1 AND token!=$2', [req.username, currentToken]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// ADMIN
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.username, u.displayname, u.bio, u.reg_ip, u.created_at, u.is_premium,
        (SELECT COUNT(*) FROM messages WHERE from_user=u.username) as msg_count,
        (SELECT COUNT(*) FROM sessions WHERE username=u.username) as session_count,
        (SELECT MAX(last_seen) FROM sessions WHERE username=u.username) as last_seen
       FROM users u ORDER BY u.created_at DESC`
    );
    ok(res, {
      users: r.rows.map(u => ({ ...u, created_at: parseInt(u.created_at), msg_count: parseInt(u.msg_count), session_count: parseInt(u.session_count), last_seen: parseInt(u.last_seen || 0) }))
    });
  } catch (e) { err(res, e.message, 500); }
});
app.delete('/api/admin/user/:username', auth, adminOnly, async (req, res) => {
  try {
    const u = req.params.username;
    if (u === OWNER) return err(res, 'Нельзя удалить владельца', 403);
    await pool.query('DELETE FROM sessions WHERE username=$1', [u]);
    await pool.query('DELETE FROM messages WHERE from_user=$1 OR to_user=$1', [u]);
    await pool.query('DELETE FROM users WHERE username=$1', [u]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});
app.post('/api/admin/kick/:username', auth, adminOnly, async (req, res) => {
  try {
    const u = req.params.username;
    if (u === OWNER) return err(res, 'Нельзя кикнуть владельца', 403);
    await pool.query('DELETE FROM sessions WHERE username=$1', [u]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});
app.post('/api/admin/ban/:username', auth, adminOnly, async (req, res) => {
  try {
    const u = req.params.username;
    if (u === OWNER) return err(res, 'Нельзя забанить владельца', 403);
    await pool.query('UPDATE users SET bio=$1 WHERE username=$2', ['__BANNED__', u]);
    await pool.query('DELETE FROM sessions WHERE username=$1', [u]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});
app.post('/api/admin/unban/:username', auth, adminOnly, async (req, res) => {
  try {
    await pool.query("UPDATE users SET bio='' WHERE username=$1", [req.params.username]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});
app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const users = await pool.query('SELECT COUNT(*) as c FROM users');
    const msgs = await pool.query('SELECT COUNT(*) as c FROM messages');
    const sess = await pool.query('SELECT COUNT(*) as c FROM sessions');
    const today = await pool.query('SELECT COUNT(*) as c FROM messages WHERE ts > $1', [Date.now() - 86400000]);
    const prem = await pool.query('SELECT COUNT(*) as c FROM users WHERE is_premium=true');
    ok(res, { users: parseInt(users.rows[0].c), messages: parseInt(msgs.rows[0].c), sessions: parseInt(sess.rows[0].c), today: parseInt(today.rows[0].c), premium: parseInt(prem.rows[0].c) });
  } catch (e) { err(res, e.message, 500); }
});
app.post('/api/admin/premium', auth, adminOnly, async (req, res) => {
  try {
    const { username, action } = req.body;
    if (!username || !['grant','revoke'].includes(action)) return err(res, 'Нужен username и action (grant/revoke)', 400);
    if (username === OWNER) return err(res, 'Владелец и так премиум', 403);
    const r = await pool.query('UPDATE users SET is_premium=$1 WHERE username=$2 RETURNING username, is_premium', [action === 'grant', username]);
    if (!r.rows.length) return err(res, 'Пользователь не найден', 404);
    ok(res, { ok: true, user: r.rows[0] });
  } catch (e) { err(res, e.message, 500); }
});
app.get('/api/admin/premium', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT username, displayname, is_premium FROM users WHERE is_premium=true ORDER BY username');
    ok(res, { users: r.rows });
  } catch (e) { err(res, e.message, 500); }
});
app.get('/api/admin/system', auth, adminOnly, async (req, res) => {
  try {
    const startedAt = process.env.STARTED_AT ? parseInt(process.env.STARTED_AT) : Math.floor(Date.now() / 1000);
    const uptimeSec = Math.floor(process.uptime());
    const d = Math.floor(uptimeSec / 86400);
    const h = Math.floor((uptimeSec % 86400) / 3600);
    const m = Math.floor((uptimeSec % 3600) / 60);
    const s = uptimeSec % 60;
    const uptimeStr = d > 0 ? `${d}д ${h}ч ${m}м ${s}с` : h > 0 ? `${h}ч ${m}м ${s}с` : `${m}м ${s}с`;
    const mem = process.memoryUsage();
    const memStr = (mem.rss / 1024 / 1024).toFixed(1) + ' MB RSS';
    const sess = await pool.query('SELECT COUNT(*) as c FROM sessions');
    ok(res, {
      version: process.env.npm_package_version || require('./package.json').version || '1.0.0',
      node: process.version,
      platform: process.platform + ' ' + process.arch,
      uptime: uptimeStr,
      started: new Date(startedAt * 1000).toLocaleString('ru-RU'),
      memory: memStr,
      sessions: parseInt(sess.rows[0].c)
    });
  } catch (e) { err(res, e.message, 500); }
});

// In-memory rate limit fallback for IP-based limits
const memRateLimitStore = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of memRateLimitStore) if (now > v.r) memRateLimitStore.delete(k); }, 300000);
function memRateLimit(key, max, ms) {
  const now = Date.now();
  const e = memRateLimitStore.get(key) || { n: 0, r: now + ms };
  if (now > e.r) { e.n = 0; e.r = now + ms; }
  e.n++;
  memRateLimitStore.set(key, e);
  return e.n > max;
}

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Wavr on port ${PORT}`));
