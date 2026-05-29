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

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason?.message || reason);
});

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
    CREATE TABLE IF NOT EXISTS chats (
      id          TEXT PRIMARY KEY,
      type        TEXT NOT NULL DEFAULT 'group',
      name        TEXT NOT NULL,
      avatar      TEXT,
      description TEXT DEFAULT '',
      creator     TEXT NOT NULL,
      created_at  BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000)
    );
    CREATE TABLE IF NOT EXISTS chat_members (
      chat_id   TEXT NOT NULL,
      username  TEXT NOT NULL,
      role      TEXT DEFAULT 'member',
      joined_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000),
      PRIMARY KEY (chat_id, username)
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
    `CREATE TABLE IF NOT EXISTS push_subscriptions (username TEXT NOT NULL, endpoint TEXT, auth TEXT, p256dh TEXT, PRIMARY KEY (username))`,
    `CREATE TABLE IF NOT EXISTS chat_archived (username TEXT NOT NULL, chat_key TEXT NOT NULL, archived_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())*1000), PRIMARY KEY (username, chat_key))`,
  ];
  for (const m of migs) { try { await pool.query(m); } catch (e) { console.error('Migration error:', e.message); } }
  try { await pool.query(`DELETE FROM sessions WHERE expires_at < $1`, [Date.now()]); } catch (e) { console.error('Session cleanup error:', e.message); }
  console.log('DB ready');
}
const _initPromise = initDB();

// ── Helpers ──
const chatKey = (a, b) => [a, b].sort().join(':');
const ok = (res, d) => res.json(d);
const err = (res, msg, s = 400) => res.status(s).json({ error: msg });
const parseReactions = (raw) => { try { return JSON.parse(raw || '{}'); } catch (e) { return {}; } };
const sanitize = (s) => s && typeof s === 'string' ? xss(s, { whiteList: {}, stripIgnoreTag: true }) : (s || '');
const typeLabel = (type) => type === 'image' ? 'Фото' : type === 'video' ? 'Видео' : type === 'file' ? 'Файл' : type === 'voice' ? '🎤 Голосовое' : type === 'sticker' ? '🎨 Стикер' : type === 'poll' ? '📊 Опрос' : null;

const OWNER = process.env.WAVR_OWNER || 'timur';

// Throttle last_seen DB writes — max once per 60s per token
const _lastSeenThrottle = new Map();
const LAST_SEEN_THROTTLE_MS = 60000;

// Auth cache: token -> { username, expires_at } with 60s TTL to avoid DB on every request
const _authCache = new Map();
const AUTH_CACHE_TTL = 60000;

function adminOnly(req, res, next) {
  if (req.username !== OWNER) return err(res, 'Нет прав', 403);
  next();
}

async function auth(req, res, next) {
  const t = req.headers['x-token'];
  if (!t) return err(res, 'Не авторизован', 401);
  const now = Date.now();
  const cached = _authCache.get(t);
  if (cached && now - cached.ts < AUTH_CACHE_TTL) {
    if (cached.expires_at && now > cached.expires_at) {
      _authCache.delete(t);
      pool.query('DELETE FROM sessions WHERE token=$1', [t]).catch(() => {});
      return err(res, 'Сессия истекла', 401);
    }
    req.username = cached.username;
    const lastSeen = _lastSeenThrottle.get(t);
    if (!lastSeen || now - lastSeen > LAST_SEEN_THROTTLE_MS) {
      _lastSeenThrottle.set(t, now);
      pool.query('UPDATE sessions SET last_seen=$1 WHERE token=$2', [now, t]).catch(() => {});
    }
    return next();
  }
  const r = await pool.query('SELECT username, expires_at FROM sessions WHERE token=$1', [t]);
  if (!r.rows.length) return err(res, 'Сессия истекла', 401);
  const sess = r.rows[0];
  if (sess.expires_at && now > parseInt(sess.expires_at)) {
    await pool.query('DELETE FROM sessions WHERE token=$1', [t]);
    return err(res, 'Сессия истекла', 401);
  }
  _authCache.set(t, { username: sess.username, expires_at: parseInt(sess.expires_at || 0), ts: now });
  req.username = sess.username;
  const lastSeen = _lastSeenThrottle.get(t);
  if (!lastSeen || now - lastSeen > LAST_SEEN_THROTTLE_MS) {
    _lastSeenThrottle.set(t, now);
    pool.query('UPDATE sessions SET last_seen=$1 WHERE token=$2', [now, t]).catch(() => {});
  }
  next();
}

// ── WebSocket ──
const wsClients = new Map(); // username → Set<WebSocket>

const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
  console.log('WS connection attempt from ' + (req.headers['x-forwarded-for'] || req.socket.remoteAddress));
  let authTimeout, username;

  const authTimer = setTimeout(() => {
    console.log('WS auth timeout: no auth message received');
    ws.close(4001, 'Auth timeout');
  }, 5000);

  ws._authed = false;
  ws.on('message', (data) => {
    if (!ws._authed) {
      try {
        const msg = JSON.parse(typeof data === 'string' ? data : data.toString());
        if (msg.type !== 'auth' || !msg.token) {
          ws.close(4001, 'Auth required as first message');
          return;
        }
        clearTimeout(authTimer);
        (async () => {
          const r = await pool.query('SELECT username FROM sessions WHERE token=$1', [msg.token]);
          if (!r.rows.length) { console.log('WS auth fail: invalid token'); ws.close(4001, 'Invalid token'); return; }
          username = r.rows[0].username;
          console.log('WS connected: ' + username);
          ws.username = username;
          ws._authed = true;

          const set = wsClients.get(username);
          if (set) { set.add(ws); } else { wsClients.set(username, new Set([ws])); }
          ws.isAlive = true;

          setupWSHandlers(ws, username);
          try { ws.send(JSON.stringify({ type: 'connected', username })); } catch (e) {}
        })();
      } catch (e) {
        ws.close(4001, 'Invalid JSON');
      }
    }
    // Post-auth messages ignored by server (it only pushes, doesn't receive)
  });
});

function setupWSHandlers(ws, username) {
  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('close', () => {
    const set = wsClients.get(username);
    if (set) { set.delete(ws); if (!set.size) wsClients.delete(username); }
  });
  ws.on('error', (e) => { console.log('WS error ' + username + ': ' + (e?.message || e)); });
}

// WebSocket heartbeat every 30s
setInterval(() => {
  const toRemove = [];
  for (const [uname, set] of wsClients) {
    for (const ws of set) {
      if (ws.isAlive === false) { ws.terminate(); toRemove.push({ set, ws }); continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch (e) { ws.terminate(); toRemove.push({ set, ws }); }
    }
  }
  const empty = [];
  for (const { set, ws } of toRemove) { set.delete(ws); if (!set.size) { for (const [k, s] of wsClients) { if (s === set) { empty.push(k); break; } } } }
  for (const k of empty) wsClients.delete(k);
}, 30000);

// Broadcast helper
function wsBroadcast(username, data) {
  const set = wsClients.get(username);
  if (!set) return;
  const msg = JSON.stringify(data);
  for (const ws of set) {
    if (ws.readyState === 1) { try { ws.send(msg); } catch (e) { /* socket closed between check and send */ } }
  }
}

// Helper to send push to chat participants (works for both private and group chats)
async function wsPushToChat(chatKey, sender, data) {
  if (isGroupChat(chatKey)) {
    const gid = groupIdFromKey(chatKey);
    const allMem = await pool.query('SELECT username FROM chat_members WHERE chat_id=$1', [gid]);
    for (const m of allMem.rows) {
      wsBroadcast(m.username, data);
      if (m.username !== sender && (!wsClients.has(m.username) || ![...(wsClients.get(m.username) || [])].some(s => s.readyState === 1))) {
        const pushPayload = {
          type: 'new_message',
          chatKey,
          from: data.from,
          displayname: data.displayname || data.from,
          text: typeLabel(data.msgType) || (data.text || ''),
          msgType: data.msgType,
          id: data.id,
          ts: data.ts
        };
        sendPushNotification(m.username, pushPayload);
      }
    }
  } else {
    const parts = chatKey.split(':');
    for (const p of parts) {
      if (p !== sender) wsBroadcast(p, data);
    }
    wsBroadcast(sender, data);
    for (const p of parts) {
      if (p !== sender && (!wsClients.has(p) || ![...(wsClients.get(p) || [])].some(s => s.readyState === 1))) {
        const pushPayload = {
          type: 'new_message',
          chatKey,
          from: data.from,
          displayname: data.displayname || data.from,
          text: typeLabel(data.msgType) || (data.text || ''),
          msgType: data.msgType,
          id: data.id,
          ts: data.ts
        };
        sendPushNotification(p, pushPayload);
      }
    }
  }
}

// ── Stickers ──
const STICKER_PACKS = [
  { id: 'classic', name: 'Классика', stickers: ['👍', '❤️', '😂', '😮', '😢', '🔥', '👎', '🎉', '😍', '💀', '🤝', '✨', '😤', '🥹', '💯', '🙏', '😎', '🤔', '🥶', '🤯'] },
  { id: 'cats', name: 'Кошки', stickers: ['🐱', '😺', '😸', '😻', '😽', '🙀', '😿', '😾', '🐈', '🐈‍⬛'] },
  { id: 'dogs', name: 'Собаки', stickers: ['🐶', '🐕', '🦮', '🐩', '🐾', '🦴', '🐕‍🦺', '🦊', '🐺'] },
  { id: 'food', name: 'Еда', stickers: ['🍕', '🍔', '🌮', '🍣', '🍩', '🍪', '🍰', '🧁', '🍦', '🍿', '🥤', '☕'] },
  { id: 'nature', name: 'Природа', stickers: ['🌺', '🌸', '🌻', '🌹', '🌷', '🌿', '🍀', '🌴', '🌊', '⛰️', '🌈', '⭐'] },
  { id: 'love', name: 'Любовь', stickers: ['💖', '💗', '💝', '💕', '💌', '💋', '🥰', '😘', '💑', '👩‍❤️‍👨', '💞', '❤️‍🔥'] },
  { id: 'party', name: 'Пати', stickers: ['🎉', '🎊', '🎈', '🎀', '🎁', '🥳', '🎇', '✨', '💃', '🕺', '🎵', '🎶'] },
  { id: 'sport', name: 'Спорт', stickers: ['⚽', '🏀', '🏈', '⚾', '🎾', '🏐', '🏓', '🎯', '🚴', '🏋️', '🤸', '🧘'] },
  { id: 'animals', name: 'Животные', stickers: ['🐻', '🐼', '🐨', '🐸', '🐒', '🐔', '🐧', '🐦', '🦆', '🦉', '🦇', '🐝'] },
  { id: 'space', name: 'Космос', stickers: ['🚀', '🛸', '🛰️', '👽', '🤖', '🌍', '🌙', '☀️', '⭐', '🌌', '🪐', '👾'] },
];

app.get('/api/stickers', (req, res) => {
  ok(res, { packs: STICKER_PACKS });
});

// ── Push notifications ──
const webpush = require('web-push');
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_EMAIL = process.env.VAPID_EMAIL || 'mailto:support@wavr.app';
if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
}

app.post('/api/push/subscribe', auth, async (req, res) => {
  try {
    const { endpoint, keys } = req.body;
    if (!endpoint || !keys || !keys.auth || !keys.p256dh) return err(res, 'Invalid subscription');
    await pool.query(`INSERT INTO push_subscriptions (username, endpoint, auth, p256dh) VALUES ($1,$2,$3,$4) ON CONFLICT (username) DO UPDATE SET endpoint=$2, auth=$3, p256dh=$4`, [req.username, endpoint, keys.auth, keys.p256dh]);
    ok(res, { ok: true });
  } catch (e) { err(res, 'Push sub fail'); }
});

app.post('/api/push/unsubscribe', auth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM push_subscriptions WHERE username=$1`, [req.username]);
    ok(res, { ok: true });
  } catch (e) { err(res, 'Push unsub fail'); }
});

// ── Search messages ──
app.get('/api/search/messages', auth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q || q.length < 2) return ok(res, { messages: [] });
    const username = req.username;
    // Find all chat keys for private chats
    const chatsR = await pool.query(`SELECT DISTINCT chat_key FROM messages WHERE (from_user=$1 OR to_user=$1) AND chat_key NOT LIKE 'group:%'`, [username]);
    const chatKeys = chatsR.rows.map(r => r.chat_key);
    // Also include group chat keys
    const grpR = await pool.query('SELECT chat_id FROM chat_members WHERE username=$1', [username]);
    for (const g of grpR.rows) chatKeys.push(groupKey(g.chat_id));
    if (!chatKeys.length) return ok(res, { messages: [] });
    // Search messages in those chats
    const like = '%' + q.replace(/%/g, '\\%').replace(/_/g, '\\_') + '%';
    const msgR = await pool.query(
      `SELECT id, chat_key, from_user, from_dn, text, type, ts, file_name, file_size, reply_to, reply_preview, reactions, edited, deleted, read_at FROM messages WHERE chat_key = ANY($1) AND (LOWER(text) LIKE LOWER($2) OR LOWER(file_name) LIKE LOWER($2)) AND deleted = false ORDER BY ts DESC LIMIT 50`,
      [chatKeys, like]
    );
    // Resolve chat names
    const uniqueKeys = [...new Set(msgR.rows.map(r => r.chat_key))];
    const chatNameMap = {};
    const grpKeys = uniqueKeys.filter(k => k.startsWith('group:'));
    if (grpKeys.length) {
      const grpIds = grpKeys.map(k => k.replace('group:', ''));
      const grpR = await pool.query(`SELECT id, name FROM chats WHERE id = ANY($1)`, [grpIds]);
      for (const g of grpR.rows) chatNameMap['group:' + g.id] = g.name;
    }
    const privKeys = uniqueKeys.filter(k => !k.startsWith('group:'));
    if (privKeys.length) {
      const others = privKeys.map(k => k.replace(username + ':', '').replace(':' + username, '')).filter(u => u !== username);
      if (others.length) {
        const ph = others.map((_, i) => '$' + (i + 1)).join(',');
        const ur = await pool.query(`SELECT username, displayname FROM users WHERE username IN (${ph})`, others);
        for (const u of ur.rows) {
          for (const k of privKeys) {
            if (k.includes(u.username) && !chatNameMap[k]) chatNameMap[k] = u.displayname;
          }
        }
      }
      for (const k of privKeys) { if (!chatNameMap[k]) chatNameMap[k] = k.split(':').filter(u => u !== username).join(':') || k; }
    }
    const messages = msgR.rows.map(r => ({
      id: r.id, chatKey: r.chat_key, chatName: chatNameMap[r.chat_key] || r.chat_key,
      from: r.from_user, displayname: r.from_dn,
      text: r.text, msgType: r.type, ts: parseInt(r.ts),
      fileName: r.file_name, fileSize: r.file_size,
      replyTo: r.reply_to, replyPreview: r.reply_preview,
      reactions: parseReactions(r.reactions), edited: r.edited,
      deleted: r.deleted, readAt: r.read_at ? parseInt(r.read_at) : 0
    }));
    ok(res, { messages });
  } catch (e) { err(res, e.message, 500); }
});

app.get('/api/push/vapid-key', (req, res) => {
  ok(res, { publicKey: VAPID_PUBLIC_KEY });
});

async function sendPushNotification(username, payload) {
  try {
    const r = await pool.query(`SELECT endpoint, auth, p256dh FROM push_subscriptions WHERE username=$1`, [username]);
    if (!r.rows.length) return;
    const { endpoint, auth, p256dh } = r.rows[0];
    if (!endpoint) return;
    const sub = { endpoint, keys: { auth, p256dh } };
    await webpush.sendNotification(sub, JSON.stringify(payload), { TTL: 86400 });
  } catch (e) {
    // if subscription is expired, clean it
    if (e.statusCode === 410) {
      try { await pool.query(`DELETE FROM push_subscriptions WHERE username=$1`, [username]); } catch (e2) {}
    }
  }
}

app.get('/api/push/vapid-key', (req, res) => {
  ok(res, { publicKey: VAPID_PUBLIC_KEY || '' });
});

// REGISTER
app.post('/api/register', regLimiter, async (req, res) => {
  try {
    let { username, password, displayname } = req.body;
    username = (username || '').toLowerCase().trim();
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return err(res, 'Username: a-z 0-9 _ (3-20 символов)');
    if (!password || password.length < 6) return err(res, 'Пароль минимум 6 символов');
    displayname = sanitize((displayname || username).slice(0, 40));
    const ex = await pool.query('SELECT username FROM users WHERE username=$1', [username]);
    if (ex.rows.length) return err(res, 'Username уже занят', 409);
    const hash = await bcrypt.hash(password, 12);
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    await pool.query(
      'INSERT INTO users (username,displayname,password,reg_ip) VALUES ($1,$2,$3,$4)',
      [username, displayname, hash, ip]
    );
    const ua = (req.headers['user-agent'] || '').slice(0, 200);
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 30 * 24 * 3600 * 1000;
    await pool.query('INSERT INTO sessions (token,username,expires_at,user_agent) VALUES ($1,$2,$3,$4)', [token, username, expires, ua]);
    ok(res, { user: { username, displayname, avatar: null, bio: '', is_premium: false }, token });
  } catch (e) { err(res, e.message, 500); }
});

// LOGIN
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    let { username, password } = req.body;
    username = (username || '').toLowerCase().trim();
    if (!username || !password) return err(res, 'Заполните все поля');
    const r = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    const u = r.rows[0];
    if (!r.rows.length || !await bcrypt.compare(password, u.password)) return err(res, 'Неверный логин или пароль', 401);
    if (u.bio === '__BANNED__') return err(res, 'Аккаунт заблокирован', 403);
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
    const user = r.rows[0];
    // Stats
    const msgR = await pool.query('SELECT COUNT(*) as cnt FROM messages WHERE (from_user=$1 OR to_user=$1) AND deleted=false', [user.username]);
    user.msg_count = parseInt(msgR.rows[0].cnt) || 0;
    const mediaR = await pool.query("SELECT COUNT(*) as cnt FROM messages WHERE (from_user=$1 OR to_user=$1) AND deleted=false AND type IN ('image','video','file')", [user.username]);
    user.media_count = parseInt(mediaR.rows[0].cnt) || 0;
    ok(res, { user });
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
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query('UPDATE messages SET from_user=$1 WHERE from_user=$2', [nu, req.username]);
          await client.query('UPDATE messages SET to_user=$1   WHERE to_user=$2', [nu, req.username]);
          await client.query('UPDATE messages SET from_dn=$1  WHERE from_user=$2', [dn, nu]);
          await client.query('UPDATE sessions  SET username=$1 WHERE username=$2', [nu, req.username]);
          const rows = await client.query('SELECT DISTINCT chat_key FROM messages WHERE from_user=$1 OR to_user=$1', [nu]);
          for (const row of rows.rows) {
            const nk = row.chat_key.split(':').map(p => p === req.username ? nu : p).sort().join(':');
            if (nk !== row.chat_key) await client.query('UPDATE messages SET chat_key=$1 WHERE chat_key=$2', [nk, row.chat_key]);
          }
          await client.query('UPDATE chat_members SET username=$1 WHERE username=$2', [nu, req.username]);
          await client.query('UPDATE chat_hidden SET username=$1 WHERE username=$2', [nu, req.username]);
          await client.query('UPDATE chat_archived SET username=$1 WHERE username=$2', [nu, req.username]);
          await client.query('UPDATE blocked SET username=$1 WHERE username=$2', [nu, req.username]);
          await client.query('UPDATE blocked SET blocked_username=$1 WHERE blocked_username=$2', [nu, req.username]);
          await client.query('UPDATE push_subscriptions SET username=$1 WHERE username=$2', [nu, req.username]);
          await client.query('UPDATE users SET username=$1,displayname=$2,bio=$3,avatar=$4 WHERE username=$5',
            [nu, dn, sanitize((bio || '').slice(0, 200)), avatar || null, req.username]);
          await client.query('COMMIT');
          finalUsername = nu;
        } catch (e) {
          await client.query('ROLLBACK');
          throw e;
        } finally {
          client.release();
        }
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
    const { to, chat, text, type, fileName, fileSize, replyTo } = req.body;
    const allowedTypes = ['text', 'image', 'video', 'file', 'sticker', 'voice', 'poll'];
    const msgType = allowedTypes.includes(type) ? type : 'text';
    if (msgType === 'text' && !text?.trim()) return err(res, 'Неверные данные');
    if (msgType !== 'text' && !text) return err(res, 'Неверные данные');
    if (!to && !chat) return err(res, 'Неверные данные');
    if (msgType !== 'text' && msgType !== 'poll' && text.length > 22 * 1024 * 1024) return err(res, 'Файл слишком большой', 400);
    if ((msgType === 'text' || msgType === 'poll') && (text || '').length > 10000) return err(res, 'Сообщение слишком длинное', 400);

    const isGroup = !!chat;
    let key, recipient;
    if (isGroup) {
      // Group chat
      const g = await pool.query('SELECT id FROM chats WHERE id=$1 AND type=$2', [sanitize(chat), 'group']);
      if (!g.rows.length) return err(res, 'Группа не найдена', 404);
      const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND username=$2', [chat, req.username]);
      if (!mem.rows.length) return err(res, 'Вы не участник группы', 403);
      key = groupKey(chat);
      recipient = chat;
    } else {
      // Private chat
      const blk = await pool.query('SELECT 1 FROM blocked WHERE username=$1 AND blocked=$2', [to, req.username]);
      if (blk.rows.length) return err(res, 'Пользователь заблокировал вас', 403);
      key = chatKey(req.username, to);
      recipient = to;
    }

    const ur = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    if (!ur.rows.length) return err(res, 'Пользователь не найден', 404);
    const dn = ur.rows[0].displayname;
    const ts = Date.now();
    const storeText = msgType === 'text' ? sanitize(text.trim()) : typeof text === 'string' ? sanitize(text) : text;

    let replyToId = null, replyPreview = null;
    const rpId = parseInt(replyTo || 0);
    if (rpId) {
      const rr = await pool.query('SELECT id, text, type, from_dn, from_user FROM messages WHERE id=$1 AND chat_key=$2', [rpId, key]);
      if (rr.rows.length) {
        replyToId = rpId;
        const rm = rr.rows[0];
        const pv = typeLabel(rm.type) || sanitize((rm.text || '').slice(0, 80));
        replyPreview = JSON.stringify({ from: rm.from_dn || rm.from_user, text: pv });
      }
    }

    const r = await pool.query(
      'INSERT INTO messages (chat_key,from_user,from_dn,to_user,text,type,ts,file_name,file_size,reply_to,reply_preview) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,ts',
      [key, req.username, dn, recipient, storeText, msgType, ts, fileName || null, fileSize || 0, replyToId, replyPreview]
    );
    const msgRow = r.rows[0];
    // Broadcast
    const payload = {
      type: 'message',
      id: parseInt(msgRow.id),
      chatKey: key,
      from: req.username,
      displayname: dn,
      text: (msgType === 'text' || msgType === 'sticker' || msgType === 'poll') ? storeText : null,
      msgType,
      ts: parseInt(msgRow.ts),
      fileName: fileName || null,
      fileSize: fileSize || 0,
      replyTo: replyToId,
      replyPreview
    };
    if (isGroup) {
      // Broadcast to all group members
      const allMem = await pool.query('SELECT username FROM chat_members WHERE chat_id=$1', [chat]);
      for (const m of allMem.rows) wsBroadcast(m.username, payload);
      // Push for offline members
      for (const m of allMem.rows) {
        if (m.username !== req.username && (!wsClients.has(m.username) || ![...(wsClients.get(m.username) || [])].some(s => s.readyState === 1))) {
          sendPushNotification(m.username, {
            type: 'new_message', chatKey: key, from: req.username, displayname: dn,
            text: msgType === 'sticker' ? '🎨 Стикер' : msgType === 'voice' ? '🎤 Голосовое' : msgType === 'image' ? '📷 Фото' : msgType === 'file' ? '📎 Файл' : (text || '').slice(0, 100),
            msgType, id: parseInt(msgRow.id), ts: parseInt(msgRow.ts)
          });
        }
      }
    } else {
      wsPushToChat(key, '', payload).catch(() => {});
    }
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
    // Check access for both private and group chats
    if (isGroupChat(key)) {
      const gid = groupIdFromKey(key);
      const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND username=$2', [gid, req.username]);
      if (!mem.rows.length) return err(res, 'Нет прав', 403);
    } else {
      const parts = key.split(':');
      if (!parts.includes(req.username)) return err(res, 'Нет прав', 403);
    }
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
    wsPushToChat(key, req.username, { type: 'reaction', id: parseInt(id), reactions }).catch(() => {});
    ok(res, { ok: true, reactions });
  } catch (e) { err(res, e.message, 500); }
});

// MARK AS READ
app.post('/api/read', auth, async (req, res) => {
  try {
    const { other, chat } = req.body;
    let key;
    if (chat) {
      key = groupKey(sanitize(chat));
    } else if (other) {
      key = chatKey(req.username, other);
    } else {
      return err(res, 'Нужен other или chat');
    }
    const now = Date.now();
    const upd = await pool.query(
      `UPDATE messages SET read_at=$1 WHERE chat_key=$2 AND from_user!=$3 AND NOT deleted AND read_at=0 RETURNING id`,
      [now, key, req.username]
    );
    // Batch push read updates via WS
    if (upd.rows.length > 0) {
      const ids = upd.rows.map(r => r.id);
      if (chat) {
        // Group chat: get all members once, send batch to all
        const allMem = await pool.query('SELECT username FROM chat_members WHERE chat_id=$1', [sanitize(chat)]);
        for (const m of allMem.rows) {
          wsBroadcast(m.username, { type: 'read_batch', ids, read_at: now });
        }
      } else {
        // Private chat: send batch to other user
        wsBroadcast(other, { type: 'read_batch', ids, read_at: now });
      }
    }
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// DELETE MESSAGE
app.delete('/api/message/:id', auth, async (req, res) => {
  try {
    const everyone = req.query.everyone === 'true';
    const r = await pool.query('SELECT from_user, chat_key FROM messages WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    if (r.rows[0].from_user !== req.username) return err(res, 'Нет прав', 403);
    const key = r.rows[0].chat_key;
    if (everyone) {
      await pool.query('DELETE FROM messages WHERE id=$1', [req.params.id]);
      wsPushToChat(key, req.username, { type: 'delete', id: parseInt(req.params.id), everyone: true }).catch(() => {});
    } else {
      await pool.query('UPDATE messages SET deleted=TRUE,text=$1 WHERE id=$2', ['Сообщение удалено', req.params.id]);
      wsPushToChat(key, req.username, { type: 'delete', id: parseInt(req.params.id), everyone: false }).catch(() => {});
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
    wsPushToChat(key, req.username, { type: 'edit', id: parseInt(req.params.id), text: newText }).catch(() => {});
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// DELETE CHAT
app.delete('/api/chat/:other', auth, async (req, res) => {
  try {
    const key = chatKey(req.username, req.params.other);
    const everyone = req.query.everyone === 'true';
    if (everyone) {
      await pool.query('DELETE FROM messages WHERE chat_key=$1', [key]);
      await pool.query('DELETE FROM chat_hidden WHERE chat_key=$1', [key]);
    } else {
      await pool.query('INSERT INTO chat_hidden (username,chat_key,hidden_at) VALUES ($1,$2,$3) ON CONFLICT (username,chat_key) DO UPDATE SET hidden_at=EXCLUDED.hidden_at', [req.username, key, Date.now()]);
    }
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// FORWARD MESSAGE
app.post('/api/forward', auth, async (req, res) => {
  try {
    const { id, to, chat } = req.body;
    if (!id) return err(res, 'Нужен id сообщения');
    const msg = await pool.query('SELECT * FROM messages WHERE id=$1 AND NOT deleted', [id]);
    if (!msg.rows.length) return err(res, 'Сообщение не найдено', 404);
    const m = msg.rows[0];
    // Check access to source message
    if (isGroupChat(m.chat_key)) {
      const gid = groupIdFromKey(m.chat_key);
      const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND username=$2', [gid, req.username]);
      if (!mem.rows.length) return err(res, 'Нет доступа', 403);
    } else {
      const parts = m.chat_key.split(':');
      if (!parts.includes(req.username)) return err(res, 'Нет доступа', 403);
    }
    // Determine destination
    let destKey;
    if (chat) {
      const g = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND username=$2', [sanitize(chat), req.username]);
      if (!g.rows.length) return err(res, 'Нет доступа к группе', 403);
      destKey = groupKey(sanitize(chat));
    } else if (to) {
      destKey = chatKey(req.username, to);
    } else {
      return err(res, 'Нужен to или chat');
    }
    const ts = Date.now();
    const ur = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    const dn = ur.rows[0].displayname;
    const fwdPrefix = '↪ ' + (m.from_dn || m.from_user) + ': ';
    const fwdText = m.type === 'text' ? fwdPrefix + (m.text || '') : m.text;
    const r = await pool.query(
      'INSERT INTO messages (chat_key,from_user,from_dn,to_user,text,type,ts,file_name,file_size) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,ts',
      [destKey, req.username, dn, to || chat || '', fwdText, m.type, ts, m.file_name || null, m.file_size || 0]
    );
    const newMsg = r.rows[0];
    const payload = {
      type: 'message',
      id: parseInt(newMsg.id),
      chatKey: destKey,
      from: req.username,
      displayname: dn,
      text: m.type === 'text' ? fwdText : null,
      msgType: m.type,
      ts: parseInt(newMsg.ts),
      fileName: m.file_name || null,
      fileSize: m.file_size || 0,
      isForward: true
    };
    wsPushToChat(destKey, '', payload).catch(() => {});
    ok(res, { ok: true, id: parseInt(newMsg.id) });
  } catch (e) { err(res, e.message, 500); }
});

// PIN / UNPIN
app.post('/api/pin/:id', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT chat_key FROM messages WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return err(res, 'Не найдено', 404);
    const key = r.rows[0].chat_key;
    // Check access for both private and group chats
    if (isGroupChat(key)) {
      const gid = groupIdFromKey(key);
      const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND username=$2', [gid, req.username]);
      if (!mem.rows.length) return err(res, 'Нет прав', 403);
    } else {
      const parts = key.split(':');
      if (!parts.includes(req.username)) return err(res, 'Нет прав', 403);
    }
    const m = await pool.query('SELECT pinned, from_user, to_user FROM messages WHERE id=$1', [req.params.id]);
    const wasPinned = m.rows[0].pinned;
    if (!wasPinned) {
      await pool.query('UPDATE messages SET pinned=FALSE WHERE chat_key=$1 AND pinned=TRUE', [r.rows[0].chat_key]);
    }
    await pool.query('UPDATE messages SET pinned=$1 WHERE id=$2', [!wasPinned, req.params.id]);
    const newPinned = !wasPinned;
    wsPushToChat(r.rows[0].chat_key, req.username, { type: 'pin', id: parseInt(req.params.id), pinned: newPinned }).catch(() => {});
    ok(res, { ok: true, pinned: newPinned });
  } catch (e) { err(res, e.message, 500); }
});

// ── Typing indicator (in-memory) ──
const typingMap = new Map();
const groupMembersCache = new Map(); // chatId → [usernames]
const pollTs = new Map();                 // deduplication for poll endpoint

app.post('/api/typing', auth, async (req, res) => {
  try {
    const { to, chat } = req.body;
    let key;
    if (chat) {
      key = groupKey(sanitize(chat));
    } else if (to) {
      key = chatKey(req.username, to);
    } else {
      return err(res, 'Нужен to или chat');
    }
    typingMap.set(key, { username: req.username, ts: Date.now() });
    if (chat) {
      // Use cache for group members
      const chatId = sanitize(chat);
      if (!groupMembersCache.has(chatId)) {
        const allMem = await pool.query('SELECT username FROM chat_members WHERE chat_id=$1', [chatId]);
        groupMembersCache.set(chatId, allMem.rows.map(m => m.username));
      }
      const members = groupMembersCache.get(chatId);
      for (const m of members) {
        if (m !== req.username) wsBroadcast(m, { type: 'typing', from: req.username, chatKey: key });
      }
    } else {
      wsBroadcast(to, { type: 'typing', from: req.username, chatKey: key });
    }
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});
app.get('/api/typing', auth, async (req, res) => {
  try {
    const { b, chat } = req.query;
    let key;
    if (chat) {
      key = groupKey(sanitize(chat));
    } else if (b) {
      key = chatKey(req.username, b);
    } else {
      return ok(res, { typing: false });
    }
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
    const { b, chat, since, before } = req.query;
    let key;
    if (chat) {
      const g = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND username=$2', [sanitize(chat), req.username]);
      if (!g.rows.length) return err(res, 'Нет доступа к группе', 403);
      key = groupKey(sanitize(chat));
    } else if (b) {
      key = chatKey(req.username, b);
    } else {
      return err(res, 'Нужен b или chat');
    }
    const sinceTs = Math.max(0, parseInt(since) || 0);
    const beforeTs = Math.max(0, parseInt(before) || 0);
    const hid = await pool.query(
      'SELECT hidden_at FROM chat_hidden WHERE username=$1 AND chat_key=$2',
      [req.username, key]
    );
    const hiddenAt = hid.rows.length ? Math.max(0, parseInt(hid.rows[0].hidden_at) || 0) : 0;
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
         FROM messages WHERE chat_key=$1 AND ts>$2 AND ts>$3 AND NOT deleted ORDER BY ts ASC LIMIT 100`,
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
    const key = r.rows[0].chat_key;
    // Check access for both private and group chats
    if (isGroupChat(key)) {
      const gid = groupIdFromKey(key);
      const mem = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND username=$2', [gid, req.username]);
      if (!mem.rows.length) return err(res, 'Нет прав', 403);
    } else {
      const parts = key.split(':');
      if (!parts.includes(req.username)) return err(res, 'Нет прав', 403);
    }
    ok(res, { id: r.rows[0].id, text: r.rows[0].text, type: r.rows[0].type });
  } catch (e) { err(res, e.message, 500); }
});

// POLL
app.get('/api/poll', auth, async (req, res) => {
  try {
    const { b, chat, since } = req.query;
    let key;
    if (chat) {
      key = groupKey(sanitize(chat));
    } else if (b) {
      key = chatKey(req.username, b);
    } else {
      return ok(res, { messages: [], readUpdates: [], reactionUpdates: [] });
    }
    const sinceTs = parseInt(since || '0');

    // Track last poll ts to avoid repeat read/reaction queries
    const pollKey = `${req.username}:${key}`;
    const lastPoll = pollTs.get(pollKey) || 0;
    pollTs.set(pollKey, Date.now());

    // New messages
    const newMsgs = await pool.query(
      `SELECT id, from_user as "from", from_dn as displayname,
              text,
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
    const chats = [];
    const seen = new Set();

    // ── Private chats ──
    const result = await pool.query(`
      SELECT m.chat_key,
        CASE WHEN m.from_user=$1 THEN m.to_user ELSE m.from_user END AS other_username,
        m.text AS last_message, m.type AS last_type, m.ts AS last_ts, m.deleted, m.from_user AS last_from
      FROM messages m
      LEFT JOIN chat_hidden hc ON hc.username=$1 AND hc.chat_key=m.chat_key
      INNER JOIN (
        SELECT chat_key, MAX(ts) AS max_ts
        FROM messages
        WHERE (from_user=$1 OR to_user=$1) AND chat_key NOT LIKE 'group:%'
        GROUP BY chat_key
      ) latest ON m.chat_key = latest.chat_key AND m.ts = latest.max_ts
      WHERE (m.from_user=$1 OR m.to_user=$1) AND m.chat_key NOT LIKE 'group:%'
        AND (hc.hidden_at IS NULL OR m.ts > hc.hidden_at)
      ORDER BY m.ts DESC
    `, [req.username]);

    const unreadR = await pool.query(`
      SELECT from_user, COUNT(*) as cnt FROM messages
      WHERE to_user=$1 AND NOT deleted AND read_at=0 AND chat_key NOT LIKE 'group:%'
      GROUP BY from_user
    `, [req.username]);
    const unreadMap = {};
    for (const r of unreadR.rows) unreadMap[r.from_user] = parseInt(r.cnt);

    const others = [...new Set(result.rows.map(r => r.other_username).filter(Boolean))];
    let usersMap = {};
    let lastSeenMap = {};
    if (others.length) {
      const ph = others.map((_, i) => `$${i + 1}`).join(',');
      const ur = await pool.query(`
        SELECT u.username, u.displayname, u.avatar, MAX(s.last_seen) as last_seen
        FROM users u LEFT JOIN sessions s ON s.username = u.username
        WHERE u.username IN (${ph})
        GROUP BY u.username, u.displayname, u.avatar
      `, others);
      for (const u of ur.rows) {
        usersMap[u.username] = u;
        lastSeenMap[u.username] = parseInt(u.last_seen || 0);
      }
    }

    for (const row of result.rows) {
      const other = row.other_username;
      if (!other || seen.has(other)) continue;
      seen.add(other);
      const u = usersMap[other] || {};
      let preview = row.deleted ? 'Удалено' : row.last_message;
      if (!row.deleted) {
        const tl = typeLabel(row.last_type);
        if (tl) preview = tl;
        else if (row.last_type === 'system') preview = row.last_message;
        else if (row.last_from && row.last_from === req.username) preview = 'Вы: ' + (preview || '');
        else if (preview && preview.length > 40) preview = preview.slice(0, 40) + '…';
      }
      chats.push({
        chatKey: row.chat_key,
        otherUsername: other,
        otherDisplayname: u.displayname || other,
        otherAvatar: u.avatar || null,
        lastMessage: preview,
        lastTs: parseInt(row.last_ts),
        unread: unreadMap[other] || 0,
        lastSeen: lastSeenMap[other] || 0,
        isGroup: false
      });
    }

    // ── Group chats ──
    const groupsR = await pool.query(
      `SELECT g.chat_id, g.name, g.avatar, g.created_at,
              m.text as last_text, m.type as last_type, m.ts as last_ts, m.from_dn as last_from_dn, m.deleted as last_deleted,
              (SELECT COUNT(*) FROM messages WHERE chat_key='group:' || g.chat_id AND NOT deleted AND read_at=0 AND from_user!=$2) as unread
       FROM chat_members cm
       JOIN chats g ON cm.chat_id=g.id
       LEFT JOIN LATERAL (
         SELECT text, type, ts, from_dn, deleted FROM messages WHERE chat_key='group:' || g.chat_id ORDER BY ts DESC LIMIT 1
       ) m ON true
       WHERE cm.username=$1
       ORDER BY COALESCE(m.ts, g.created_at) DESC`,
      [req.username, req.username]
    );
    for (const g of groupsR.rows) {
      const gKey = groupKey(g.chat_id);
      if (seen.has(gKey)) continue;
      seen.add(gKey);
      let lastMessage = '';
      let lastTs = parseInt(g.created_at);
      let lastType = 'text';
      if (g.last_ts) {
        lastTs = parseInt(g.last_ts);
        lastType = g.last_type || 'text';
        if (g.last_deleted) lastMessage = 'Удалено';
        else {
          const tl = typeLabel(lastType);
          if (tl) lastMessage = tl;
          else if (lastType === 'system') lastMessage = g.last_text;
          else {
            const dn = g.last_from_dn || '';
            lastMessage = dn ? `${dn}: ${g.last_text.slice(0, 40)}` : g.last_text.slice(0, 40);
          }
        }
      }
      chats.push({
        chatKey: gKey,
        groupId: g.chat_id,
        otherUsername: g.chat_id,
        otherDisplayname: g.name,
        otherAvatar: g.avatar || null,
        lastMessage,
        lastTs,
        unread: parseInt(g.unread) || 0,
        lastSeen: 0,
        isGroup: true
      });
    }

    chats.sort((a, b) => b.lastTs - a.lastTs);
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
app.get('/api/admin/check', auth, (req, res) => {
  ok(res, { isOwner: req.username === OWNER, owner: OWNER });
});
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
    await pool.query('DELETE FROM chat_members WHERE username=$1', [u]);
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
    const [users, msgs, sess, today, prem] = await Promise.all([
      pool.query('SELECT COUNT(*) as c FROM users'),
      pool.query('SELECT COUNT(*) as c FROM messages'),
      pool.query('SELECT COUNT(*) as c FROM sessions'),
      pool.query('SELECT COUNT(*) as c FROM messages WHERE ts > $1', [Date.now() - 86400000]),
      pool.query('SELECT COUNT(*) as c FROM users WHERE is_premium=true')
    ]);
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
app.post('/api/admin/broadcast', auth, adminOnly, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || typeof text !== 'string') return err(res, 'Текст обязателен', 400);
    const users = await pool.query('SELECT username FROM users');
    const msg = { type: 'admin_broadcast', text: sanitize(text) };
    for (const row of users.rows) {
      wsBroadcast(row.username, msg);
    }
    ok(res, { ok: true, sent: users.rows.length });
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

// ── Groups ──
function genId() { return crypto.randomBytes(12).toString('base64url'); }

function isGroupChat(key) { return key && key.startsWith('group:'); }
function groupIdFromKey(key) { return key ? key.replace('group:', '') : null; }
function groupKey(id) { return 'group:' + id; }

// Create group
app.post('/api/groups', auth, async (req, res) => {
  try {
    let { name, members } = req.body;
    name = sanitize((name || '').trim());
    if (!name || name.length < 1 || name.length > 100) return err(res, 'Название обязательно (1-100 символов)');
    if (!members || !Array.isArray(members) || !members.length) return err(res, 'Добавьте хотя бы одного участника');
    const allMembers = [...new Set([req.username, ...members.map(m => (m || '').toLowerCase().trim()).filter(Boolean)])];
    if (allMembers.length < 2) return err(res, 'Минимум 2 участника');
    if (allMembers.length > 200) return err(res, 'Максимум 200 участников');

    const ph = allMembers.map((_, i) => `$${i + 1}`).join(',');
    const ur = await pool.query(`SELECT username FROM users WHERE username IN (${ph})`, allMembers);
    const found = new Set(ur.rows.map(r => r.username));
    const missing = allMembers.filter(u => !found.has(u));
    if (missing.length) return err(res, `Пользователи не найдены: ${missing.join(', ')}`, 404);

    const id = genId();
    const ts = Date.now();
    await pool.query('INSERT INTO chats (id,type,name,creator,created_at) VALUES ($1,$2,$3,$4,$5)', [id, 'group', name, req.username, ts]);
    const vals = [], params = [id, ts];
    for (const u of allMembers) {
      vals.push(`($1,$${params.length + 1},$${params.length + 2},$2)`);
      params.push(u, u === req.username ? 'owner' : 'member');
    }
    await pool.query(`INSERT INTO chat_members (chat_id,username,role,joined_at) VALUES ${vals.join(',')}`, params);
    // Send system message
    const dnR = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    const creatorDn = dnR.rows[0]?.displayname || req.username;
    const sysMsg = `${creatorDn} создал(а) группу «${name}»`;
    const key = groupKey(id);
    const isR = await pool.query(
      "INSERT INTO messages (chat_key,from_user,from_dn,to_user,text,type,ts) VALUES ($1,$2,$3,$4,$5,'system',$6) RETURNING id,ts",
      [key, req.username, creatorDn, id, sysMsg, ts]
    );
    // Notify all members via WS
    const msgRow = isR.rows[0];
    const payload = {
      type: 'group_created',
      chatKey: key,
      groupId: id,
      name,
      creator: req.username,
      from: req.username,
      displayname: creatorDn,
      text: sysMsg,
      msgType: 'system',
      id: parseInt(msgRow.id),
      ts: parseInt(msgRow.ts),
      members: allMembers
    };
    for (const u of allMembers) wsBroadcast(u, payload);
    // Also create 1-on-1 chats with the group as virtual entity (so it appears in chat list)
    ok(res, { ok: true, group: { id, name, type: 'group', creator: req.username, created_at: ts }, chatKey: key });
  } catch (e) { err(res, e.message, 500); }
});

// Get group info
app.get('/api/groups/:id', auth, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const g = await pool.query('SELECT * FROM chats WHERE id=$1', [id]);
    if (!g.rows.length) return err(res, 'Группа не найдена', 404);
    const mem = await pool.query('SELECT cm.username, cm.role, cm.joined_at, u.displayname, u.avatar FROM chat_members cm JOIN users u ON cm.username=u.username WHERE cm.chat_id=$1 ORDER BY cm.role ASC, cm.username ASC', [id]);
    const isMember = mem.rows.some(r => r.username === req.username);
    if (!isMember) return err(res, 'Вы не участник', 403);
    ok(res, {
      group: { ...g.rows[0], created_at: parseInt(g.rows[0].created_at) },
      members: mem.rows.map(m => ({ username: m.username, role: m.role, joined_at: parseInt(m.joined_at), displayname: m.displayname, avatar: m.avatar }))
    });
  } catch (e) { err(res, e.message, 500); }
});

// Update group
app.put('/api/groups/:id', auth, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const roleR = await pool.query('SELECT role FROM chat_members WHERE chat_id=$1 AND username=$2', [id, req.username]);
    if (!roleR.rows.length) return err(res, 'Вы не участник', 403);
    if (roleR.rows[0].role === 'member') return err(res, 'Нет прав', 403);
    const { name, description } = req.body;
    const updates = [];
    const vals = [];
    let idx = 1;
    if (name !== undefined) {
      const n = sanitize((name || '').trim());
      if (!n || n.length > 100) return err(res, 'Название 1-100 символов');
      updates.push(`name=$${idx++}`); vals.push(n);
    }
    if (description !== undefined) {
      updates.push(`description=$${idx++}`); vals.push(sanitize((description || '').slice(0, 500)));
    }
    if (!updates.length) return err(res, 'Нечего обновлять');
    vals.push(id);
    await pool.query(`UPDATE chats SET ${updates.join(',')} WHERE id=$${idx}`, vals);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// Add members to group
app.post('/api/groups/:id/members', auth, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const roleR = await pool.query('SELECT role FROM chat_members WHERE chat_id=$1 AND username=$2', [id, req.username]);
    if (!roleR.rows.length) return err(res, 'Вы не участник', 403);
    if (roleR.rows[0].role === 'member') return err(res, 'Нет прав', 403);
    let { members } = req.body;
    if (!members || !Array.isArray(members) || !members.length) return err(res, 'Нужен список участников');
    members = members.map(m => (m || '').toLowerCase().trim()).filter(Boolean);
    const ph = members.map((_, i) => `$${i + 1}`).join(',');
    const ur = await pool.query(`SELECT username FROM users WHERE username IN (${ph})`, members);
    const found = new Set(ur.rows.map(r => r.username));
    const missing = members.filter(u => !found.has(u));
    if (missing.length) return err(res, `Не найдены: ${missing.join(', ')}`, 404);
    const ex = await pool.query(`SELECT username FROM chat_members WHERE chat_id=$1 AND username = ANY($2)`, [id, members]);
    const alreadyIn = new Set(ex.rows.map(r => r.username));
    const toAdd = members.filter(u => !alreadyIn.has(u));
    if (!toAdd.length) return err(res, 'Все уже в группе');
    const ts = Date.now();
    const dnR = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    const adderDn = dnR.rows[0]?.displayname || req.username;
    for (const u of toAdd) {
      await pool.query('INSERT INTO chat_members (chat_id,username,role,joined_at) VALUES ($1,$2,$3,$4)', [id, u, 'member', ts]);
    }
    const key = groupKey(id);
    const names = toAdd.join(', ');
    const sysMsg = `${adderDn} добавил(а) ${names}`;
    const isR = await pool.query(
      "INSERT INTO messages (chat_key,from_user,from_dn,to_user,text,type,ts) VALUES ($1,$2,$3,$4,$5,'system',$6) RETURNING id,ts",
      [key, req.username, adderDn, id, sysMsg, ts]
    );
    const payload = { type: 'members_added', chatKey: key, groupId: id, members: toAdd, adder: req.username, id: parseInt(isR.rows[0].id), ts: parseInt(isR.rows[0].ts) };
    const allMem = await pool.query('SELECT username FROM chat_members WHERE chat_id=$1', [id]);
    for (const m of allMem.rows) wsBroadcast(m.username, payload);
    groupMembersCache.delete(id); // Invalidate cache
    ok(res, { ok: true, added: toAdd });
  } catch (e) { err(res, e.message, 500); }
});

// Remove member / leave group
app.delete('/api/groups/:id/members/:username', auth, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const target = sanitize(req.params.username);
    const roleR = await pool.query('SELECT role FROM chat_members WHERE chat_id=$1 AND username=$2', [id, req.username]);
    if (!roleR.rows.length) return err(res, 'Вы не участник', 403);
    const isSelf = target === req.username;
    if (!isSelf && roleR.rows[0].role === 'member') return err(res, 'Нет прав', 403);
    const targetRole = await pool.query('SELECT role FROM chat_members WHERE chat_id=$1 AND username=$2', [id, target]);
    if (!targetRole.rows.length) return err(res, 'Участник не в группе', 404);
    if (!isSelf && targetRole.rows[0].role === 'owner') return err(res, 'Нельзя удалить создателя', 403);
    await pool.query('DELETE FROM chat_members WHERE chat_id=$1 AND username=$2', [id, target]);
    const dnR = await pool.query('SELECT displayname FROM users WHERE username=$1', [target]);
    const targetDn = dnR.rows[0]?.displayname || target;
    const key = groupKey(id);
    let actorDn = req.username;
    if (!isSelf) { const adn = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]); actorDn = adn.rows[0]?.displayname || req.username; }
    const finalMsg = isSelf ? `${targetDn} покинул(а) группу` : `${actorDn} удалил(а) ${targetDn}`;
    const ts = Date.now();
    const isR = await pool.query(
      "INSERT INTO messages (chat_key,from_user,from_dn,to_user,text,type,ts) VALUES ($1,$2,$3,$4,$5,'system',$6) RETURNING id,ts",
      [key, req.username, actorDn, id, finalMsg, ts]
    );
    const allMem = await pool.query('SELECT username FROM chat_members WHERE chat_id=$1', [id]);
    const payload = { type: 'member_removed', chatKey: key, groupId: id, removed: target, actor: req.username, isSelf, id: parseInt(isR.rows[0].id), ts: parseInt(isR.rows[0].ts) };
    for (const m of [...allMem.rows, { username: target }]) wsBroadcast(m.username, payload);
    groupMembersCache.delete(id); // Invalidate cache
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// Change member role
app.put('/api/groups/:id/members/:username', auth, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const target = sanitize(req.params.username);
    const { role } = req.body;
    if (!['admin', 'member'].includes(role)) return err(res, 'Роль: admin или member');
    const myRole = await pool.query('SELECT role FROM chat_members WHERE chat_id=$1 AND username=$2', [id, req.username]);
    if (!myRole.rows.length || myRole.rows[0].role !== 'owner') return err(res, 'Только создатель может менять роли', 403);
    if (target === req.username) return err(res, 'Нельзя изменить свою роль');
    const targetExists = await pool.query('SELECT role FROM chat_members WHERE chat_id=$1 AND username=$2', [id, target]);
    if (!targetExists.rows.length) return err(res, 'Участник не в группе', 404);
    await pool.query('UPDATE chat_members SET role=$1 WHERE chat_id=$2 AND username=$3', [role, id, target]);
    const key = groupKey(id);
    const allMem = await pool.query('SELECT username FROM chat_members WHERE chat_id=$1', [id]);
    const payload = { type: 'role_changed', chatKey: key, groupId: id, username: target, role };
    for (const m of allMem.rows) wsBroadcast(m.username, payload);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// ── Vote on poll ──
app.post('/api/vote', auth, async (req, res) => {
  try {
    const { id, option } = req.body;
    if (id === undefined || option === undefined) return err(res, 'Нужен id и option');
    // Use transaction with row lock to prevent race conditions
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const msg = await client.query('SELECT text, chat_key FROM messages WHERE id=$1 AND type=$2 AND NOT deleted FOR UPDATE', [id, 'poll']);
      if (!msg.rows.length) { await client.query('ROLLBACK'); client.release(); return err(res, 'Опрос не найден', 404); }
      let poll = { question: '', options: [], votes: [], multiple: false };
      try { poll = JSON.parse(msg.rows[0].text); } catch (e) { await client.query('ROLLBACK'); client.release(); return err(res, 'Повреждённый опрос'); }
      if (option < 0 || option >= poll.options.length) { await client.query('ROLLBACK'); client.release(); return err(res, 'Некорректная опция'); }
      if (!poll.multiple) {
        for (const v of (poll.votes || [])) {
          if (v.users) v.users = v.users.filter(u => u !== req.username);
        }
      }
      if (!poll.votes) poll.votes = [];
      if (!poll.votes[option]) poll.votes[option] = { option, users: [] };
      if (!poll.votes[option].users) poll.votes[option].users = [];
      const idx = poll.votes[option].users.indexOf(req.username);
      if (idx >= 0) {
        poll.votes[option].users.splice(idx, 1);
      } else {
        poll.votes[option].users.push(req.username);
      }
      await client.query('UPDATE messages SET text=$1 WHERE id=$2', [JSON.stringify(poll), id]);
      await client.query('COMMIT');
      client.release();
      wsPushToChat(msg.rows[0].chat_key, req.username, { type: 'vote_update', id, poll }).catch(() => {});
      ok(res, { ok: true, poll });
    } catch (e) { await client.query('ROLLBACK'); client.release(); throw e; }
  } catch (e) { err(res, e.message, 500); }
});

// ── Archived chats ──

app.get('/api/archived', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT chat_key FROM chat_archived WHERE username=$1', [req.username]);
    ok(res, { archived: r.rows.map(row => row.chat_key) });
  } catch (e) { err(res, e.message, 500); }
});

app.post('/api/archive/:chatKey', auth, async (req, res) => {
  try {
    const ck = decodeURIComponent(req.params.chatKey);
    await pool.query('INSERT INTO chat_archived (username, chat_key) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.username, ck]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

app.delete('/api/archive/:chatKey', auth, async (req, res) => {
  try {
    const ck = decodeURIComponent(req.params.chatKey);
    await pool.query('DELETE FROM chat_archived WHERE username=$1 AND chat_key=$2', [req.username, ck]);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

// ── Leave group ──
app.post('/api/groups/:id/leave', auth, async (req, res) => {
  try {
    const id = sanitize(req.params.id);
    const mem = await pool.query('SELECT role FROM chat_members WHERE chat_id=$1 AND username=$2', [id, req.username]);
    if (!mem.rows.length) return err(res, 'Вы не участник', 404);
    if (mem.rows[0].role === 'owner') return err(res, 'Создатель не может покинуть группу. Сначала передайте права.', 403);
    await pool.query('DELETE FROM chat_members WHERE chat_id=$1 AND username=$2', [id, req.username]);
    groupMembersCache.delete(id);
    const dnR = await pool.query('SELECT displayname FROM users WHERE username=$1', [req.username]);
    const dn = dnR.rows[0]?.displayname || req.username;
    const key = groupKey(id);
    const ts = Date.now();
    const isR = await pool.query(
      "INSERT INTO messages (chat_key,from_user,from_dn,to_user,text,type,ts) VALUES ($1,$2,$3,$4,$5,'system',$6) RETURNING id,ts",
      [key, req.username, dn, id, `${dn} покинул(а) группу`, ts]
    );
    const allMem = await pool.query('SELECT username FROM chat_members WHERE chat_id=$1', [id]);
    const payload = { type: 'member_removed', chatKey: key, groupId: id, removed: req.username, actor: req.username, isSelf: true, id: parseInt(isR.rows[0].id), ts: parseInt(isR.rows[0].ts) };
    for (const m of [...allMem.rows, { username: req.username }]) wsBroadcast(m.username, payload);
    ok(res, { ok: true });
  } catch (e) { err(res, e.message, 500); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
_initPromise.then(() => {
  server.listen(PORT, () => console.log(`Wavr on port ${PORT}`));
}).catch(e => {
  console.error('FATAL: DB init failed, exiting', e);
  process.exit(1);
});
