const CACHE = 'wavr-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icon.svg'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
  );
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});

// ── Push notifications ──
self.addEventListener('push', e => {
  let data;
  try {
    data = e.data ? JSON.parse(e.data.text()) : {};
  } catch (err) {
    data = {};
  }
  if (!data || !data.type) return;

  const title = data.displayname || data.from || 'Wavr';
  let body = data.text || '';
  if (data.msgType === 'image') body = '📷 Фото';
  else if (data.msgType === 'video') body = '🎬 Видео';
  else if (data.msgType === 'file') body = '📎 Файл';
  else if (data.msgType === 'sticker') body = '🎨 Стикер';

  const options = {
    body,
    icon: '/icon.svg',
    badge: '/icon.svg',
    vibrate: [100, 50, 100],
    data: {
      chatKey: data.chatKey,
      messageId: data.id,
      ts: data.ts
    }
  };

  e.waitUntil(
    self.registration.showNotification(title, options)
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const d = e.notification.data || {};
  const chatKey = d.chatKey;
  if (chatKey) {
    const url = '/?chat=' + encodeURIComponent(chatKey);
    e.waitUntil(
      clients.matchAll({ type: 'window' }).then(clientList => {
        for (const client of clientList) {
          if (client.url.includes(location.origin) && 'focus' in client) {
            client.postMessage({ type: 'navigate', chatKey });
            return client.focus();
          }
        }
        if (clients.openWindow) return clients.openWindow(url);
      })
    );
  }
});
