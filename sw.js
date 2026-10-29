// Avio.AI service worker: case-email notifications only (no caching, no fetch handling).
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = { body: e.data && e.data.text() }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Avio.AI', {
    body: d.body || 'New case email', tag: d.id || undefined, data: { id: d.id || '' }, icon: 'icon-192.png', badge: 'icon-192.png'
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const id = (e.notification.data && e.notification.data.id) || '';
  const url = new URL('./?inbox=' + encodeURIComponent(id), self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) { if ('focus' in c) { c.postMessage({ inbox: id }); return c.focus(); } }
    return self.clients.openWindow(url);
  }));
});
