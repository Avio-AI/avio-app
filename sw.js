// Avio.AI service worker.
// 1. Offline app: keeps a copy of the app page and its own files (vendor scripts, fonts, icons) so the app opens with
//    no signal. The page is fetched fresh from the network first (a published fix shows on the next launch); the copy
//    is used only when the network fails or takes too long. Data sets are not handled here: the page keeps them itself.
// 2. Case-email notifications (push).
const SHELL = 'avio-shell-v3';   // v2: a v1 copy may hold the User Guide in place of the app (fixed 20 NOV 2026)
                                 // v3: a v2 copy may be a redirected response, which Safari refuses to open (fixed 24 NOV 2026)
const PAGE = new URL('./', self.registration.scope).href;          // the app page, stored under one key whatever the ?query
const FILES = ['manifest.webmanifest', 'icon-180.png', 'icon-192.png', 'icon-512.png', 'icon.svg',
  'vendor/fonts.css', 'vendor/fonts/material-symbols-rounded.woff2', 'vendor/fonts/roboto-latin-400-normal.woff2',
  'vendor/fonts/roboto-latin-500-normal.woff2', 'vendor/fonts/roboto-latin-700-normal.woff2',
  'vendor/fonts/roboto-mono-latin-400-normal.woff2', 'vendor/fonts/roboto-mono-latin-500-normal.woff2',
  'vendor/fonts/Lato-Regular.ttf', 'vendor/fonts/Lato-Bold.ttf',
  'vendor/jszip.min.js', 'vendor/jspdf.umd.min.js', 'vendor/pdf-lib.min.js', 'vendor/fontkit.umd.min.js',
  'vendor/pdf.min.mjs', 'vendor/pdf.worker.min.mjs'].map(f => new URL(f, self.registration.scope).href);

// Safari refuses to open a page from a response that went through a redirect ("Response served by service worker has
// redirections"), e.g. a copy stored while the domain moved. Rebuild such a response so it carries no redirect mark.
const plain = async r => (r && r.redirected)
  ? new Response(await r.blob(), { status: r.status, statusText: r.statusText, headers: r.headers }) : r;

// one file failing (renamed, offline) must not stop the rest from being stored
const store = async (c, url) => { try { const r = await fetch(url, { cache: 'no-cache' }); if (r.ok) await c.put(url, await plain(r)); } catch (e) {} };

self.addEventListener('install', e => {
  e.waitUntil(caches.open(SHELL).then(c => Promise.all([PAGE, ...FILES].map(u => store(c, u)))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k.startsWith('avio-shell-') && k !== SHELL) await caches.delete(k);
  await self.clients.claim();
})()));

// Only the app's own address is the app page. Other pages (the Help guides open in a frame, which is also a navigation)
// must never be stored as the app: that made an offline launch open the guide.
const isPage = url => { const p = url.origin + url.pathname; return p === PAGE || p === PAGE + 'index.html'; };
const isShellFile = url => FILES.includes(url.href) || url.href.startsWith(new URL('help/', self.registration.scope).href);

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;              // Claude, GitHub, mail: straight to the network
  if (isPage(url)) { e.respondWith(pageFirst(req)); return; }
  if (isShellFile(url)) { e.respondWith(fileFresh(req, url.href)); return; }
});

// the page: network first; the stored copy if the network fails, or after 8 s with weak signal
async function pageFirst(req) {
  const c = await caches.open(SHELL);
  const net = fetch(req.url, { cache: 'no-cache', credentials: 'same-origin' })
    .then(plain).then(async r => { if (r.ok) await c.put(PAGE, r.clone()); return r; });
  const slow = new Promise(res => setTimeout(res, 8000));
  try {
    const r = await Promise.race([net, slow.then(() => null)]);
    if (r) return r;
    const hit = await plain(await c.match(PAGE));
    if (hit) { net.catch(() => {}); return hit; }
    return await net;
  } catch (err) {
    const hit = await plain(await c.match(PAGE));
    if (hit) return hit;
    throw err;
  }
}
// scripts, fonts, icons, help pictures: the stored copy at once, refreshed in the background
async function fileFresh(req, key) {
  const c = await caches.open(SHELL);
  const hit = await plain(await c.match(key));
  const net = fetch(req).then(plain).then(async r => { if (r.ok) await c.put(key, r.clone()); return r; });
  if (hit) { net.catch(() => {}); return hit; }
  return net;
}

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
