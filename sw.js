// sw.js
const CACHE = 'vault-pwa-v26';
const ASSETS = [
  './',
  './index.html?v=24',
  './styles.css?v=24',
  './app.js?v=24',
  './manifest.webmanifest'
  './icon-192.png',
  './icon-512.png',
  './icon-192-maskable.png',
'./icons/icon-512-maskable.png',
'./apple-touch-icon.png',
'./favicon-32.png',
'./favicon-16.png'
];

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // network-first dla HTML, cache-first dla reszty
  if (url.pathname.endsWith('.html') || e.request.mode === 'navigate') {
    e.respondWith(
      fetch(e.request).then(r => {
        const copy = r.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return r;
      }).catch(() => caches.match(e.request))
    );
  } else {
    e.respondWith(
      caches.match(e.request).then(res => res || fetch(e.request).then(r => {
        const copy = r.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return r;
      }))
    );
  }
});