// Keeps the loader working offline. It caches only these public files; your data lives in the
// encrypted file and the phone's own storage, never here.
const CACHE = 'money-loader-v3';
const FILES = ['./', 'index.html', 'loader.js', 'vendor/preact.js', 'vendor/chart.js', 'manifest.webmanifest', 'icon-180.png', 'icon-512.png'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.endsWith('/money.mtp')) return; // the data file: always the network, kept by the loader itself
  // Network first, always asking the server (so updates arrive), falling back to the cache when offline.
  e.respondWith(fetch(e.request.url, { cache: 'no-cache' }).then(r => { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); return r; })
    .catch(() => caches.match(e.request, { ignoreSearch: true })));
});
