// FitTrack Service Worker — v0.8.0
// BEWUSST OHNE CACHING: Ein cachender Service Worker würde nach Updates
// die alte App-Version ausliefern (Versionsdrift-Problem vom 12.06.2026).
// Dieser SW macht die App als PWA installierbar, lädt aber immer frisch vom Server.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()));
self.addEventListener('fetch', () => {
  // Kein respondWith = Browser lädt normal øber das Netzwerk
});
