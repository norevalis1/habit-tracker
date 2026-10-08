// SERVICE WORKER: a small helper script the browser runs in the background.
// Its job: remember the app's files on your phone so the app opens instantly,
// and still opens when your connection is weak or off.
//
// It does NOT store or touch your habit data. Your habits always come live
// from Supabase (we never intercept those requests).
//
// When you change index.html in the future, bump the number in CACHE below.
// That tells phones to throw away the old copy.

const CACHE = "habits-v2";
const CDN = "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2";
const APP_FILES = ["./", "./index.html", "./manifest.webmanifest", "./icon-192.png", "./icon-512.png", "./apple-touch-icon.png"];

// 1. INSTALL: save the app's files.
self.addEventListener("install", event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await cache.addAll(APP_FILES);
    // The login/database library comes from another website; save it too
    // (best effort: don't fail the install if it can't be fetched right now).
    try { await cache.put(CDN, await fetch(new Request(CDN, { mode: "no-cors" }))); } catch (e) { /* ok */ }
    await self.skipWaiting();
  })());
});

// 2. ACTIVATE: delete older saved copies.
self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key !== CACHE) await caches.delete(key);
    await self.clients.claim();
  })());
});

// 3. FETCH: decide where each request gets its answer.
self.addEventListener("fetch", event => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);

  // The page itself: try the internet first (so updates show up),
  // and fall back to the saved copy when offline.
  if (req.mode === "navigate") {
    event.respondWith((async () => {
      try {
        const fresh = await fetch(req);
        if (fresh.ok) { const c = await caches.open(CACHE); c.put("./index.html", fresh.clone()); }
        return fresh;
      } catch (e) {
        return (await caches.match("./index.html")) || (await caches.match("./")) || Response.error();
      }
    })());
    return;
  }

  // The library from the CDN, and our own icons/manifest: saved copy first,
  // refreshed quietly in the background.
  if (req.url === CDN || (url.origin === self.location.origin && APP_FILES.some(f => url.pathname.endsWith(f.slice(1))))) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE);
      const saved = await cache.match(req);
      const refresh = fetch(req).then(res => { if (res && (res.ok || res.type === "opaque")) cache.put(req, res.clone()); return res; }).catch(() => null);
      return saved || (await refresh) || Response.error();
    })());
  }
  // Everything else (Supabase data and login) goes straight to the internet, untouched.
});

// 4. PUSH: the server sent a reminder. Show it as a notification.
// (The message is encrypted on its way here; the browser decrypts it for us.)
self.addEventListener("push", event => {
  let data = { title: "Habits", body: "Time to check in." };
  try { if (event.data) data = Object.assign(data, event.data.json()); } catch (e) { /* use the default text */ }
  event.waitUntil(self.registration.showNotification(data.title, {
    body: data.body,
    icon: "icon-192.png",
    badge: "icon-192.png",
    tag: "habits-reminder",       // a newer reminder replaces an older one instead of stacking
    renotify: true,
    data: { url: "./" }
  }));
});

// 5. TAP on a notification: open (or come back to) the app.
self.addEventListener("notificationclick", event => {
  event.notification.close();
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const w of windows) if ("focus" in w) return w.focus();
    return self.clients.openWindow("./");
  })());
});
