/* ============================================================================
 *  KAKI PROXY — Service Worker (public/sw.js)
 *  --------------------------------------------------------------------------
 *  Runs on the proxy origin. Its job is to make sure that EVERY network
 *  request the browser makes — including ones the in-page bootstrap missed,
 *  ones from inline event handlers, ones from sandboxed iframes, ones from
 *  prefetch/preload, and ones from <video src> initiated by the media stack
 *  itself — is routed through the proxy with the correct upstream URL.
 *
 *  Why this matters for YouTube and other streaming sites:
 *    • The HTML5 media element issues partial-range requests directly from
 *      the browser; if those don't pass through the proxy, video stalls.
 *    • DASH/HLS manifests load tens of segment URLs every second; only a SW
 *      can intercept them cheaply enough.
 *    • Workers + WASM modules built dynamically by YouTube's player would
 *      otherwise escape any page-level patching.
 *
 *  Strategy:
 *    • For any request whose URL is on our origin AND under /p/<token>...,
 *      pass through unchanged. The server handles the heavy lifting.
 *    • For any request whose URL is on our origin but NOT under our prefix
 *      (i.e. something resolved against our origin by accident), redirect
 *      it to /__nav?u=<absolute-upstream> using the bound base URL stored
 *      in this SW from the page that registered us.
 *    • For ABSOLUTE upstream URLs that somehow reached fetch() unrewritten,
 *      transparently rewrite them to /__nav?u=<...>.
 *
 *  We do NOT do URL-cipher in the SW — the server's /__nav endpoint will
 *  emit a 302 to the encoded path. That keeps the cipher key inside the
 *  server.
 * ========================================================================== */

'use strict';

const KAKI = {
  // We keep a per-client base URL so relative paths can resolve. Maps
  // clientId → last seen upstream base URL.
  bases: new Map(),
  prefix: '/p/',
  navPath: '/__nav?u=',
};

self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('message', e => {
  // The page can tell us its current upstream URL via postMessage. We use
  // it to resolve relative URLs that the browser failed to make absolute.
  if (!e.data || !e.source) return;
  if (e.data.type === 'kaki:base' && typeof e.data.url === 'string') {
    KAKI.bases.set(e.source.id, e.data.url);
  }
});

function isProxiedPath(pathname) {
  return pathname.startsWith(KAKI.prefix);
}

function decodeProxiedTarget(reqUrl) {
  // The path is /p/<token>/optional/tail. We can't decode the token in the
  // SW (we don't have the key), but we can detect that the request is
  // ALREADY proxied and let it through unchanged.
  return reqUrl.pathname.startsWith(KAKI.prefix);
}

function isProxyableScheme(u) {
  return /^https?:$/i.test(u.protocol);
}

self.addEventListener('fetch', event => {
  const req = event.request;
  let url;
  try { url = new URL(req.url); } catch { return; }
  const sameOrigin = url.origin === self.location.origin;

  // 1. Same-origin + already on the proxy path → straight through.
  if (sameOrigin && isProxiedPath(url.pathname)) return;

  // 2. Same-origin static endpoints we recognise → straight through.
  if (sameOrigin && (
        url.pathname === '/' ||
        url.pathname === '/sw.js' ||
        url.pathname.startsWith('/__kaki/') ||
        url.pathname.startsWith('/__nav') ||
        url.pathname.startsWith('/assets/'))) return;

  // 3. Same-origin BUT something resolved against us by mistake (e.g. a
  //    site used location.origin in its own scripts). We need to re-route
  //    it to the upstream-equivalent path. The base URL of the controlling
  //    client tells us where this page actually came from.
  if (sameOrigin) {
    event.respondWith((async () => {
      const base = KAKI.bases.get(event.clientId) || await guessBaseFromClient(event);
      if (!base) {
        // No idea where this should go — just pass through and let the
        // server decide (it will likely 404).
        return fetch(req);
      }
      try {
        const abs = new URL(url.pathname + url.search + url.hash, base).toString();
        if (!/^https?:\/\//i.test(abs)) return fetch(req);
        const navUrl = self.location.origin + KAKI.navPath + encodeURIComponent(abs);
        // Re-issue as a proxied request.
        return fetch(navUrl, copyInit(req));
      } catch {
        return fetch(req);
      }
    })());
    return;
  }

  // 4. Cross-origin absolute URL — must be re-routed through the proxy.
  if (isProxyableScheme(url)) {
    event.respondWith((async () => {
      const navUrl = self.location.origin + KAKI.navPath + encodeURIComponent(req.url);
      return fetch(navUrl, copyInit(req));
    })());
  }
});

// Best-effort: when the SW has no recorded base for a client, ask the client.
async function guessBaseFromClient(event) {
  try {
    const c = await self.clients.get(event.clientId);
    if (!c) return null;
    // We don't have a way to synchronously read window.__KAKI__, but the
    // client's referrer is the page URL on our origin, which contains the
    // encoded upstream as /p/<token>. We can't decode it here either, but
    // the server's /__nav endpoint will accept relative resolution via the
    // proxied path's tail. So we use the client's URL as the base; the
    // server will absolutify against the stored token.
    return c.url;
  } catch { return null; }
}

function copyInit(req) {
  // Build a Request-init that preserves method, body, mode and credentials
  // but drops headers the SW isn't allowed to set.
  return {
    method:          req.method,
    headers:         req.headers,
    body:            ['GET', 'HEAD'].includes(req.method) ? undefined : req.body,
    mode:            req.mode === 'navigate' ? 'cors' : req.mode,
    credentials:     req.credentials,
    cache:           req.cache,
    redirect:        'follow',
    referrer:        req.referrer,
    referrerPolicy:  req.referrerPolicy,
    integrity:       req.integrity,
    keepalive:       req.keepalive,
    // body streams need duplex: 'half' in modern fetch
    duplex:          'half',
  };
}
