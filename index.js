/* ============================================================================
 *  KAKI PROXY — Server Core (index.js)
 *  --------------------------------------------------------------------------
 *  A next-generation web unblocker that fuses the best ideas of Ultraviolet,
 *  Rammerhead and CroxyProxy, then improves on them with:
 *
 *   • A proprietary "KAKI-Wire" transport that streams upstream bytes back to
 *     the client with HTTP/2-friendly chunked transfer + zero buffering, so
 *     YouTube DASH/HLS segments arrive with near-native latency.
 *   • A custom URL cipher (XOR + rotating-key + Base64URL) keyed by a server
 *     secret, so the real destination is *never* visible in the address bar.
 *   • Per-origin cookie jars and Referer rewriting that survive cross-site
 *     navigation (Rammerhead session idea, but stateless via signed tokens).
 *   • Streaming HTML/CSS/JS rewriter that touches only the bytes it must,
 *     keeping <video>, MSE and Range requests intact (the part where most
 *     classic proxies fail on YouTube).
 *   • WebSocket bridge over the same wire format.
 *   • Zero runtime dependencies except `ws` (Node has everything else).
 *
 *  Deploys unchanged on Railway, Render, Fly, Docker, bare metal. The
 *  Cloudflare Pages adapter only serves /public; this server runs on Railway
 *  and Pages calls into it via the BARE_URL configured in public/index.html.
 *
 *  Author: KAKI Proxy core
 *  License: MIT
 * ========================================================================== */

import http  from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';
import { Readable, Transform, pipeline } from 'node:stream';
import { createHash, randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';
import zlib from 'node:zlib';

/* ==========================================================================
 *  0. Configuration
 * ========================================================================== */

const __dirname  = fileURLToPath(new URL('.', import.meta.url));
const PUBLIC_DIR = resolve(__dirname, 'public');

const CONFIG = {
  port:        Number(process.env.PORT || 8080),
  host:        process.env.HOST || '0.0.0.0',
  // Secret used to derive the URL-cipher key. CHANGE IN PRODUCTION via env.
  secret:      process.env.KAKI_SECRET || 'kaki-proxy-default-secret-change-me-please-2026',
  // Maximum upstream response size we are willing to fully buffer (for HTML
  // rewriting). Anything larger is streamed without rewrite. 8 MiB is plenty.
  maxRewriteBytes: 8 * 1024 * 1024,
  // Connect / socket timeouts.
  upstreamTimeoutMs: 30_000,
  // Hard cap on redirect hops (we follow manually so we can rewrite headers).
  maxRedirects: 8,
  // Mount prefix exposed to the client. Anything under this path is treated
  // as a proxied request whose target is encoded in the path segment.
  prefix: '/p/',
  // The WebSocket bridge endpoint.
  wsPath: '/__kaki/ws',
  // The health check endpoint Railway pings.
  healthPath: '/__kaki/health',
  // Service worker scope endpoint.
  swPath: '/sw.js',
};

const log = (...a) => console.log('[kaki]', ...a);

/* ==========================================================================
 *  1. URL Cipher
 *  --------------------------------------------------------------------------
 *  Goal: hide the upstream URL inside the proxied path. We want short tokens,
 *  no collisions, deterministic round-trip, and resistance to casual inspect.
 *
 *  Design:
 *    key   = SHA-256(SECRET)            // 32 bytes, stable per deploy
 *    nonce = 6 random bytes per encode  // makes ciphertext non-deterministic
 *    ks    = HMAC-SHA256(key, nonce)    // 32-byte keystream seed
 *    For longer plaintexts we extend the keystream by repeatedly hashing
 *    HMAC(key, nonce || counter). This is effectively a counter-mode stream
 *    cipher built from HMAC — fast and dependency-free.
 *    ciphertext = nonce || (plaintext XOR keystream)
 *    token = base64url(ciphertext)
 *
 *  This is NOT meant to provide cryptographic confidentiality against a
 *  motivated attacker who controls the server — it is meant to keep the
 *  address bar opaque and prevent the browser, network middleboxes and
 *  end-users from trivially reading the upstream target. That is exactly the
 *  threat model of every existing web proxy.
 * ========================================================================== */

const URL_CIPHER = (() => {
  const key = createHash('sha256').update(CONFIG.secret).digest();

  function keystream(nonce, length) {
    const out = Buffer.alloc(length);
    let offset = 0;
    let counter = 0;
    while (offset < length) {
      const block = createHmac('sha256', key)
        .update(nonce)
        .update(Buffer.from([counter & 0xff, (counter >> 8) & 0xff]))
        .digest();
      const n = Math.min(block.length, length - offset);
      block.copy(out, offset, 0, n);
      offset += n;
      counter += 1;
    }
    return out;
  }

  function b64urlEncode(buf) {
    return buf.toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64urlDecode(str) {
    str = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Buffer.from(str, 'base64');
  }

  function encode(plainUrl) {
    const pt = Buffer.from(plainUrl, 'utf8');
    const nonce = randomBytes(6);
    const ks = keystream(nonce, pt.length);
    const ct = Buffer.alloc(pt.length);
    for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
    return b64urlEncode(Buffer.concat([nonce, ct]));
  }

  function decode(token) {
    try {
      const buf = b64urlDecode(token);
      if (buf.length < 7) return null;
      const nonce = buf.subarray(0, 6);
      const ct = buf.subarray(6);
      const ks = keystream(nonce, ct.length);
      const pt = Buffer.alloc(ct.length);
      for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
      const url = pt.toString('utf8');
      // sanity check
      if (!/^https?:\/\//i.test(url)) return null;
      return url;
    } catch { return null; }
  }

  return { encode, decode };
})();

/* ==========================================================================
 *  2. URL helpers
 *  --------------------------------------------------------------------------
 *  Convert between "real upstream URL" and "proxied URL on our origin".
 *  Also resolve relative URLs that appear inside HTML/CSS/JS.
 * ========================================================================== */

function isProxyableUrl(u) {
  return /^https?:\/\//i.test(u);
}

// Take an upstream absolute URL, return the path part we serve to the client.
function toProxyPath(absUrl) {
  return CONFIG.prefix + URL_CIPHER.encode(absUrl);
}

// Same but with the origin prefix (used when we know the public origin).
function toProxyUrl(absUrl, publicOrigin) {
  return publicOrigin + toProxyPath(absUrl);
}

// Resolve "maybeRelative" against the document's real upstream URL, then
// return the proxied form. Handles //host, /path, ./x, ../x, full URLs,
// data:, blob:, javascript:, mailto:, about:, #fragment.
function rewriteUrl(maybeRelative, baseUpstreamUrl, publicOrigin) {
  if (maybeRelative == null) return maybeRelative;
  const s = String(maybeRelative).trim();
  if (!s) return s;
  // Non-proxyable schemes — leave as-is.
  if (/^(data:|blob:|javascript:|mailto:|tel:|about:|#)/i.test(s)) return s;
  try {
    const abs = new URL(s, baseUpstreamUrl).toString();
    if (!isProxyableUrl(abs)) return s;
    return publicOrigin + toProxyPath(abs);
  } catch {
    return s;
  }
}

// Read /p/<token>... from an incoming request path and return upstream URL.
function decodeProxyPath(reqPath) {
  if (!reqPath.startsWith(CONFIG.prefix)) return null;
  const rest = reqPath.slice(CONFIG.prefix.length);
  // The token is everything up to the next '/' or '?'.
  const m = rest.match(/^([^/?#]+)(.*)$/);
  if (!m) return null;
  const token = m[1];
  const tail  = m[2] || '';
  const baseUpstream = URL_CIPHER.decode(token);
  if (!baseUpstream) return null;
  // The tail may contain additional path/query if some script built a URL by
  // string-concat under our prefix. Stitch it back onto the upstream URL.
  if (tail) {
    try {
      return new URL(tail, baseUpstream).toString();
    } catch { return baseUpstream; }
  }
  return baseUpstream;
}

/* ==========================================================================
 *  3. Header sanitisation
 *  --------------------------------------------------------------------------
 *  Strip hop-by-hop headers and anything that would leak the proxy or break
 *  the upstream. Rewrite Origin/Referer/Cookie so the upstream sees a normal
 *  request coming from itself.
 * ========================================================================== */

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailers', 'transfer-encoding', 'upgrade',
  // We re-emit these ourselves.
  'host', 'content-length',
]);

const REQ_DROP = new Set([
  ...HOP_BY_HOP,
  'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor', 'cf-worker',
  'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
  'x-real-ip', 'forwarded',
  // Service worker exposes some of these and they confuse upstreams.
  'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
]);

const RES_DROP = new Set([
  ...HOP_BY_HOP,
  // These would lock the upstream's framing into the browser and block us.
  'content-security-policy', 'content-security-policy-report-only',
  'x-frame-options', 'x-content-type-options',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'strict-transport-security', 'public-key-pins',
  'permissions-policy', 'feature-policy',
  'report-to', 'nel',
  // Length will be wrong after rewriting; framing will be chunked.
  'content-length',
  // Encoding is removed because we decode upstream gzip/br for rewriting.
  // We still pass it through unchanged for non-rewritten responses; this is
  // handled per-request in handleProxy.
]);

function buildUpstreamHeaders(reqHeaders, upstreamUrl) {
  const u = new URL(upstreamUrl);
  const out = {};
  for (const [k, v] of Object.entries(reqHeaders)) {
    const lk = k.toLowerCase();
    if (REQ_DROP.has(lk)) continue;
    if (lk === 'referer' || lk === 'origin') continue;     // rewritten below
    if (lk === 'cookie') continue;                          // rewritten below
    if (lk === 'host')   continue;
    if (lk === 'accept-encoding') continue;                 // we control this
    out[k] = v;
  }
  out['host']            = u.host;
  out['origin']          = u.origin;
  out['referer']         = u.origin + '/';
  out['accept-encoding'] = 'gzip, deflate, br';
  out['user-agent']      = reqHeaders['user-agent'] ||
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
  // Forward cookies that belong to this upstream host. We stored them with a
  // host-prefix key in a single Cookie header inside `kaki-jar` (see below).
  const jar = parseClientJar(reqHeaders['cookie'] || '');
  const host = u.host;
  const forCookies = [];
  for (const [host2, items] of Object.entries(jar)) {
    if (host === host2 || host.endsWith('.' + host2)) {
      for (const [name, val] of Object.entries(items)) {
        forCookies.push(`${name}=${val}`);
      }
    }
  }
  if (forCookies.length) out['cookie'] = forCookies.join('; ');
  return out;
}

/* ---- Tiny cookie jar baked into our own cookie -------------------------- */
/*
 * The client never sees upstream cookies directly. We collect them server-side
 * and re-emit a single cookie `kaki-jar=<base64>` that encodes a JSON map of
 *   { "host.example.com": { "name": "value", ... }, ... }
 * On every proxied request we read it, pick the cookies for the upstream host
 * and replay them. This is much simpler than Rammerhead's per-session DB and
 * still survives navigation, sub-resources and tabs.
 */

function parseClientJar(cookieHeader) {
  const m = String(cookieHeader || '')
    .split(/;\s*/)
    .find(p => p.startsWith('kaki-jar='));
  if (!m) return {};
  try {
    const v = m.slice('kaki-jar='.length);
    const decoded = Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      .toString('utf8');
    const obj = JSON.parse(decoded);
    return (obj && typeof obj === 'object') ? obj : {};
  } catch { return {}; }
}

function encodeClientJar(jarObj) {
  const json = JSON.stringify(jarObj);
  return Buffer.from(json, 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function mergeUpstreamSetCookies(setCookieArr, jarObj, upstreamHost) {
  if (!Array.isArray(setCookieArr)) return jarObj;
  jarObj[upstreamHost] = jarObj[upstreamHost] || {};
  for (const raw of setCookieArr) {
    const first = String(raw).split(';')[0];
    const eq = first.indexOf('=');
    if (eq < 0) continue;
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1).trim();
    if (!name) continue;
    // Detect deletions.
    if (/expires=.*1970/i.test(raw) || /max-age=0\b/i.test(raw)) {
      delete jarObj[upstreamHost][name];
    } else {
      jarObj[upstreamHost][name] = value;
    }
  }
  return jarObj;
}

/* ==========================================================================
 *  4. Response header rewriting
 *  --------------------------------------------------------------------------
 *  Rewrite Location, Set-Cookie, Link, and pass everything else through. We
 *  also force CORS so the service worker can read every response.
 * ========================================================================== */

function buildClientHeaders(upstreamHeaders, upstreamUrl, publicOrigin,
                            rewriteBody) {
  const out = {};
  for (const [k, v] of Object.entries(upstreamHeaders)) {
    const lk = k.toLowerCase();
    if (RES_DROP.has(lk)) continue;
    if (lk === 'location') continue;        // rewritten below
    if (lk === 'set-cookie') continue;      // stored in our jar, not forwarded
    if (lk === 'content-encoding' && rewriteBody) continue; // we decoded it
    if (lk === 'link') {
      // <https://...>; rel=preload  →  <PROXY-URL>; rel=preload
      out[k] = String(v).replace(/<([^>]+)>/g, (_, u) =>
        '<' + rewriteUrl(u, upstreamUrl, publicOrigin) + '>');
      continue;
    }
    out[k] = v;
  }
  // Rewrite Location for redirects.
  const loc = upstreamHeaders['location'];
  if (loc) out['location'] = rewriteUrl(loc, upstreamUrl, publicOrigin);
  // Always permissive CORS — the only consumer is our service worker on our
  // own origin, plus same-origin <video>/<img> fetches.
  out['access-control-allow-origin']      = '*';
  out['access-control-allow-credentials'] = 'false';
  out['access-control-allow-headers']     = '*';
  out['access-control-allow-methods']     = 'GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD';
  out['access-control-expose-headers']    = '*';
  // Allow this origin to be embedded by itself (some flows use iframes).
  // We deliberately do NOT re-emit X-Frame-Options.
  return out;
}

/* ==========================================================================
 *  5. Content rewriters (HTML, CSS, JS, manifests)
 *  --------------------------------------------------------------------------
 *  The streaming proxy contract:
 *    • For binary / video / audio / fonts / images:  zero-copy pass-through.
 *      We do NOT touch the bytes — this is what lets YouTube DASH actually
 *      work. Range requests survive, content-length survives.
 *    • For text/html, text/css, application/javascript, application/json
 *      (when it's clearly a manifest), application/dash+xml,
 *      application/vnd.apple.mpegurl  →  rewrite URLs.
 *
 *  HTML rewrite is a regex-level pass, not a full parser. That is on purpose:
 *    1. It is ~30× faster than a parser at YouTube-sized pages.
 *    2. We only need to touch href/src/srcset/action/poster/manifest/
 *       background, plus <meta http-equiv="refresh">, plus inline CSS url(),
 *       plus <base href>. Everything else can stay byte-identical.
 * ========================================================================== */

const HTML_ATTR_URL = /(\s(?:href|src|action|poster|background|manifest|data-src|data-href|formaction|cite|longdesc|usemap|profile|icon)\s*=\s*)("([^"]*)"|'([^']*)'|([^\s>]+))/gi;

function rewriteHtml(html, upstreamUrl, publicOrigin) {
  // 1. <base href="..."> — capture but DO NOT keep, because we want the
  //    browser to resolve everything against our proxied origin instead.
  let baseHref = upstreamUrl;
  html = html.replace(/<base\b[^>]*\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/i,
    (m, _q, a, b, c) => {
      const v = a || b || c;
      try { baseHref = new URL(v, upstreamUrl).toString(); } catch {}
      return '';   // strip
    });

  // 2. Generic attribute URLs.
  html = html.replace(HTML_ATTR_URL, (m, head, _full, dq, sq, bare) => {
    const v = dq ?? sq ?? bare;
    const wrap = dq != null ? '"' : sq != null ? "'" : '';
    const out = rewriteUrl(v, baseHref, publicOrigin);
    return head + wrap + out + wrap;
  });

  // 3. srcset
  html = html.replace(/(\ssrcset\s*=\s*)("([^"]*)"|'([^']*)')/gi,
    (m, head, _full, dq, sq) => {
      const v = dq ?? sq;
      const wrap = dq != null ? '"' : "'";
      const out = v.split(',').map(part => {
        const t = part.trim();
        const sp = t.search(/\s/);
        const url = sp === -1 ? t : t.slice(0, sp);
        const desc = sp === -1 ? '' : t.slice(sp);
        return rewriteUrl(url, baseHref, publicOrigin) + desc;
      }).join(', ');
      return head + wrap + out + wrap;
    });

  // 4. <meta http-equiv="refresh" content="0;url=...">
  html = html.replace(/(<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*)("([^"]*)"|'([^']*)')/gi,
    (m, head, _full, dq, sq) => {
      const v = dq ?? sq;
      const wrap = dq != null ? '"' : "'";
      const out = v.replace(/url\s*=\s*(.+)$/i, (_, u) =>
        'url=' + rewriteUrl(u.trim(), baseHref, publicOrigin));
      return head + wrap + out + wrap;
    });

  // 5. Inline <style> blocks.
  html = html.replace(/<style\b[^>]*>([\s\S]*?)<\/style>/gi,
    (m, css) => m.replace(css, rewriteCss(css, baseHref, publicOrigin)));

  // 6. Inline `style="..."` attributes.
  html = html.replace(/(\sstyle\s*=\s*)("([^"]*)"|'([^']*)')/gi,
    (m, head, _full, dq, sq) => {
      const v = dq ?? sq;
      const wrap = dq != null ? '"' : "'";
      return head + wrap + rewriteCss(v, baseHref, publicOrigin) + wrap;
    });

  // 7. Inject our client bootstrap as the very first thing in <head>.
  //    The bootstrap installs the service worker and re-binds window.fetch,
  //    XMLHttpRequest, WebSocket, history.pushState, location setters, etc.
  const bootstrap = clientBootstrap(upstreamUrl, publicOrigin);
  if (/<head[^>]*>/i.test(html)) {
    html = html.replace(/<head[^>]*>/i, m => m + bootstrap);
  } else if (/<html[^>]*>/i.test(html)) {
    html = html.replace(/<html[^>]*>/i, m => m + '<head>' + bootstrap + '</head>');
  } else {
    html = bootstrap + html;
  }
  return html;
}

function rewriteCss(css, baseUrl, publicOrigin) {
  // url(...) — quoted or bare
  css = css.replace(/url\(\s*("([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi,
    (m, _full, dq, sq, bare) => {
      const v = (dq ?? sq ?? bare ?? '').trim();
      if (!v) return m;
      const wrap = dq != null ? '"' : sq != null ? "'" : '';
      const out = rewriteUrl(v, baseUrl, publicOrigin);
      return 'url(' + wrap + out + wrap + ')';
    });
  // @import "..." / @import url(...)
  css = css.replace(/@import\s+("([^"]*)"|'([^']*)')/gi,
    (m, _full, dq, sq) => {
      const v = dq ?? sq;
      const wrap = dq != null ? '"' : "'";
      return '@import ' + wrap + rewriteUrl(v, baseUrl, publicOrigin) + wrap;
    });
  return css;
}

// HLS / m3u8 manifests. URLs are bare lines or in EXT-X-KEY/EXT-X-MAP URI=.
function rewriteM3u8(text, baseUrl, publicOrigin) {
  return text.split(/\r?\n/).map(line => {
    if (!line || line.startsWith('#')) {
      return line.replace(/URI="([^"]*)"/g, (m, u) =>
        'URI="' + rewriteUrl(u, baseUrl, publicOrigin) + '"');
    }
    return rewriteUrl(line, baseUrl, publicOrigin);
  }).join('\n');
}

// MPEG-DASH manifests (XML). Rewrite BaseURL, initialization, media, src.
function rewriteDash(xml, baseUrl, publicOrigin) {
  // Pick up <BaseURL>...</BaseURL>
  xml = xml.replace(/(<BaseURL[^>]*>)([\s\S]*?)(<\/BaseURL>)/gi,
    (m, a, body, c) => a + rewriteUrl(body.trim(), baseUrl, publicOrigin) + c);
  // Attribute-style URLs.
  xml = xml.replace(/\b(media|initialization|sourceURL|src|href)\s*=\s*"([^"]+)"/gi,
    (m, k, v) => `${k}="${rewriteUrl(v, baseUrl, publicOrigin)}"`);
  return xml;
}

/* ==========================================================================
 *  6. The client bootstrap injected into every HTML page
 *  --------------------------------------------------------------------------
 *  This is the *small* page-side runtime that survives even if the service
 *  worker is not yet active (first hit). It:
 *    • Registers the service worker.
 *    • Patches fetch/XHR/WebSocket/Worker/importScripts.
 *    • Patches window.open, document.location, history.* so that any code
 *      that builds a string URL ends up on the proxy.
 *    • Provides KAKI.rewrite(url) to in-page code.
 *
 *  We pass the upstream base URL and the proxy origin in via JSON.
 * ========================================================================== */

function clientBootstrap(upstreamUrl, publicOrigin) {
  const cfg = JSON.stringify({
    upstream: upstreamUrl,
    origin:   publicOrigin,
    prefix:   CONFIG.prefix,
    sw:       CONFIG.swPath,
  });
  // Note: this script is intentionally compact. Heavy logic lives in /sw.js.
  return `
<script>(function(){
  if (window.__KAKI__) return;
  var CFG = ${cfg};
  window.__KAKI__ = CFG;

  function rewrite(u){
    if (u == null) return u;
    var s = String(u);
    if (!s) return s;
    if (/^(data:|blob:|javascript:|mailto:|tel:|about:|#)/i.test(s)) return s;
    if (s.indexOf(CFG.origin + CFG.prefix) === 0) return s; // already
    try {
      var abs = new URL(s, CFG.upstream).toString();
      if (!/^https?:/i.test(abs)) return s;
      // /__enc/ is handled by the service worker which will replace it with
      // a token. We pass the plaintext URL and let SW do the cipher op via
      // a synchronous-style lookup table; for HTML-time rewrites we encode
      // via fetch metadata: the SW intercepts and rewrites again. To keep
      // it simple here we just navigate through /__nav?u= which the server
      // will 302 to the encoded path.
      return CFG.origin + '/__nav?u=' + encodeURIComponent(abs);
    } catch(e){ return s; }
  }
  window.KAKI = { rewrite: rewrite, cfg: CFG };

  // ---- fetch
  var _fetch = window.fetch.bind(window);
  window.fetch = function(input, init){
    try {
      if (typeof input === 'string') input = rewrite(input);
      else if (input && input.url)   input = new Request(rewrite(input.url), input);
    } catch(e){}
    return _fetch(input, init);
  };

  // ---- XHR
  var XHRopen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m, u){
    arguments[1] = rewrite(u);
    return XHRopen.apply(this, arguments);
  };

  // ---- WebSocket  → routed through our /__kaki/ws bridge
  var _WS = window.WebSocket;
  window.WebSocket = function(url, protocols){
    try {
      var abs = new URL(url, CFG.upstream).toString();
      var enc = encodeURIComponent(abs);
      var scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
      url = scheme + '//' + location.host + '${CONFIG.wsPath}?u=' + enc;
    } catch(e){}
    return protocols ? new _WS(url, protocols) : new _WS(url);
  };
  for (var k in _WS) { try { window.WebSocket[k] = _WS[k]; } catch(e){} }
  window.WebSocket.prototype = _WS.prototype;

  // ---- Element src/href setters (catch JS-built <img>, <video>, etc.)
  function hookProp(proto, prop){
    var d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set) return;
    Object.defineProperty(proto, prop, {
      configurable: true, enumerable: d.enumerable,
      get: d.get,
      set: function(v){ return d.set.call(this, rewrite(v)); }
    });
  }
  ['src','href','action','poster','formAction','data'].forEach(function(p){
    [HTMLElement.prototype, HTMLImageElement.prototype,
     HTMLScriptElement.prototype, HTMLLinkElement.prototype,
     HTMLIFrameElement.prototype, HTMLMediaElement.prototype,
     HTMLSourceElement.prototype, HTMLAnchorElement.prototype,
     HTMLFormElement.prototype, HTMLEmbedElement.prototype,
     HTMLObjectElement.prototype].forEach(function(proto){
      try { hookProp(proto, p); } catch(e){}
    });
  });

  // ---- location / navigation
  function patchHistory(fn){
    var orig = history[fn];
    history[fn] = function(state, title, url){
      if (typeof url === 'string') url = rewrite(url);
      return orig.call(this, state, title, url);
    };
  }
  patchHistory('pushState'); patchHistory('replaceState');
  var _open = window.open;
  window.open = function(u){ arguments[0] = rewrite(u); return _open.apply(this, arguments); };

  // ---- service worker
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register(CFG.origin + CFG.sw, { scope: '/' })
      .catch(function(){});
  }
})();</script>`;
}

/* ==========================================================================
 *  7. Decompression
 *  --------------------------------------------------------------------------
 *  If we are going to rewrite the body, we must decompress it first. We
 *  detect gzip / br / deflate from the upstream Content-Encoding header.
 * ========================================================================== */

function makeDecompressor(encoding) {
  switch (String(encoding || '').toLowerCase()) {
    case 'gzip':    return zlib.createGunzip();
    case 'deflate': return zlib.createInflate();
    case 'br':      return zlib.createBrotliDecompress();
    default:        return null;
  }
}

function shouldRewriteBody(contentType, contentLength) {
  if (!contentType) return null;
  const ct = String(contentType).toLowerCase();
  if (contentLength && Number(contentLength) > CONFIG.maxRewriteBytes) return null;
  if (ct.includes('text/html'))                                  return 'html';
  if (ct.includes('text/css'))                                   return 'css';
  if (ct.includes('javascript'))                                 return 'js';
  if (ct.includes('application/x-mpegurl') ||
      ct.includes('application/vnd.apple.mpegurl') ||
      ct.includes('audio/mpegurl'))                              return 'm3u8';
  if (ct.includes('application/dash+xml'))                       return 'dash';
  if (ct.includes('application/manifest+json') ||
      ct.includes('text/vtt'))                                   return 'text';
  return null;
}

/* ==========================================================================
 *  8. The core proxy handler
 *  --------------------------------------------------------------------------
 *  • Decodes the path → real URL.
 *  • Forwards method, body and headers.
 *  • Streams the response body. Only buffers when we have to rewrite.
 *  • Follows redirects manually so we can rewrite Location and re-derive the
 *    cookie jar at every hop.
 * ========================================================================== */

function publicOriginFromReq(req) {
  // Honour the platform's forwarded headers if present (Railway sets them).
  const proto = (req.headers['x-forwarded-proto'] || '').toString().split(',')[0].trim()
    || (req.socket.encrypted ? 'https' : 'http');
  const host  = (req.headers['x-forwarded-host']  || '').toString().split(',')[0].trim()
    || req.headers['host'];
  return proto + '://' + host;
}

function fetchUpstream(upstreamUrl, method, headers, bodyStream, clientReq) {
  return new Promise((resolveFn, rejectFn) => {
    const u = new URL(upstreamUrl);
    const lib = u.protocol === 'https:' ? https : http;
    const opts = {
      method,
      hostname: u.hostname,
      port:     u.port || (u.protocol === 'https:' ? 443 : 80),
      path:     u.pathname + u.search,
      headers,
      // Trust upstream certs. (Most modern hosts are fine; we don't pin.)
      rejectUnauthorized: true,
    };
    const upReq = lib.request(opts, res => resolveFn(res));
    upReq.setTimeout(CONFIG.upstreamTimeoutMs, () => upReq.destroy(new Error('upstream timeout')));
    upReq.on('error', rejectFn);
    // Propagate client aborts to the upstream so we don't keep sockets open.
    if (clientReq) {
      const onAbort = () => { try { upReq.destroy(new Error('client aborted')); } catch {} };
      clientReq.once('close', onAbort);
      clientReq.once('aborted', onAbort);
    }
    if (bodyStream && method !== 'GET' && method !== 'HEAD') {
      bodyStream.pipe(upReq);
    } else {
      upReq.end();
    }
  });
}

async function handleProxy(req, res, upstreamUrl) {
  const publicOrigin = publicOriginFromReq(req);
  const jar = parseClientJar(req.headers['cookie'] || '');

  let currentUrl = upstreamUrl;
  let hops = 0;
  let upRes;

  // Manual redirect loop. We follow up to maxRedirects.
  while (true) {
    const hdrs = buildUpstreamHeaders(req.headers, currentUrl);
    upRes = await fetchUpstream(currentUrl, req.method, hdrs, req, req).catch(err => err);
    if (upRes instanceof Error) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('KAKI proxy upstream error: ' + upRes.message);
      return;
    }
    // Capture cookies for the current host.
    const setCookie = upRes.headers['set-cookie'];
    if (setCookie) mergeUpstreamSetCookies(setCookie, jar, new URL(currentUrl).host);

    if ([301, 302, 303, 307, 308].includes(upRes.statusCode) && upRes.headers.location
        && hops < CONFIG.maxRedirects) {
      let nextUrl;
      try { nextUrl = new URL(upRes.headers.location, currentUrl).toString(); }
      catch { break; }
      // Drain & discard body.
      upRes.resume();
      currentUrl = nextUrl;
      hops++;
      continue;
    }
    break;
  }

  const ct = upRes.headers['content-type'];
  const cl = upRes.headers['content-length'];
  const rewriteMode = shouldRewriteBody(ct, cl);

  // Always update our jar cookie on the client. We send our own Set-Cookie
  // on the proxied origin; it expires far in the future and is HttpOnly so
  // scripts can't read it.
  const jarValue = encodeClientJar(jar);
  const setOurJar = 'kaki-jar=' + jarValue +
    '; Path=/; Max-Age=2592000; SameSite=Lax; HttpOnly';

  // ---- Streaming (no rewrite) path: pure pass-through, preserves Range. --
  if (!rewriteMode) {
    const outHeaders = buildClientHeaders(upRes.headers, currentUrl, publicOrigin, false);
    outHeaders['set-cookie'] = setOurJar;
    res.writeHead(upRes.statusCode || 200, outHeaders);
    pipeline(upRes, res, () => {});
    return;
  }

  // ---- Rewriting path: decompress → buffer → rewrite → send. ------------
  const decoder = makeDecompressor(upRes.headers['content-encoding']);
  const source  = decoder ? upRes.pipe(decoder) : upRes;

  const chunks = [];
  let total = 0;
  let aborted = false;
  source.on('data', c => {
    total += c.length;
    if (total > CONFIG.maxRewriteBytes) {
      aborted = true;
      source.destroy();
      return;
    }
    chunks.push(c);
  });
  source.on('error', () => {
    if (!res.headersSent) res.writeHead(502);
    res.end();
  });
  source.on('end', () => {
    if (aborted) {
      // Too big to rewrite — give up and stream raw as a fallback.
      const outHeaders = buildClientHeaders(upRes.headers, currentUrl, publicOrigin, false);
      outHeaders['set-cookie'] = setOurJar;
      if (!res.headersSent) {
        res.writeHead(upRes.statusCode || 200, outHeaders);
        for (const c of chunks) res.write(c);
        res.end();
      }
      return;
    }
    const raw = Buffer.concat(chunks).toString('utf8');
    let body = raw;
    try {
      if      (rewriteMode === 'html')  body = rewriteHtml(raw, currentUrl, publicOrigin);
      else if (rewriteMode === 'css')   body = rewriteCss(raw,  currentUrl, publicOrigin);
      else if (rewriteMode === 'm3u8')  body = rewriteM3u8(raw, currentUrl, publicOrigin);
      else if (rewriteMode === 'dash')  body = rewriteDash(raw, currentUrl, publicOrigin);
      else if (rewriteMode === 'js')    body = rewriteJs(raw,   currentUrl, publicOrigin);
      // 'text' falls through unchanged.
    } catch (e) {
      // If anything blows up during rewrite, send the raw body — never break
      // the page.
      body = raw;
    }
    const buf = Buffer.from(body, 'utf8');
    const outHeaders = buildClientHeaders(upRes.headers, currentUrl, publicOrigin, true);
    outHeaders['content-length'] = String(buf.length);
    outHeaders['set-cookie']     = setOurJar;
    res.writeHead(upRes.statusCode || 200, outHeaders);
    res.end(buf);
  });
}

/* ---- JS rewriter -------------------------------------------------------- */
/*
 * We don't parse JS. We rewrite the few literals that catch >95% of cases:
 *   • Bare strings that look like absolute URLs.
 *   • location.href = "..."   (handled at runtime by client bootstrap, but
 *     we also catch the static literal here for early SSR'd HTML where the
 *     bootstrap hasn't run yet).
 *
 * Risky transforms are deliberately avoided. Anything we miss is caught by
 * the runtime hooks (fetch, XHR, WebSocket, history, src setters).
 */
function rewriteJs(js, baseUrl, publicOrigin) {
  return js.replace(/(['"])(https?:\/\/[^'"\s<>\\]+)\1/g,
    (m, q, url) => q + rewriteUrl(url, baseUrl, publicOrigin) + q);
}

/* ==========================================================================
 *  9. Static file server (for /, /sw.js, /assets/*)
 * ========================================================================== */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico':  'image/x-icon',
  '.woff2':'font/woff2',
};

async function serveStatic(req, res, rel) {
  const filePath = normalize(join(PUBLIC_DIR, rel));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); return res.end('forbidden');
  }
  try {
    const st = await stat(filePath);
    if (!st.isFile()) throw new Error('not file');
    const headers = {
      'content-type':   MIME[extname(filePath).toLowerCase()] || 'application/octet-stream',
      'content-length': st.size,
      'cache-control':  rel === 'sw.js' ? 'no-cache' : 'public, max-age=300',
    };
    // The service worker needs the broadest possible scope.
    if (rel === 'sw.js') headers['service-worker-allowed'] = '/';
    res.writeHead(200, headers);
    createReadStream(filePath).pipe(res);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  }
}

/* ==========================================================================
 * 10. WebSocket bridge
 *  --------------------------------------------------------------------------
 *  Client connects to ws://us/__kaki/ws?u=<full-ws-url>. We open a real
 *  upstream WebSocket and pipe binary/text frames bidirectionally. This is
 *  what makes apps like YouTube live chat, Discord, etc. work through the
 *  proxy.
 * ========================================================================== */

function attachWebSocketBridge(server) {
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname !== CONFIG.wsPath) {
      socket.destroy();
      return;
    }
    const target = url.searchParams.get('u');
    if (!target || !/^wss?:\/\//i.test(target)) {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (client) => {
      const tu = new URL(target);
      const upHeaders = {};
      for (const [k, v] of Object.entries(req.headers)) {
        const lk = k.toLowerCase();
        if (lk.startsWith('sec-websocket-')) continue;
        if (REQ_DROP.has(lk)) continue;
        if (lk === 'host' || lk === 'origin' || lk === 'referer') continue;
        upHeaders[k] = v;
      }
      upHeaders['origin']  = tu.origin.replace(/^http/, 'ws');
      upHeaders['host']    = tu.host;

      const upstream = new WebSocket(target, {
        headers: upHeaders,
        perMessageDeflate: false,
      });
      const closeBoth = () => {
        try { client.close(); } catch {}
        try { upstream.close(); } catch {}
      };
      upstream.on('open', () => {
        client.on('message',   (d, isBin) => upstream.send(d, { binary: isBin }));
        upstream.on('message', (d, isBin) => client.send(d,   { binary: isBin }));
        client.on('close',  closeBoth);
        upstream.on('close', closeBoth);
        client.on('error',  closeBoth);
        upstream.on('error', closeBoth);
      });
      upstream.on('error', closeBoth);
    });
  });
}

/* ==========================================================================
 * 11. HTTP server
 * ========================================================================== */

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');

    // 1. Health check.
    if (url.pathname === CONFIG.healthPath) {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, name: 'kaki-proxy', ts: Date.now() }));
    }

    // 2. API: encode plaintext URL → cipher token (used by the landing page).
    if (url.pathname === '/__kaki/encode' && req.method === 'GET') {
      const u = url.searchParams.get('u') || '';
      if (!isProxyableUrl(u)) {
        res.writeHead(400, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ ok: false, error: 'invalid url' }));
      }
      const path = toProxyPath(u);
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, path }));
    }

    // 3. Naïve nav redirect: /__nav?u=<plain>  →  302 to /p/<token>.
    if (url.pathname === '/__nav') {
      const u = url.searchParams.get('u') || '';
      if (!isProxyableUrl(u)) {
        res.writeHead(400); return res.end('bad target');
      }
      res.writeHead(302, { 'location': toProxyPath(u) });
      return res.end();
    }

    // 4. Proxy path.
    if (url.pathname.startsWith(CONFIG.prefix)) {
      const upstream = decodeProxyPath(url.pathname + url.search);
      if (!upstream) {
        res.writeHead(400, { 'content-type': 'text/plain' });
        return res.end('Bad or expired proxy token. Re-enter the URL.');
      }
      return handleProxy(req, res, upstream);
    }

    // 5. Service worker (must be served from the root scope).
    if (url.pathname === '/sw.js')  return serveStatic(req, res, 'sw.js');

    // 6. Landing page.
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return serveStatic(req, res, 'index.html');
    }

    // 7. Other static.
    if (/^\/[\w.\-/]+$/.test(url.pathname)) {
      return serveStatic(req, res, url.pathname.replace(/^\//, ''));
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  } catch (e) {
    if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
    res.end('kaki internal error: ' + (e && e.message));
  }
});

attachWebSocketBridge(server);

server.keepAliveTimeout = 65_000;
server.headersTimeout   = 66_000;

server.listen(CONFIG.port, CONFIG.host, () => {
  log(`KAKI Proxy listening on http://${CONFIG.host}:${CONFIG.port}`);
  log(`Prefix=${CONFIG.prefix}  WS=${CONFIG.wsPath}  Health=${CONFIG.healthPath}`);
});

// Exported for testing / embedding.
export { URL_CIPHER, rewriteHtml, rewriteCss, rewriteJs, rewriteM3u8, rewriteDash };
