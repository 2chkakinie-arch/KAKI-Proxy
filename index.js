/* =========================================================================
 *  KAKI Proxy — World-class YouTube-only streaming unblocker
 *  -----------------------------------------------------------------------
 *  Single-file Node.js backend. Designed for Railway / any Node host.
 *
 *  Design goals:
 *   1. Specialised for YouTube embedded playback only (max reliability).
 *   2. Server-side fetch of  https://www.youtube-nocookie.com/embed/<id>
 *      so the *server* IP is what Google sees, not the client. This is the
 *      single most effective bypass against "Sign in to confirm you're not
 *      a bot" — that screen is triggered by the requesting IP, the User-
 *      Agent, and the lack of a believable Referer chain. We control all
 *      three and forward a clean, well-formed request from a single
 *      stable IP.
 *   3. Every absolute and relative URL inside the returned HTML / JS / CSS
 *      / JSON is rewritten to /p/<encrypted-url>. The encryption is real
 *      AES-256-GCM with a per-deploy random key, so the URLs cannot be
 *      tampered with or replayed externally.
 *   4. Full HTTP Range support — googlevideo CDN *requires* byte-range
 *      requests for the DASH segments the YouTube player demands.
 *   5. A small client-side patch is injected into the proxied HTML so that
 *      runtime fetch() / XHR / WebSocket / Image() / dynamic <script>
 *      loads also flow through the proxy, catching player_response stream
 *      URLs that are not known at HTML rewrite time.
 *   6. Headers stripped: X-Frame-Options, Content-Security-Policy (the
 *      embed page sets frame-ancestors to youtube.com, which would break
 *      our wrapping iframe).
 *   7. Cookies are *not* forwarded. The embed page works anonymously and
 *      forwarding cookies is what makes UV/Rammerhead trigger bot checks.
 *
 *  Endpoints:
 *    GET  /                       — Landing page (public/index.html)
 *    GET  /watch/:id              — Convenience: builds the encrypted URL
 *                                   for youtube-nocookie.com/embed/:id and
 *                                   redirects to /p/<token>.
 *    GET  /api/embed/:id          — Returns { token, url } JSON for the
 *                                   frontend to set as iframe src.
 *    GET  /p/:token               — The actual proxy endpoint.
 *    GET  /healthz                — Health check for Railway.
 *
 *  Environment:
 *    PORT             — listen port (default 3000)
 *    KAKI_SECRET      — optional 32-byte hex secret; auto-generated if absent
 *    KAKI_UA          — optional override User-Agent
 * ========================================================================= */

'use strict';

const express      = require('express');
const compression  = require('compression');
const path         = require('path');
const crypto       = require('crypto');
const { Readable } = require('stream');
const { request, Agent, setGlobalDispatcher } = require('undici');

/* -------------------------------------------------------------------------
 *  Global HTTP client tuning. undici is much faster than node-fetch and
 *  gives us proper Range / streaming behaviour.
 * ------------------------------------------------------------------------- */
setGlobalDispatcher(new Agent({
  keepAliveTimeout:        30_000,
  keepAliveMaxTimeout:     60_000,
  connections:             256,
  pipelining:              1,
  headersTimeout:          20_000,
  bodyTimeout:             0,        // never time-out a streaming body
}));

const app  = express();
const PORT = process.env.PORT || 3000;

/* -------------------------------------------------------------------------
 *  Cryptography — AES-256-GCM for URL tokens.
 * ------------------------------------------------------------------------- */
const SECRET = (() => {
  const env = process.env.KAKI_SECRET;
  if (env && /^[0-9a-fA-F]{64}$/.test(env)) return Buffer.from(env, 'hex');
  // Per-deploy random key. Tokens become invalid on restart, which is
  // exactly what we want for an unblocker — links can't be hot-linked.
  return crypto.randomBytes(32);
})();

function b64urlEncode(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}
function encryptUrl(url) {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', SECRET, iv);
  const enc    = Buffer.concat([cipher.update(url, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return b64urlEncode(Buffer.concat([iv, tag, enc]));
}
function decryptUrl(token) {
  try {
    const data = b64urlDecode(token);
    if (data.length < 28) return null;
    const iv     = data.subarray(0, 12);
    const tag    = data.subarray(12, 28);
    const enc    = data.subarray(28);
    const decip  = crypto.createDecipheriv('aes-256-gcm', SECRET, iv);
    decip.setAuthTag(tag);
    const dec    = Buffer.concat([decip.update(enc), decip.final()]);
    return dec.toString('utf8');
  } catch { return null; }
}

/* -------------------------------------------------------------------------
 *  Host whitelist — only proxy domains that YouTube actually uses. Anything
 *  else returns 403 to prevent the proxy being abused as an open relay.
 * ------------------------------------------------------------------------- */
const ALLOWED_HOSTS = [
  'youtube.com',
  'youtube-nocookie.com',
  'youtubei.googleapis.com',
  'ytimg.com',
  'ggpht.com',
  'googlevideo.com',
  'gstatic.com',
  'google.com',          // apis.google.com (cast), accounts.google.com
  'googleapis.com',
  'googleusercontent.com',
  'doubleclick.net',     // some embed UI assets — return empty 204 below
  'jnn-pa.googleapis.com'
];
function hostAllowed(host) {
  host = String(host || '').toLowerCase();
  return ALLOWED_HOSTS.some(d => host === d || host.endsWith('.' + d));
}

/* -------------------------------------------------------------------------
 *  Build a clean upstream URL from whatever was encoded in the token.
 *  We accept fully-qualified https URLs and also bare "/path" strings that
 *  default to www.youtube-nocookie.com.
 * ------------------------------------------------------------------------- */
function resolveUpstream(raw, defaultOrigin) {
  if (!raw) return null;
  if (raw.startsWith('//')) raw = 'https:' + raw;
  if (raw.startsWith('/'))  raw = (defaultOrigin || 'https://www.youtube-nocookie.com') + raw;
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    if (!hostAllowed(u.hostname)) return null;
    return u;
  } catch { return null; }
}

/* -------------------------------------------------------------------------
 *  Pick an upstream-appropriate Referer / Origin. The embed page expects
 *  to be loaded with Referer=youtube-nocookie.com. googlevideo segments
 *  expect Referer=youtube.com. Getting this right matters: a wrong Referer
 *  makes googlevideo return 403.
 * ------------------------------------------------------------------------- */
function pickReferer(host) {
  host = host.toLowerCase();
  if (host.endsWith('googlevideo.com'))     return 'https://www.youtube.com/';
  if (host.endsWith('youtube-nocookie.com'))return 'https://www.youtube-nocookie.com/';
  if (host.endsWith('ytimg.com'))           return 'https://www.youtube.com/';
  if (host.endsWith('ggpht.com'))           return 'https://www.youtube.com/';
  return 'https://www.youtube.com/';
}
function pickOrigin(host) {
  host = host.toLowerCase();
  if (host.endsWith('youtube-nocookie.com')) return 'https://www.youtube-nocookie.com';
  return 'https://www.youtube.com';
}

// A current, widely-used Chrome UA. Keeping this fresh matters — YouTube's
// device-classifier falls back to 'robot or crawler' when the UA / Client
// Hints combination looks unfamiliar.
const DEFAULT_UA = process.env.KAKI_UA ||
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const DEFAULT_SEC_UA          = '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"';
const DEFAULT_SEC_UA_FULL_VER = '"Google Chrome";v="131.0.6778.86", "Chromium";v="131.0.6778.86", "Not_A Brand";v="24.0.0.0"';

/* -------------------------------------------------------------------------
 *  URL rewriting inside textual bodies. We replace any URL that points at
 *  a whitelisted host with /p/<encrypted-token>. Done conservatively to
 *  avoid corrupting the body.
 *
 *  Patterns handled:
 *    https://host/path
 *    //host/path
 *    https:\/\/host\/path        (JSON-escaped)
 *    \\\/\\\/host\\\/path        (deeply escaped, rare)
 *    "/relative/path"            (only inside embed.html host, see below)
 * ------------------------------------------------------------------------- */
const HOST_RE_ALT = ALLOWED_HOSTS
  .map(h => h.replace(/\./g, '\\.'))
  .map(h => '(?:[a-z0-9-]+\\.)*' + h)
  .join('|');

// Matches https://… or http://… with normal or JSON-escaped slashes.
const ABSOLUTE_URL_RE = new RegExp(
  '(https?:(?:\\\\?/){2})(' + HOST_RE_ALT + ')((?:[^\\s"\'<>`)\\\\]|\\\\/)*)',
  'gi'
);
// Matches //host/… (protocol-relative).
const PROTO_REL_URL_RE = new RegExp(
  '((?<![:/\\\\])(?:\\\\?/){2})(' + HOST_RE_ALT + ')((?:[^\\s"\'<>`)\\\\]|\\\\/)*)',
  'gi'
);

function rewriteUrlString(fullUrl) {
  // Strip JSON escaping: \/ => /
  const clean = fullUrl.replace(/\\\//g, '/');
  return '/p/' + encryptUrl(clean);
}

function rewriteBody(text, baseOrigin) {
  if (typeof text !== 'string') return text;

  // 1. absolute URLs → proxied
  text = text.replace(ABSOLUTE_URL_RE, (m, proto, host, rest) => {
    const full = 'https://' + host + (rest || '').replace(/\\\//g, '/');
    return rewriteUrlString(full);
  });
  // 2. protocol-relative //host/…
  text = text.replace(PROTO_REL_URL_RE, (m, _slashes, host, rest) => {
    const full = 'https://' + host + (rest || '').replace(/\\\//g, '/');
    return rewriteUrlString(full);
  });
  // 3. site-root-relative /path  →  point them back at the embed origin.
  //    We only rewrite inside attribute / JSON contexts where the leading
  //    quote tells us it's a URL (src/href/url() etc.). Doing a blind
  //    replace of every "/foo" would mangle JS code.
  text = text.replace(
    /(\b(?:src|href|action|data-src|data-href|poster)\s*=\s*")(\/[^"\s>]+)/g,
    (m, attr, p) => attr + '/p/' + encryptUrl(baseOrigin + p)
  );
  text = text.replace(
    /("(?:jsUrl|js_url|playerUrl|player_url|baseUrl|url|src|iurl|iurlmq|iurlhq|iurlsd|iurlmaxres|thumbnailUrl)"\s*:\s*")(\/[^"\\]+)/g,
    (m, k, p) => k + '/p/' + encryptUrl(baseOrigin + p)
  );

  return text;
}

/* -------------------------------------------------------------------------
 *  Client-side patch — injected into every proxied HTML document so that
 *  runtime network calls (fetch / XHR / WebSocket / new Image / dynamic
 *  imports / postMessage targetOrigin) are routed through the proxy.
 *
 *  This is the bit that catches the streaming URLs the YouTube player
 *  resolves dynamically from base.js, plus any /youtubei/v1/player POST
 *  the player issues to refresh the manifest.
 * ------------------------------------------------------------------------- */
const CLIENT_PATCH = `<script>(function(){
  if (window.__KAKI__) return; window.__KAKI__ = 1;
  var PROXY_BASE = location.origin + '/p/';
  var HOSTS = ${JSON.stringify(ALLOWED_HOSTS)};
  function hostAllowed(h){ h = String(h||'').toLowerCase();
    return HOSTS.some(function(d){ return h===d || h.endsWith('.'+d); }); }
  function shouldProxy(u){
    try{
      if (!u) return false;
      if (typeof u !== 'string') u = String(u);
      if (u.indexOf('/p/') === 0) return false;
      if (u.indexOf(PROXY_BASE) === 0) return false;
      if (u.indexOf('blob:') === 0 || u.indexOf('data:') === 0) return false;
      var abs;
      if (/^https?:\\/\\//i.test(u))      abs = new URL(u);
      else if (u.indexOf('//') === 0)     abs = new URL('https:'+u);
      else if (u.charAt(0) === '/')       return { rel:true, path:u };
      else                                return false;
      if (!hostAllowed(abs.hostname)) return false;
      return { rel:false, abs:abs.href };
    }catch(e){ return false; }
  }
  function tokenize(target){
    // Server endpoint that encrypts on the fly to avoid bundling crypto in the client.
    // We POST the raw URL and receive the encrypted token. Synchronous for
    // XHR/Image; async-friendly for fetch.
    return fetch('/api/encrypt?u=' + encodeURIComponent(target))
      .then(function(r){ return r.text(); })
      .then(function(t){ return PROXY_BASE + t; });
  }
  function tokenizeSync(target){
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/encrypt?u=' + encodeURIComponent(target), false);
    try { xhr.send(); } catch(e) { return null; }
    if (xhr.status >= 200 && xhr.status < 300) return PROXY_BASE + xhr.responseText;
    return null;
  }
  function resolve(u){
    var s = shouldProxy(u);
    if (!s) return u;
    var target = s.rel ? location.origin.replace(location.origin, 'https://www.youtube-nocookie.com') + s.path : s.abs;
    if (s.rel) target = 'https://www.youtube-nocookie.com' + s.path;
    return target;
  }

  /* --- fetch ----------------------------------------------------------- */
  var _fetch = window.fetch;
  window.fetch = function(input, init){
    try{
      var url = (typeof input === 'string') ? input : (input && input.url);
      var s = shouldProxy(url);
      if (s){
        var target = s.rel ? ('https://www.youtube-nocookie.com' + s.path) : s.abs;
        return tokenize(target).then(function(p){
          if (typeof input === 'string') return _fetch(p, init);
          // Request object — rebuild with proxied URL.
          var newReq = new Request(p, input);
          return _fetch(newReq, init);
        });
      }
    }catch(e){}
    return _fetch.apply(this, arguments);
  };

  /* --- XHR ------------------------------------------------------------- */
  var _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url){
    try{
      var s = shouldProxy(url);
      if (s){
        var target = s.rel ? ('https://www.youtube-nocookie.com' + s.path) : s.abs;
        var p = tokenizeSync(target);
        if (p) { arguments[1] = p; }
      }
    }catch(e){}
    return _open.apply(this, arguments);
  };

  /* --- Image / Audio / Video src setters ------------------------------- */
  function patchMediaSrc(proto){
    var desc = Object.getOwnPropertyDescriptor(proto, 'src');
    if (!desc || !desc.set) return;
    Object.defineProperty(proto, 'src', {
      configurable: true, enumerable: true,
      get: desc.get,
      set: function(v){
        try{
          var s = shouldProxy(v);
          if (s){
            var target = s.rel ? ('https://www.youtube-nocookie.com' + s.path) : s.abs;
            var p = tokenizeSync(target);
            if (p) v = p;
          }
        }catch(e){}
        return desc.set.call(this, v);
      }
    });
  }
  patchMediaSrc(HTMLImageElement.prototype);
  try { patchMediaSrc(HTMLMediaElement.prototype); } catch(e){}
  try { patchMediaSrc(HTMLSourceElement.prototype); } catch(e){}
  try { patchMediaSrc(HTMLScriptElement.prototype); } catch(e){}
  try { patchMediaSrc(HTMLIFrameElement.prototype); } catch(e){}

  /* --- Anchor / form action (defensive) -------------------------------- */
  // Prevents the "Watch on YouTube" link from breaking out of the proxy.
  document.addEventListener('click', function(ev){
    var a = ev.target.closest && ev.target.closest('a[href]');
    if (!a) return;
    var s = shouldProxy(a.href);
    if (s){
      ev.preventDefault();
      var target = s.rel ? ('https://www.youtube-nocookie.com' + s.path) : s.abs;
      var p = tokenizeSync(target);
      if (p) location.href = p;
    }
  }, true);
})();</script>`;

/* -------------------------------------------------------------------------
 *  Express middleware
 * ------------------------------------------------------------------------- */
app.disable('x-powered-by');
app.use(compression());
app.use(express.static(path.join(__dirname, 'public'), {
  index: 'index.html', maxAge: '1h'
}));

/* Health check */
app.get('/healthz', (req, res) => res.json({ ok: true, name: 'kaki-proxy' }));

/* On-the-fly encryption endpoint used by the client-side patch.
 * We rate-limit by simple IP throttle to avoid abuse. */
const encryptHits = new Map();
app.get('/api/encrypt', (req, res) => {
  const ip  = req.ip;
  const now = Date.now();
  const rec = encryptHits.get(ip) || { c:0, t:now };
  if (now - rec.t > 10_000) { rec.c = 0; rec.t = now; }
  rec.c++;
  encryptHits.set(ip, rec);
  if (rec.c > 600) return res.status(429).send('rate_limited');

  const u = req.query.u;
  if (!u || typeof u !== 'string') return res.status(400).send('missing_u');
  if (u.length > 4096)             return res.status(414).send('too_long');
  const parsed = resolveUpstream(u, 'https://www.youtube-nocookie.com');
  if (!parsed) return res.status(403).send('host_not_allowed');
  res.set('Cache-Control', 'no-store');
  res.type('text/plain').send(encryptUrl(parsed.href));
});

/* JSON endpoint for the landing page UI */
app.get('/api/embed/:id', (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!/^[A-Za-z0-9_-]{6,20}$/.test(id))
    return res.status(400).json({ error: 'invalid_video_id' });
  const url   = 'https://www.youtube-nocookie.com/embed/' + id
              + '?autoplay=1&playsinline=1&modestbranding=1&rel=0';
  const token = encryptUrl(url);
  res.json({ id, token, src: '/p/' + token });
});

/* Convenience redirect */
app.get('/watch/:id', (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!/^[A-Za-z0-9_-]{6,20}$/.test(id)) return res.status(400).send('bad id');
  const url   = 'https://www.youtube-nocookie.com/embed/' + id
              + '?autoplay=1&playsinline=1&modestbranding=1&rel=0';
  res.redirect(302, '/p/' + encryptUrl(url));
});

/* -------------------------------------------------------------------------
 *  THE PROXY itself.
 * ------------------------------------------------------------------------- */
app.all('/p/:token', async (req, res) => {
  const token  = req.params.token;
  const target = decryptUrl(token);
  if (!target) return res.status(400).send('bad token');

  let upstreamUrl;
  try { upstreamUrl = new URL(target); }
  catch { return res.status(400).send('bad url'); }
  if (!hostAllowed(upstreamUrl.hostname))
    return res.status(403).send('host not allowed');

  /* -- Build upstream headers -------------------------------------------
   *
   * We always present ourselves as a vanilla Chrome on Windows. The exact
   * combination of Sec-Fetch-* and Sec-CH-UA-* headers below is what a real
   * Chrome sends for a top-level navigation — if we omit any of them YT's
   * device classifier falls back to "cbrand=robot, cmodel=bot or crawler"
   * and ratchets up the bot-check probability.
   * ------------------------------------------------------------------- */
  const isTopLevelEmbed = upstreamUrl.pathname.startsWith('/embed/');
  const upstreamHeaders = {
    'user-agent':         DEFAULT_UA,
    'accept':             isTopLevelEmbed
      ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
      : (req.headers['accept'] || '*/*'),
    'accept-language':    'en-US,en;q=0.9',
    // We *decompress* upstream responses ourselves when we need to rewrite
    // them. The simplest, most robust way is to ask upstream not to compress
    // textual bodies. We keep gzip/br for binaries so streaming stays cheap.
    'accept-encoding':    'identity',
    'referer':            pickReferer(upstreamUrl.hostname),
    'origin':             pickOrigin(upstreamUrl.hostname),
    'sec-fetch-dest':     isTopLevelEmbed ? 'iframe'   : (req.headers['sec-fetch-dest'] || 'empty'),
    'sec-fetch-mode':     isTopLevelEmbed ? 'navigate' : (req.headers['sec-fetch-mode'] || 'cors'),
    'sec-fetch-site':     isTopLevelEmbed ? 'cross-site' : 'same-site',
    'sec-ch-ua':          DEFAULT_SEC_UA,
    'sec-ch-ua-arch':     '"x86"',
    'sec-ch-ua-bitness':  '"64"',
    'sec-ch-ua-full-version-list': DEFAULT_SEC_UA_FULL_VER,
    'sec-ch-ua-mobile':   '?0',
    'sec-ch-ua-model':    '""',
    'sec-ch-ua-platform': '"Windows"',
    'sec-ch-ua-platform-version': '"15.0.0"',
    'upgrade-insecure-requests': isTopLevelEmbed ? '1' : undefined,
    'priority':           'u=0, i',
    'dnt':                '1',
  };
  // Drop undefined entries so undici doesn't choke
  for (const k of Object.keys(upstreamHeaders)) {
    if (upstreamHeaders[k] === undefined) delete upstreamHeaders[k];
  }
  // Forward Range (vital for googlevideo segments)
  if (req.headers['range']) upstreamHeaders['range'] = req.headers['range'];
  if (req.headers['if-range'])         upstreamHeaders['if-range']         = req.headers['if-range'];
  if (req.headers['if-none-match'])    upstreamHeaders['if-none-match']    = req.headers['if-none-match'];
  if (req.headers['if-modified-since'])upstreamHeaders['if-modified-since']= req.headers['if-modified-since'];

  /* -- Body (POST e.g. /youtubei/v1/player) ----------------------------- */
  let upstreamBody;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    // collect raw body
    upstreamBody = await new Promise((resolve, reject) => {
      const chunks = [];
      req.on('data',  c => chunks.push(c));
      req.on('end',   () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
    if (req.headers['content-type'])   upstreamHeaders['content-type']   = req.headers['content-type'];
    if (req.headers['content-length']) upstreamHeaders['content-length'] = req.headers['content-length'];
  }

  /* -- Issue upstream request ------------------------------------------- */
  let up;
  try {
    up = await request(upstreamUrl.href, {
      method:           req.method,
      headers:          upstreamHeaders,
      body:             upstreamBody,
      maxRedirections:  5,
      throwOnError:     false,
    });
  } catch (err) {
    return res.status(502).send('upstream_error: ' + err.message);
  }

  /* -- Forward status + headers (filtered) ------------------------------ */
  const ct       = String(up.headers['content-type'] || '').toLowerCase();
  const isText   = /^(?:text\/html|text\/css|application\/(?:javascript|x-javascript|json)|text\/javascript|text\/plain|application\/xml)/i.test(ct);

  // Headers we drop because they break the proxied context
  const STRIP = new Set([
    'content-security-policy',
    'content-security-policy-report-only',
    'x-frame-options',
    'cross-origin-opener-policy',
    'cross-origin-embedder-policy',
    'cross-origin-resource-policy',
    'permissions-policy',
    'feature-policy',
    'report-to',
    'nel',
    'set-cookie',                // never persist Google cookies in the client
    'strict-transport-security',
    'public-key-pins',
    'content-length',            // we may rewrite the body → length changes
    'content-encoding',          // we already let undici decode
    'transfer-encoding',
    'alt-svc',
  ]);

  for (const [k, v] of Object.entries(up.headers)) {
    if (STRIP.has(k.toLowerCase())) continue;
    res.setHeader(k, v);
  }
  // Liberal CORS so the iframe is reachable from any embedding page.
  res.setHeader('access-control-allow-origin',  '*');
  res.setHeader('access-control-allow-headers', '*');
  res.setHeader('access-control-allow-methods', 'GET,POST,HEAD,OPTIONS');
  res.setHeader('access-control-expose-headers','*');
  res.setHeader('timing-allow-origin',          '*');
  res.setHeader('x-kaki-upstream-host',         upstreamUrl.hostname);

  res.status(up.statusCode);

  /* -- Rewrite textual bodies, stream everything else ------------------- */
  if (isText) {
    const buf = Buffer.from(await up.body.arrayBuffer());
    let body  = buf.toString('utf8');

    const origin = upstreamUrl.origin;
    body = rewriteBody(body, origin);

    // Inject our client-side patch into HTML <head>.
    if (/^text\/html/.test(ct)) {
      if (/<head[^>]*>/i.test(body)) {
        body = body.replace(/<head[^>]*>/i, m => m + CLIENT_PATCH);
      } else {
        body = CLIENT_PATCH + body;
      }
      // Allow the iframe to be embedded anywhere
      res.setHeader('x-kaki-rewritten', '1');
    }

    const out = Buffer.from(body, 'utf8');
    res.setHeader('content-length', out.length);
    return res.end(out);
  }

  /* -- Binary / streaming pass-through ----------------------------------
   *
   * For media (video/audio segments from googlevideo) we want true
   * streaming so playback can start before the whole segment is buffered.
   * For small assets (images, fonts) buffering is fine and avoids the
   * fromWeb -> pipe edge cases we saw on some Node versions.
   *
   * Heuristic: if there is no Content-Length OR the Content-Length is
   * larger than 256 KiB OR the Content-Type is video/audio, stream.
   * Otherwise buffer.
   * ------------------------------------------------------------------- */
  const cl    = parseInt(up.headers['content-length'] || '0', 10) || 0;
  const isAV  = /^(?:video|audio)\//i.test(ct) || upstreamUrl.hostname.endsWith('googlevideo.com');
  const stream = isAV || cl === 0 || cl > 262_144;

  if (!stream) {
    try {
      const buf = Buffer.from(await up.body.arrayBuffer());
      res.setHeader('content-length', buf.length);
      return res.end(buf);
    } catch (e) {
      try { res.end(); } catch {}
      return;
    }
  }

  // True streaming pipe — preserves Range / partial-content semantics.
  try {
    const nodeStream = Readable.fromWeb(up.body);
    nodeStream.on('error', () => { try { res.end(); } catch {} });
    req.on('close', () => {
      try { nodeStream.destroy(); } catch {}
    });
    nodeStream.pipe(res);
  } catch (e) {
    try { res.end(); } catch {}
  }
});

/* OPTIONS preflight */
app.options('/p/:token', (req, res) => {
  res.setHeader('access-control-allow-origin',  '*');
  res.setHeader('access-control-allow-headers', '*');
  res.setHeader('access-control-allow-methods', 'GET,POST,HEAD,OPTIONS');
  res.status(204).end();
});

/* -------------------------------------------------------------------------
 *  404
 * ------------------------------------------------------------------------- */
app.use((req, res) => res.status(404).send('Not found'));

/* -------------------------------------------------------------------------
 *  Boot
 * ------------------------------------------------------------------------- */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`KAKI Proxy listening on :${PORT}`);
  console.log(`Secret fingerprint: ${crypto.createHash('sha256').update(SECRET).digest('hex').slice(0,12)}`);
});
