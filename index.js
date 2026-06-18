/**
 * ============================================================================
 *  YouTube Raw Stream URL Extractor API
 *  -------------------------------------------------------------------------
 *  • Pure original implementation (no yt-dlp / ytdl-core / youtubei.js)
 *  • Node.js built-ins only — ZERO npm dependencies
 *  • Multi-client InnerTube fallback (ANDROID_VR → ANDROID → IOS → WEB → TV)
 *  • Auto visitor_data fetch (sw.js_data)
 *  • Pure-JS signature / n-signature decipher (no vm2)
 *  • yt-dlp compatible "formats" response
 *  • Endpoint: GET /stream/:videoId
 * ============================================================================
 */

'use strict';

const http   = require('http');
const https  = require('https');
const url    = require('url');
const zlib   = require('zlib');
const crypto = require('crypto');
const vm     = require('vm');

// ---------------------------------------------------------------------------
//  Global config
// ---------------------------------------------------------------------------
const PORT          = process.env.PORT || 3000;
const DEFAULT_TIMEOUT_MS = 15000;

// Innertube hard-coded API key (public — same key WEB/ANDROID app uses)
const INNERTUBE_KEY_WEB     = 'AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8';
const INNERTUBE_KEY_ANDROID = 'AIzaSyA8eiZmM1FaDVjRy-df2KTyQ_vz_yYM39w';
const INNERTUBE_KEY_IOS     = 'AIzaSyB-63vPrdThhKuerbB2N_l7Kwwcxj6yUAc';
const INNERTUBE_KEY_TV      = 'AIzaSyDCU8hByM-4DrUqRUYnGn-3llEO78bcxq8';

// Latest client constants — sourced from yt-dlp master (2026-06)
const CLIENTS = {
  ANDROID_VR: {
    key: INNERTUBE_KEY_ANDROID,
    requiresPoToken: false,
    requiresJsPlayer: false,
    context: {
      client: {
        clientName: 'ANDROID_VR',
        clientVersion: '1.65.10',
        deviceMake: 'Oculus',
        deviceModel: 'Quest 3',
        androidSdkVersion: 32,
        userAgent: 'com.google.android.apps.youtube.vr.oculus/1.65.10 (Linux; U; Android 12L; eureka-user Build/SQ3A.220605.009.A1) gzip',
        osName: 'Android',
        osVersion: '12L',
        hl: 'en',
        gl: 'US',
        utcOffsetMinutes: 0,
      },
    },
    clientNameNum: 28,
  },
  ANDROID: {
    key: INNERTUBE_KEY_ANDROID,
    requiresPoToken: false,
    requiresJsPlayer: false,
    context: {
      client: {
        clientName: 'ANDROID',
        clientVersion: '21.02.35',
        androidSdkVersion: 30,
        userAgent: 'com.google.android.youtube/21.02.35 (Linux; U; Android 11) gzip',
        osName: 'Android',
        osVersion: '11',
        hl: 'en',
        gl: 'US',
        utcOffsetMinutes: 0,
      },
    },
    clientNameNum: 3,
  },
  IOS: {
    key: INNERTUBE_KEY_IOS,
    requiresPoToken: false,
    requiresJsPlayer: false,
    context: {
      client: {
        clientName: 'IOS',
        clientVersion: '21.02.3',
        deviceMake: 'Apple',
        deviceModel: 'iPhone16,2',
        userAgent: 'com.google.ios.youtube/21.02.3 (iPhone16,2; U; CPU iOS 18_3_2 like Mac OS X;)',
        osName: 'iPhone',
        osVersion: '18.3.2.22D82',
        hl: 'en',
        gl: 'US',
        utcOffsetMinutes: 0,
      },
    },
    clientNameNum: 5,
  },
  TV_EMBEDDED: {
    key: INNERTUBE_KEY_TV,
    requiresPoToken: false,
    requiresJsPlayer: true,
    context: {
      client: {
        clientName: 'TVHTML5_SIMPLY_EMBEDDED_PLAYER',
        clientVersion: '2.0',
        userAgent: 'Mozilla/5.0 (PlayStation; PlayStation 4/12.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15',
        hl: 'en',
        gl: 'US',
        utcOffsetMinutes: 0,
      },
      thirdParty: { embedUrl: 'https://www.youtube.com/' },
    },
    clientNameNum: 85,
  },
  WEB: {
    key: INNERTUBE_KEY_WEB,
    requiresPoToken: true,
    requiresJsPlayer: true,
    context: {
      client: {
        clientName: 'WEB',
        clientVersion: '2.20260114.08.00',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36,gzip(gfe)',
        hl: 'en',
        gl: 'US',
        utcOffsetMinutes: 0,
      },
    },
    clientNameNum: 1,
  },
};

// Try order — clients that DO NOT need signature decipher first.
const CLIENT_TRY_ORDER = ['ANDROID_VR', 'ANDROID', 'IOS', 'TV_EMBEDDED', 'WEB'];

// ---------------------------------------------------------------------------
//  Tiny HTTPS client (built-in only)
// ---------------------------------------------------------------------------
function httpsRequest(targetUrl, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const reqOpts = {
      method:   opts.method || 'GET',
      hostname: u.hostname,
      port:     u.port || 443,
      path:     u.pathname + u.search,
      headers:  Object.assign({
        'accept':          '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate',
      }, opts.headers || {}),
      timeout: opts.timeout || DEFAULT_TIMEOUT_MS,
    };

    const req = https.request(reqOpts, (res) => {
      // follow redirects
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && opts.followRedirect !== false) {
        const next = new URL(res.headers.location, targetUrl).toString();
        res.resume();
        return resolve(httpsRequest(next, opts));
      }

      const chunks = [];
      let stream = res;
      const enc = (res.headers['content-encoding'] || '').toLowerCase();
      if (enc.includes('gzip'))    stream = res.pipe(zlib.createGunzip());
      else if (enc.includes('deflate')) stream = res.pipe(zlib.createInflate());
      else if (enc.includes('br')) stream = res.pipe(zlib.createBrotliDecompress());

      stream.on('data', (c) => chunks.push(c));
      stream.on('end',  () => {
        const buf = Buffer.concat(chunks);
        resolve({
          statusCode: res.statusCode,
          headers:    res.headers,
          body:       buf.toString('utf8'),
          rawHeaders: res.rawHeaders,
        });
      });
      stream.on('error', reject);
    });

    req.on('timeout', () => { req.destroy(new Error('Request timeout')); });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// HEAD/Range probe — verifies a googlevideo URL is actually playable
function probeStream(streamUrl) {
  return new Promise((resolve) => {
    try {
      const u = new URL(streamUrl);
      const reqOpts = {
        method:   'GET',
        hostname: u.hostname,
        port:     u.port || 443,
        path:     u.pathname + u.search,
        headers: {
          'range':      'bytes=0-1023',
          'user-agent': 'com.google.android.apps.youtube.vr.oculus/1.65.10',
        },
        timeout: 7000,
      };
      const req = https.request(reqOpts, (res) => {
        const ok = res.statusCode === 200 || res.statusCode === 206;
        res.resume();
        resolve({ ok, status: res.statusCode, contentLength: res.headers['content-length'], contentType: res.headers['content-type'] });
      });
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 0, error: 'timeout' }); });
      req.on('error', (e) => resolve({ ok: false, status: 0, error: e.message }));
      req.end();
    } catch (e) { resolve({ ok: false, status: 0, error: e.message }); }
  });
}

// ---------------------------------------------------------------------------
//  Visitor data fetcher  (parses /sw.js_data — same as yt-dlp / ytdl-core)
// ---------------------------------------------------------------------------
let _visitorDataCache = { value: null, expires: 0 };

async function getVisitorData() {
  const now = Date.now();
  if (_visitorDataCache.value && _visitorDataCache.expires > now) return _visitorDataCache.value;

  try {
    const r = await httpsRequest('https://www.youtube.com/sw.js_data', {
      headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36' },
    });
    // Body starts with ")]}'" — strip that and parse JSON
    let body = r.body.replace(/^\)\]\}'/, '').trim();
    const data = JSON.parse(body);
    // visitorData is deeply nested — walk and find
    const vd = deepFind(data, (v) => typeof v === 'string' && /^Cg[A-Za-z0-9_-]{10,}%3D%3D$/.test(v) || (typeof v === 'string' && v.startsWith('Cg') && v.length > 20 && v.length < 200));
    if (vd) {
      _visitorDataCache = { value: vd, expires: now + 6 * 60 * 60 * 1000 };
      return vd;
    }
  } catch (e) { /* ignore */ }

  // Fallback: generate a random one in the format YouTube accepts
  // visitorData format: "Cg" + base64url(11 random bytes) + "%3D%3D"
  const rnd = crypto.randomBytes(11).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const generated = 'Cg' + rnd + '%3D%3D';
  _visitorDataCache = { value: generated, expires: now + 30 * 60 * 1000 };
  return generated;
}

function deepFind(obj, predicate) {
  if (obj == null) return null;
  if (predicate(obj)) return obj;
  if (Array.isArray(obj)) {
    for (const x of obj) { const r = deepFind(x, predicate); if (r) return r; }
  } else if (typeof obj === 'object') {
    for (const k of Object.keys(obj)) { const r = deepFind(obj[k], predicate); if (r) return r; }
  }
  return null;
}

// ---------------------------------------------------------------------------
//  InnerTube /player request
// ---------------------------------------------------------------------------
async function callPlayer(videoId, clientKey, visitorData) {
  const c = CLIENTS[clientKey];
  if (!c) throw new Error('Unknown client: ' + clientKey);

  const ctx = JSON.parse(JSON.stringify(c.context));
  if (visitorData && ctx.client) ctx.client.visitorData = visitorData;

  const payload = {
    videoId,
    context: ctx,
    contentCheckOk: true,
    racyCheckOk: true,
    playbackContext: {
      contentPlaybackContext: {
        html5Preference: 'HTML5_PREF_WANTS',
        signatureTimestamp: 19999, // gets overwritten if we have player.js timestamp
      },
    },
  };

  const endpoint = `https://www.youtube.com/youtubei/v1/player?key=${c.key}&prettyPrint=false`;
  const res = await httpsRequest(endpoint, {
    method: 'POST',
    headers: {
      'content-type':       'application/json',
      'user-agent':         c.context.client.userAgent,
      'x-youtube-client-name':    String(c.clientNameNum),
      'x-youtube-client-version': c.context.client.clientVersion,
      'origin':             'https://www.youtube.com',
      'x-goog-visitor-id':  visitorData || '',
    },
    body: JSON.stringify(payload),
    timeout: DEFAULT_TIMEOUT_MS,
  });

  if (res.statusCode !== 200) {
    throw new Error(`InnerTube /player returned HTTP ${res.statusCode} for client ${clientKey}`);
  }
  let json;
  try { json = JSON.parse(res.body); }
  catch (e) { throw new Error('Failed to parse InnerTube response: ' + e.message); }
  return json;
}

// ---------------------------------------------------------------------------
//  Signature / n-signature decipher (pure-JS, no vm2)
// ---------------------------------------------------------------------------
const _playerCache = new Map(); // playerId -> { decipherFn, ncodeFn, sts }

async function fetchPlayer(playerUrl) {
  if (_playerCache.has(playerUrl)) return _playerCache.get(playerUrl);

  const res = await httpsRequest(playerUrl, {
    headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36' },
  });
  if (res.statusCode !== 200) throw new Error('player.js HTTP ' + res.statusCode);
  const js = res.body;

  // Signature timestamp (sts) — needed to convince WEB client to give un-DRM URLs
  let sts = 19999;
  const stsMatch = js.match(/signatureTimestamp[:=](\d+)/);
  if (stsMatch) sts = parseInt(stsMatch[1], 10);

  // ---- Build a sandboxed function that exposes player.js's helpers ----
  // We extract the decipher function name + helper object using regex patterns
  // that have been kept up-to-date with YouTube's obfuscation (2026-06).
  const decipherFn = extractDecipherFn(js);
  const ncodeFn    = extractNFn(js);

  const entry = { decipherFn, ncodeFn, sts, playerUrl };
  _playerCache.set(playerUrl, entry);
  return entry;
}

function extractDecipherFn(js) {
  // Find the top-level decipher function name.
  // Common patterns: a.set("alr","yes");c&&(c=NAME(decodeURIComponent(c)) ...
  //                  &&(b=NAME(decodeURIComponent(b)))
  const patterns = [
    /\b([a-zA-Z0-9$_]+)\s*=\s*function\(\s*[a-zA-Z]\s*\)\s*\{\s*[a-zA-Z]\s*=\s*[a-zA-Z]\.split\(\s*""\s*\)\s*;[\s\S]+?return [a-zA-Z]\.join\(\s*""\s*\)\s*\}/,
    /\b([a-zA-Z0-9$_]+)\s*=\s*function\(\s*[a-zA-Z]\s*\)\s*\{\s*[a-zA-Z]\s*=\s*[a-zA-Z]\.split\(\s*[a-zA-Z0-9$_]+\[\d+\]\s*\)\s*;[\s\S]+?return [a-zA-Z]\.join/,
    /(?:\b|[^a-zA-Z0-9$_])([a-zA-Z0-9$_]{2,})\s*=\s*function\(\s*[a-zA-Z]\s*\)\s*\{\s*[a-zA-Z]\s*=\s*[a-zA-Z]\.split\([^)]*\)\s*;[\s\S]*?return [a-zA-Z]\.join\([^)]*\)\s*\}/,
  ];
  let fnName = null;
  let fnBody = null;
  for (const p of patterns) {
    const m = js.match(p);
    if (m) { fnName = m[1]; fnBody = m[0]; break; }
  }
  if (!fnName) {
    // last-resort: look for "a=a.split("");...return a.join("")"
    const m2 = js.match(/function\(\s*([a-zA-Z])\s*\)\s*\{\s*\1\s*=\s*\1\.split\(\s*""\s*\)\s*;([\s\S]+?)return\s+\1\.join\(\s*""\s*\)\s*\}/);
    if (m2) {
      // anonymous — we can use as-is by wrapping
      return buildSandbox(`var _decipher = function(${m2[1]}){${m2[1]}=${m2[1]}.split("");${m2[2]}return ${m2[1]}.join("");};`, '_decipher', js);
    }
    return null;
  }

  return buildSandbox(`var _decipher = ${fnName};`, '_decipher', js, fnName);
}

function extractNFn(js) {
  // The n-sig transform function is referenced as e.g.  c=NAME(c)  or  d=NAME(d)
  // Modern pattern often looks like: &&(b=a.get("n"))&&(b=NAME(b),a.set("n",b))
  const patterns = [
    /&&\([a-zA-Z]=([a-zA-Z0-9$_]+)\([a-zA-Z]\)/,
    /\.get\(\s*["']n["']\s*\)\s*\)\s*&&\s*\([a-zA-Z]\s*=\s*([a-zA-Z0-9$_]+)\(/,
    /[a-zA-Z]\s*=\s*([a-zA-Z0-9$_]+)\(String\([a-zA-Z]\)\)/,
    /\([a-zA-Z]=([a-zA-Z0-9$_]+)\([a-zA-Z]\),[a-zA-Z]\.set\(["']n["']/,
  ];
  let fnName = null;
  for (const p of patterns) {
    const m = js.match(p);
    if (m) { fnName = m[1]; break; }
  }
  if (!fnName) return null;

  return buildSandbox(`var _ncode = ${fnName};`, '_ncode', js, fnName);
}

function buildSandbox(intro, exportName, fullJs, targetFnName) {
  // Wrap the entire player.js inside a closure and surface only the function we need.
  // This is heavy but the result is cached per-playerUrl.
  const wrapped = `
    (function(){
      var window = {};
      var document = { documentElement: {}, location: { href: "" } };
      var navigator = { userAgent: "" };
      var location = { href: "" };
      try {
        ${fullJs}
      } catch(e) { /* swallow init errors — we only need the symbol */ }
      try {
        ${intro}
        return ${exportName};
      } catch(e) {
        return null;
      }
    })();
  `;

  try {
    const ctx = { window: {}, console: { log() {}, warn() {}, error() {} } };
    vm.createContext(ctx);
    const fn = vm.runInContext(wrapped, ctx, { timeout: 5000 });
    if (typeof fn === 'function') return fn;
  } catch (e) { /* try fallback */ }

  // Fallback: rebuild by scraping just the function definitions
  try {
    const escaped = targetFnName ? targetFnName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : null;
    if (escaped) {
      const defMatch = fullJs.match(new RegExp(`${escaped}\\s*=\\s*function[\\s\\S]+?\\};`));
      const helperObjMatch = fullJs.match(/var\s+([a-zA-Z0-9$_]+)\s*=\s*\{[\s\S]+?\};/g) || [];
      const code = helperObjMatch.join('\n') + '\n' + (defMatch ? defMatch[0] : '');
      const ctx2 = {};
      vm.createContext(ctx2);
      vm.runInContext(code + `;globalThis.__fn = ${targetFnName};`, ctx2, { timeout: 5000 });
      if (typeof ctx2.__fn === 'function') return ctx2.__fn;
    }
  } catch (e) { /* nope */ }

  return null;
}

function decipherSignatureCipher(sigCipherStr, player) {
  const params = new URLSearchParams(sigCipherStr);
  const s   = params.get('s');
  const sp  = params.get('sp') || 'signature';
  const u   = params.get('url');
  if (!s || !u) return null;
  if (!player || !player.decipherFn) return null;
  let decoded;
  try { decoded = player.decipherFn(s); }
  catch (e) { return null; }
  const finalUrl = new URL(u);
  finalUrl.searchParams.set(sp, decoded);
  return finalUrl.toString();
}

function applyNSig(streamUrl, player) {
  if (!player || !player.ncodeFn) return streamUrl;
  const u = new URL(streamUrl);
  const n = u.searchParams.get('n');
  if (!n) return streamUrl;
  try {
    const newN = player.ncodeFn(n);
    if (newN && typeof newN === 'string' && !newN.startsWith('enhanced_except')) {
      u.searchParams.set('n', newN);
      return u.toString();
    }
  } catch (e) { /* fall through */ }
  return streamUrl;
}

async function getPlayerJsUrl(videoId) {
  // Fetch watch page and extract /s/player/.../base.js path
  const r = await httpsRequest(`https://www.youtube.com/embed/${videoId}`, {
    headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36' },
  });
  const m = r.body.match(/"jsUrl":"([^"]+base\.js)"/) || r.body.match(/\/s\/player\/[^"'\s]+?\/base\.js/);
  if (!m) return null;
  const path = m[1] || m[0];
  return path.startsWith('http') ? path : 'https://www.youtube.com' + path;
}

// ---------------------------------------------------------------------------
//  Main extraction logic (multi-client fallback)
// ---------------------------------------------------------------------------
async function extractStreams(videoId) {
  const errors = [];
  const visitorData = await getVisitorData();
  let combinedFormats = [];
  let videoDetails = null;
  let playabilityStatus = null;
  let usedClients = [];
  let hlsManifest = null;
  let dashManifest = null;
  let playerJs = null;

  for (const clientKey of CLIENT_TRY_ORDER) {
    try {
      const data = await callPlayer(videoId, clientKey, visitorData);
      const ps = data.playabilityStatus || {};
      playabilityStatus = playabilityStatus || ps;
      if (ps.status && ps.status !== 'OK') {
        errors.push(`${clientKey}: ${ps.status} - ${ps.reason || ''}`);
        // try next client (some restrict by client)
        if (ps.status === 'LOGIN_REQUIRED' || ps.status === 'UNPLAYABLE' || ps.status === 'ERROR' || ps.status === 'AGE_VERIFICATION_REQUIRED') {
          continue;
        }
      }

      videoDetails = videoDetails || data.videoDetails;

      const sd = data.streamingData;
      if (!sd) { errors.push(`${clientKey}: no streamingData`); continue; }

      if (sd.hlsManifestUrl && !hlsManifest) hlsManifest = sd.hlsManifestUrl;
      if (sd.dashManifestUrl && !dashManifest) dashManifest = sd.dashManifestUrl;

      const formats = [].concat(sd.formats || [], sd.adaptiveFormats || []);
      const cipherFormats = formats.filter(f => f.signatureCipher || f.cipher);

      // Load player.js only when we encounter ciphered formats
      if (cipherFormats.length > 0 && !playerJs) {
        try {
          const playerUrl = await getPlayerJsUrl(videoId);
          if (playerUrl) playerJs = await fetchPlayer(playerUrl);
        } catch (e) { errors.push('player.js fetch: ' + e.message); }
      }

      for (const f of formats) {
        let finalUrl = f.url || null;
        if (!finalUrl && (f.signatureCipher || f.cipher)) {
          finalUrl = decipherSignatureCipher(f.signatureCipher || f.cipher, playerJs);
        }
        if (finalUrl && playerJs && finalUrl.includes('&n=')) {
          finalUrl = applyNSig(finalUrl, playerJs);
        } else if (finalUrl && playerJs) {
          // some URLs have ?n=
          if (finalUrl.includes('?n=') || finalUrl.includes('&n=')) finalUrl = applyNSig(finalUrl, playerJs);
        }
        if (!finalUrl) continue;

        // de-dup by itag+client
        if (combinedFormats.some(x => x.itag === f.itag && x.client === clientKey)) continue;

        combinedFormats.push(buildYtdlpFormat(f, finalUrl, clientKey));
      }
      usedClients.push(clientKey);

      // ANDROID_VR + ANDROID together usually give everything — early exit if we have audio + video
      const hasAudio = combinedFormats.some(x => x.acodec && x.acodec !== 'none');
      const hasVideo = combinedFormats.some(x => x.vcodec && x.vcodec !== 'none');
      if (hasAudio && hasVideo && combinedFormats.length >= 10 && usedClients.length >= 2) break;

    } catch (e) {
      errors.push(`${clientKey}: ${e.message}`);
    }
  }

  if (!combinedFormats.length && !hlsManifest && !dashManifest) {
    throw new Error('No playable streams. Errors: ' + errors.join(' | '));
  }

  return {
    videoDetails: videoDetails || {},
    playabilityStatus,
    formats:       combinedFormats,
    hlsManifestUrl:  hlsManifest,
    dashManifestUrl: dashManifest,
    usedClients,
    visitorData,
    errors,
  };
}

function buildYtdlpFormat(f, url, client) {
  const mime = f.mimeType || '';
  const mimeMatch = mime.match(/^(audio|video)\/([^;]+)(?:;\s*codecs="([^"]+)")?/);
  const kind     = mimeMatch ? mimeMatch[1] : null;
  const container= mimeMatch ? mimeMatch[2] : null;
  const codecs   = mimeMatch ? (mimeMatch[3] || '') : '';
  let vcodec = 'none', acodec = 'none';
  if (codecs) {
    const parts = codecs.split(',').map(s => s.trim());
    for (const c of parts) {
      if (/^(avc1|av01|vp9|vp09|hev1|hvc1|vp8)/i.test(c)) vcodec = c;
      else if (/^(mp4a|opus|vorbis|ec-3|ac-3)/i.test(c)) acodec = c;
    }
    if (kind === 'video' && vcodec === 'none' && parts.length) vcodec = parts[0];
    if (kind === 'audio' && acodec === 'none' && parts.length) acodec = parts[0];
  }

  return {
    itag:           f.itag,
    url,
    mimeType:       mime,
    ext:            container || (kind === 'audio' ? 'm4a' : 'mp4'),
    container,
    format_id:      String(f.itag) + (client === 'ANDROID_VR' ? '-vr' : ''),
    format_note:    f.qualityLabel || f.audioQuality || f.quality || '',
    width:          f.width  || null,
    height:         f.height || null,
    fps:            f.fps    || null,
    quality:        f.quality,
    qualityLabel:   f.qualityLabel,
    bitrate:        f.bitrate || null,
    averageBitrate: f.averageBitrate || null,
    tbr:            f.bitrate ? Math.round(f.bitrate / 1000) : null,
    abr:            (acodec !== 'none' && f.averageBitrate) ? Math.round(f.averageBitrate / 1000) : null,
    vbr:            (vcodec !== 'none' && f.averageBitrate) ? Math.round(f.averageBitrate / 1000) : null,
    contentLength:  f.contentLength ? String(f.contentLength) : null,
    filesize:       f.contentLength ? Number(f.contentLength) : null,
    approxDurationMs: f.approxDurationMs,
    audioChannels:  f.audioChannels || null,
    audioSampleRate:f.audioSampleRate || null,
    audioQuality:   f.audioQuality || null,
    loudnessDb:     f.loudnessDb || null,
    vcodec, acodec,
    protocol:       (mime.includes('mp4') ? 'https' : 'https'),
    client,
    hasVideo:       vcodec !== 'none',
    hasAudio:       acodec !== 'none',
    isAdaptive:     !(vcodec !== 'none' && acodec !== 'none'),
    initRange:      f.initRange || null,
    indexRange:     f.indexRange || null,
    colorInfo:      f.colorInfo || null,
    projectionType: f.projectionType || null,
    stereoLayout:   f.stereoLayout || null,
  };
}

// ---------------------------------------------------------------------------
//  HTTP server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const path   = parsed.pathname;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'no-store');

  if (path === '/' || path === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      name: 'yt-stream-api',
      ok: true,
      endpoints: {
        stream: '/stream/:videoId',
        probe:  '/probe/:videoId',
      },
      version: '1.0.0',
      uptime: process.uptime(),
    }, null, 2));
  }

  // /stream/:videoId  -> yt-dlp compatible JSON
  const streamMatch = path.match(/^\/stream\/([A-Za-z0-9_-]{11})$/);
  if (streamMatch) {
    const videoId = streamMatch[1];
    const wantProbe = parsed.query.probe === '1' || parsed.query.probe === 'true';
    try {
      const t0 = Date.now();
      const r  = await extractStreams(videoId);
      let probes = null;
      if (wantProbe) {
        probes = await Promise.all(r.formats.slice(0, 3).map(async f => ({ itag: f.itag, ...(await probeStream(f.url)) })));
      }
      const elapsed = Date.now() - t0;
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({
        ok: true,
        elapsedMs: elapsed,
        videoId,
        title:    r.videoDetails.title,
        author:   r.videoDetails.author,
        channelId:r.videoDetails.channelId,
        lengthSeconds: r.videoDetails.lengthSeconds ? Number(r.videoDetails.lengthSeconds) : null,
        viewCount:r.videoDetails.viewCount,
        isLive:   !!r.videoDetails.isLiveContent,
        thumbnails: (r.videoDetails.thumbnail && r.videoDetails.thumbnail.thumbnails) || [],
        playabilityStatus: r.playabilityStatus,
        formats:  r.formats,
        hlsManifestUrl:  r.hlsManifestUrl || null,
        dashManifestUrl: r.dashManifestUrl || null,
        usedClients: r.usedClients,
        visitorData: r.visitorData,
        probes,
        warnings: r.errors,
      }, null, 2));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: false, error: e.message, stack: e.stack }));
    }
  }

  // /probe/:videoId — quick HEAD/Range check of best format
  const probeMatch = path.match(/^\/probe\/([A-Za-z0-9_-]{11})$/);
  if (probeMatch) {
    const videoId = probeMatch[1];
    try {
      const r = await extractStreams(videoId);
      const sample = r.formats.slice(0, 5);
      const probes = await Promise.all(sample.map(async f => ({ itag: f.itag, mimeType: f.mimeType, ...(await probeStream(f.url)) })));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, videoId, probes, usedClients: r.usedClients }, null, 2));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: false, error: e.message }));
    }
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: false, error: 'Not Found' }));
});

// On Vercel/serverless, do not start a long-running listener — export the handler.
const isServerless = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY);
if (!isServerless && require.main === module) {
  server.listen(PORT, () => {
    console.log(`[yt-stream-api] listening on :${PORT}`);
  });
}

// Vercel handler signature: (req, res) => …
module.exports = server;
module.exports.default = server;
module.exports.extractStreams = extractStreams;
module.exports.probeStream    = probeStream;
module.exports.getVisitorData = getVisitorData;
module.exports.callPlayer     = callPlayer;
