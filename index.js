/**
 * YouTube googlevideo Raw Stream URL Extraction API
 * Endpoint: GET /stream/:videoId  →  全ての再生可能ストリームをJSONで返す
 */
'use strict';

const express = require('express');
const { request: undiciRequest, Agent, setGlobalDispatcher } = require('undici');

setGlobalDispatcher(new Agent({
  connections: 64,
  keepAliveTimeout: 30_000,
  keepAliveMaxTimeout: 60_000,
  headersTimeout: 20_000,
  bodyTimeout: 30_000
}));

let YTJS = null;
const sessions = new Map();

async function loadYTJS() {
  if (YTJS) return YTJS;
  const mod = await import('youtubei.js');
  if (mod.Platform && mod.Platform.shim) {
    mod.Platform.shim.eval = async (data) => new Function(data.output)();
  }
  YTJS = mod;
  return mod;
}

async function getSession(clientType) {
  if (sessions.has(clientType)) return sessions.get(clientType);
  const p = (async () => {
    const { Innertube } = await loadYTJS();
    return Innertube.create({
      client_type: clientType,
      retrieve_player: true,
      generate_session_locally: false,
      enable_session_cache: true
    });
  })().catch((err) => { sessions.delete(clientType); throw err; });
  sessions.set(clientType, p);
  return p;
}

const CLIENT_PRIORITY = [
  { key: 'IOS',          label: 'iOS' },
  { key: 'ANDROID',      label: 'ANDROID' },
  { key: 'MWEB',         label: 'MWEB' },
  { key: 'TV',           label: 'TVHTML5' },
  { key: 'TV_EMBEDDED',  label: 'TVHTML5_SIMPLY_EMBEDDED_PLAYER' },
  { key: 'WEB_EMBEDDED', label: 'WEB_EMBEDDED_PLAYER' },
  { key: 'WEB',          label: 'WEB' }
];

const VIDEO_ID_RE = /^[A-Za-z0-9_-]{11}$/;

function parseExpire(url) {
  try {
    const u = new URL(url);
    const expire = u.searchParams.get('expire');
    return expire ? parseInt(expire, 10) * 1000 : 0;
  } catch (_) { return 0; }
}

function isGooglevideo(url) {
  return typeof url === 'string' && /\.googlevideo\.com\//.test(url);
}

async function probeUrl(url, timeoutMs = 6000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await undiciRequest(url, {
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
        range: 'bytes=0-1',
        'accept-language': 'en-US,en;q=0.9'
      },
      signal: ac.signal,
      maxRedirections: 3
    });
    try { for await (const _ of res.body) { break; } } catch (_) {}
    return {
      ok: res.statusCode >= 200 && res.statusCode < 300,
      status: res.statusCode,
      contentLength: res.headers['content-length'] ? parseInt(res.headers['content-length'], 10) : null,
      contentType: res.headers['content-type'] || null
    };
  } catch (err) {
    return { ok: false, status: 0, error: String(err && err.message || err) };
  } finally { clearTimeout(t); }
}

function describeFormat(fmt, deciphered) {
  const out = {
    itag: fmt.itag,
    mime_type: fmt.mime_type || null,
    container: null,
    codecs: null,
    bitrate: fmt.bitrate || null,
    average_bitrate: fmt.average_bitrate || null,
    width: fmt.width || null,
    height: fmt.height || null,
    fps: fmt.fps || null,
    quality: fmt.quality || null,
    quality_label: fmt.quality_label || null,
    audio_quality: fmt.audio_quality || null,
    audio_sample_rate: fmt.audio_sample_rate || null,
    audio_channels: fmt.audio_channels || null,
    has_audio: !!fmt.has_audio,
    has_video: !!fmt.has_video,
    is_drc: !!fmt.is_drc,
    content_length: fmt.content_length || null,
    approx_duration_ms: fmt.approx_duration_ms || null,
    last_modified: fmt.last_modified || null,
    loudness_db: fmt.loudness_db ?? null,
    language: fmt.language || null,
    url: deciphered
  };
  if (fmt.mime_type) {
    const m = /^([^;]+);\s*codecs="([^"]+)"/.exec(fmt.mime_type);
    if (m) {
      out.container = m[1].split('/')[1] || null;
      out.codecs = m[2];
    }
  }
  return out;
}

function extractAllFormats(info, session) {
  const sd = info.streaming_data;
  if (!sd) return { combined: [], adaptive: [], hls: null, dash: null };

  const decipherSafe = (fmt) => {
    try { return fmt.decipher(session.player); }
    catch (err) { return fmt.url || null; }
  };

  const combined = (sd.formats || [])
    .map((f) => describeFormat(f, decipherSafe(f)))
    .filter((f) => f.url);

  const adaptive = (sd.adaptive_formats || [])
    .map((f) => describeFormat(f, decipherSafe(f)))
    .filter((f) => f.url);

  return {
    combined, adaptive,
    hls: sd.hls_manifest_url || null,
    dash: sd.dash_manifest_url || null
  };
}

const cache = new Map();

function cacheGet(videoId) {
  const e = cache.get(videoId);
  if (!e) return null;
  if (Date.now() >= e.expiresAt - 30_000) { cache.delete(videoId); return null; }
  return e.payload;
}

function cacheSet(videoId, payload) {
  let soonest = Infinity;
  const scan = (arr) => arr.forEach((f) => {
    const e = parseExpire(f.url);
    if (e && e < soonest) soonest = e;
  });
  scan(payload.formats.combined);
  scan(payload.formats.adaptive);
  if (!isFinite(soonest)) soonest = Date.now() + 5 * 60_000;
  cache.set(videoId, { payload, expiresAt: soonest });
}

async function resolveStreams(videoId, opts = {}) {
  const probe = opts.probe !== false;
  const attempts = [];

  for (const client of CLIENT_PRIORITY) {
    const attempt = { client: client.key, ok: false };
    try {
      const session = await getSession(client.key);
      const info = await session.getBasicInfo(videoId, client.key);

      const ps = info.playability_status;
      attempt.playability_status = ps ? { status: ps.status, reason: ps.reason || null } : null;

      if (ps && ps.status && ps.status !== 'OK') {
        attempt.error = ps.reason || `playability ${ps.status}`;
        attempts.push(attempt);
        continue;
      }

      const formats = extractAllFormats(info, session);
      const allUrls = [...formats.combined, ...formats.adaptive].filter((f) => isGooglevideo(f.url));

      if (allUrls.length === 0) {
        attempt.error = 'no googlevideo urls';
        attempts.push(attempt);
        continue;
      }

      if (probe) {
        const sample = [];
        if (formats.combined[0]) sample.push(formats.combined[0]);
        const vSample = formats.adaptive.find((f) => f.has_video && !f.has_audio);
        const aSample = formats.adaptive.find((f) => f.has_audio && !f.has_video);
        if (vSample) sample.push(vSample);
        if (aSample) sample.push(aSample);

        const probes = await Promise.all(sample.map((s) => probeUrl(s.url)));
        const okCount = probes.filter((p) => p.ok).length;
        attempt.probe = probes.map((p, i) => ({
          itag: sample[i].itag, status: p.status, ok: p.ok, content_length: p.contentLength
        }));

        if (okCount === 0) {
          attempt.error = 'all probed urls failed';
          attempts.push(attempt);
          continue;
        }
      }

      attempt.ok = true;
      attempts.push(attempt);

      const details = info.basic_info || {};
      return {
        ok: true,
        video_id: videoId,
        client_used: client.key,
        title: details.title || null,
        author: details.author || null,
        channel_id: details.channel_id || null,
        duration: details.duration || null,
        view_count: details.view_count || null,
        is_live: !!details.is_live,
        is_upcoming: !!details.is_upcoming,
        thumbnails: details.thumbnail || [],
        formats: {
          combined: formats.combined,
          adaptive: formats.adaptive,
          hls_manifest_url: formats.hls,
          dash_manifest_url: formats.dash
        },
        attempts
      };
    } catch (err) {
      attempt.error = String(err && (err.message || err.info) || err);
      attempts.push(attempt);
    }
  }

  return { ok: false, video_id: videoId, error: 'All InnerTube clients failed to return playable streams', attempts };
}

const app = express();
app.disable('x-powered-by');
app.set('etag', false);

app.use((req, res, next) => {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-methods', 'GET, OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.get('/', (_req, res) => {
  res.json({
    name: 'yt-stream-api',
    version: '1.0.0',
    endpoints: { stream: '/stream/:videoId', health: '/health' },
    notes: 'GET /stream/<11-char-videoId>?probe=0 to skip URL probing.'
  });
});

app.get('/health', (_req, res) => res.json({ ok: true, uptime: process.uptime() }));

app.get('/stream/:videoId', async (req, res) => {
  const { videoId } = req.params;
  if (!VIDEO_ID_RE.test(videoId)) {
    return res.status(400).json({ ok: false, error: 'invalid videoId (must be 11 chars [A-Za-z0-9_-])' });
  }
  const probe = req.query.probe !== '0' && req.query.probe !== 'false';
  const noCache = req.query.nocache === '1' || req.query.nocache === 'true';

  if (!noCache) {
    const hit = cacheGet(videoId);
    if (hit) return res.json({ ...hit, cached: true });
  }

  try {
    const out = await resolveStreams(videoId, { probe });
    if (out.ok && !noCache) cacheSet(videoId, out);
    res.status(out.ok ? 200 : 502).json({ ...out, cached: false });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err && err.message || err) });
  }
});

const PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`[yt-stream-api] listening on http://${HOST}:${PORT}`);
  });
}

module.exports = app;
