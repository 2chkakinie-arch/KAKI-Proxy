/*
 * yt-stream-api — Multi-platform YouTube googlevideo raw stream URL extraction API
 *
 * Endpoint: GET /stream/:videoId
 *   → 再生可能なすべてのストリームを JSON で返す
 *
 * 設計方針:
 *   1. yt.actions.execute('/player', ...) で複数 InnerTube クライアントの raw player レスポンスを取得
 *      （youtubei.js v17 の Format クラスは一部クライアントで url を正しく読まないバグがあるため raw を直接使う）
 *   2. PO Token 不要なクライアント (IOS / ANDROID_VR / ANDROID) を主軸にし、
 *      他の WEB 系クライアントもフォールバックとして試行
 *   3. @distube/ytdl-core を最終フォールバック
 *   4. すべての結果をマージし、itag でユニーク化
 *   5. オプションで HEAD/Range probe を実行し再生可能性を実際に確認
 *   6. ビデオID単位で短期キャッシュ（URL期限切れ前）
 */

'use strict';

const http = require('http');
const { URL } = require('url');
const { Innertube, ClientType } = require('youtubei.js');
const ytdl = require('@distube/ytdl-core');
const { request, Agent } = require('undici');

// ─── 設定 ────────────────────────────────────────────────────────────────
const PORT             = parseInt(process.env.PORT || '3000', 10);
const HOST             = process.env.HOST || '0.0.0.0';
const REQUEST_TIMEOUT  = parseInt(process.env.REQUEST_TIMEOUT_MS || '30000', 10);
const PROBE_TIMEOUT_MS = parseInt(process.env.PROBE_TIMEOUT_MS   || '6000',  10);
const CACHE_TTL_MS     = parseInt(process.env.CACHE_TTL_MS       || '180000', 10); // 3 min
const ENABLE_PROBE     = (process.env.ENABLE_PROBE  || 'true')  === 'true';
const ENABLE_YTDL_CORE = (process.env.ENABLE_YTDL_CORE || 'true') === 'true';
const PROBE_CONCURRENCY = parseInt(process.env.PROBE_CONCURRENCY || '12', 10);

// 試行するクライアント順 (URL 取得成功率が高い順)
const CLIENT_ORDER = [
  'IOS',           // ★ URL直返し、sig不要
  'ANDROID_VR',    // ★ URL直返し、sig不要、フォーマット多
  'ANDROID',       // adaptive 25件
  'WEB',
  'TV',
  'MWEB',
  'WEB_EMBEDDED',
  'TV_EMBEDDED',
  'WEB_CREATOR'
];

// ─── グローバルガード ─────────────────────────────────────────────────────
process.on('unhandledRejection', (reason) => {
  const msg = String((reason && (reason.message || reason)) || '').slice(0, 200);
  // 内部ログのみ
  if (process.env.DEBUG) console.error('[unhandledRejection]', msg);
});
process.on('uncaughtException', (err) => {
  if (process.env.DEBUG) console.error('[uncaughtException]', err?.message || err);
});

// ─── undici 共有ディスパッチャ ────────────────────────────────────────────
const sharedAgent = new Agent({
  connect: { timeout: 8000 },
  keepAliveTimeout: 30000,
  keepAliveMaxTimeout: 60000,
  pipelining: 1,
  connections: 64
});

// ─── キャッシュ ──────────────────────────────────────────────────────────
const cache = new Map(); // videoId -> { expiresAt, data }
function cacheGet(id) {
  const e = cache.get(id);
  if (!e) return null;
  if (Date.now() > e.expiresAt) { cache.delete(id); return null; }
  return e.data;
}
function cacheSet(id, data, ttl = CACHE_TTL_MS) {
  cache.set(id, { data, expiresAt: Date.now() + ttl });
  if (cache.size > 500) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
}

// ─── Innertube シングルトン ──────────────────────────────────────────────
let innertubePromise = null;
function getInnertube() {
  if (!innertubePromise) {
    innertubePromise = Innertube.create({
      retrieve_player: true,
      generate_session_locally: true
    }).catch(err => {
      innertubePromise = null;
      throw err;
    });
  }
  return innertubePromise;
}

// ─── ユーティリティ ──────────────────────────────────────────────────────
function withTimeout(promise, ms, label = 'op') {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${label} timeout ${ms}ms`)), ms);
    promise.then(v => { clearTimeout(t); resolve(v); },
                 e => { clearTimeout(t); reject(e); });
  });
}

function extractCodec(mime) {
  if (!mime) return null;
  const m = mime.match(/codecs="([^"]+)"/);
  return m ? m[1] : null;
}
function extractContainer(mime) {
  if (!mime) return null;
  const m = mime.match(/^([^;]+);/);
  return m ? m[1] : null;
}

function isValidVideoId(v) {
  return typeof v === 'string' && /^[A-Za-z0-9_-]{11}$/.test(v);
}

// ─── raw player レスポンスからフォーマットを正規化 ──────────────────────
function normalizeRawFormat(f, clientName, kind) {
  const url = f.url || null;
  if (!url || !/^https?:\/\//.test(url)) return null;

  const mime = f.mimeType || '';
  const container = extractContainer(mime);
  const codec     = extractCodec(mime);
  const hasVideo  = /^video\//.test(mime) || !!f.width;
  const hasAudio  = /^audio\//.test(mime) || !!f.audioQuality;

  return {
    itag: f.itag,
    url,
    mimeType: mime || null,
    codec,
    container,
    bitrate: f.bitrate ?? null,
    averageBitrate: f.averageBitrate ?? null,
    width: f.width ?? null,
    height: f.height ?? null,
    fps: f.fps ?? null,
    qualityLabel: f.qualityLabel ?? null,
    quality: f.quality ?? null,
    audioQuality: f.audioQuality ?? null,
    audioSampleRate: f.audioSampleRate ? parseInt(f.audioSampleRate, 10) : null,
    audioChannels: f.audioChannels ?? null,
    loudnessDb: f.loudnessDb ?? null,
    contentLength: f.contentLength ? parseInt(f.contentLength, 10) : null,
    approxDurationMs: f.approxDurationMs ? parseInt(f.approxDurationMs, 10) : null,
    hasVideo: !!hasVideo && !(/^audio\//.test(mime)),
    hasAudio: !!hasAudio && !(/^video\//.test(mime) && !f.audioQuality),
    isProgressive: hasVideo && hasAudio && kind === 'progressive',
    kind,
    initRange: f.initRange || null,
    indexRange: f.indexRange || null,
    sourceClients: [clientName]
  };
}

// ─── InnerTube クライアント別フェッチ ────────────────────────────────────
async function fetchFromInnertubeClient(yt, videoId, clientName) {
  try {
    const r = await withTimeout(
      yt.actions.execute('/player', {
        videoId,
        client: clientName
      }),
      REQUEST_TIMEOUT,
      `innertube/${clientName}`
    );
    const data = r?.data;
    if (!data) throw new Error('empty response');

    const playabilityStatus = data.playabilityStatus?.status || 'UNKNOWN';
    const sd = data.streamingData;
    if (!sd) {
      return {
        client: clientName,
        ok: false,
        reason: `no streamingData (status=${playabilityStatus})`,
        playabilityStatus,
        formats: []
      };
    }

    const progressives = (sd.formats || [])
      .map(f => normalizeRawFormat(f, clientName, 'progressive'))
      .filter(Boolean);
    const adaptives = (sd.adaptiveFormats || [])
      .map(f => normalizeRawFormat(f, clientName, 'adaptive'))
      .filter(Boolean);

    return {
      client: clientName,
      ok: true,
      playabilityStatus,
      videoDetails: data.videoDetails || null,
      expiresInSeconds: sd.expiresInSeconds ? parseInt(sd.expiresInSeconds, 10) : null,
      hlsManifestUrl: sd.hlsManifestUrl || null,
      dashManifestUrl: sd.dashManifestUrl || null,
      formats: [...progressives, ...adaptives]
    };
  } catch (e) {
    return {
      client: clientName,
      ok: false,
      reason: String(e.message || e).slice(0, 200),
      formats: []
    };
  }
}

// ─── @distube/ytdl-core フォールバック ───────────────────────────────────
async function fetchFromYtdlCore(videoId) {
  try {
    const info = await withTimeout(
      ytdl.getInfo(`https://www.youtube.com/watch?v=${videoId}`, {
        requestOptions: {
          headers: {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
          }
        }
      }),
      REQUEST_TIMEOUT,
      'ytdl-core'
    );
    const formats = (info.formats || [])
      .filter(f => f.url && /^https?:\/\//.test(f.url))
      .map(f => ({
        itag: f.itag,
        url: f.url,
        mimeType: f.mimeType || null,
        codec: extractCodec(f.mimeType) || f.codecs || null,
        container: f.container ? `video/${f.container}` : extractContainer(f.mimeType),
        bitrate: f.bitrate ?? null,
        averageBitrate: f.averageBitrate ?? null,
        width: f.width ?? null,
        height: f.height ?? null,
        fps: f.fps ?? null,
        qualityLabel: f.qualityLabel ?? null,
        quality: f.quality ?? null,
        audioQuality: f.audioQuality ?? null,
        audioSampleRate: f.audioSampleRate ? parseInt(f.audioSampleRate, 10) : null,
        audioChannels: f.audioChannels ?? null,
        loudnessDb: f.loudnessDb ?? null,
        contentLength: f.contentLength ? parseInt(f.contentLength, 10) : null,
        approxDurationMs: f.approxDurationMs ? parseInt(f.approxDurationMs, 10) : null,
        hasVideo: !!f.hasVideo,
        hasAudio: !!f.hasAudio,
        isProgressive: !!(f.hasVideo && f.hasAudio),
        kind: (f.hasVideo && f.hasAudio) ? 'progressive' : 'adaptive',
        initRange: f.initRange || null,
        indexRange: f.indexRange || null,
        sourceClients: ['YTDL_CORE']
      }));

    return {
      client: 'YTDL_CORE',
      ok: true,
      playabilityStatus: info.player_response?.playabilityStatus?.status || 'OK',
      videoDetails: info.videoDetails || null,
      expiresInSeconds: null,
      hlsManifestUrl: info.player_response?.streamingData?.hlsManifestUrl || null,
      dashManifestUrl: info.player_response?.streamingData?.dashManifestUrl || null,
      formats
    };
  } catch (e) {
    return {
      client: 'YTDL_CORE',
      ok: false,
      reason: String(e.message || e).slice(0, 200),
      formats: []
    };
  }
}

// ─── マージ & デデュープ ─────────────────────────────────────────────────
function mergeResults(results) {
  const byItag = new Map();
  for (const r of results) {
    if (!r.ok) continue;
    for (const f of r.formats) {
      if (!f || !f.itag || !f.url) continue;
      const existing = byItag.get(f.itag);
      if (!existing) {
        byItag.set(f.itag, { ...f, sourceClients: [...f.sourceClients] });
      } else {
        for (const c of f.sourceClients) {
          if (!existing.sourceClients.includes(c)) existing.sourceClients.push(c);
        }
      }
    }
  }
  const formats = [...byItag.values()];
  formats.sort((a, b) => {
    // 1) progressive first, then adaptive video, then audio
    const grp = (x) => x.isProgressive ? 0 : (x.hasVideo ? 1 : 2);
    const ga = grp(a), gb = grp(b);
    if (ga !== gb) return ga - gb;
    // 2) descending bitrate/resolution
    return (b.bitrate || 0) - (a.bitrate || 0);
  });
  return formats;
}

// ─── 再生可能性 probe ────────────────────────────────────────────────────
async function probeOne(url) {
  try {
    const res = await withTimeout(request(url, {
      method: 'GET',
      headers: {
        'range': 'bytes=0-1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
      },
      dispatcher: sharedAgent
    }), PROBE_TIMEOUT_MS, 'probe');
    const status = res.statusCode;
    try { await res.body.dump(); } catch (_) { /* ignore */ }
    return { ok: status >= 200 && status < 400, status };
  } catch (e) {
    return { ok: false, status: 0, reason: String(e.message || e).slice(0, 120) };
  }
}

async function probeAll(formats) {
  if (!ENABLE_PROBE || !formats.length) return formats;
  const queue = formats.slice();
  const workers = Array.from({ length: Math.min(PROBE_CONCURRENCY, queue.length) }, async () => {
    while (queue.length) {
      const f = queue.shift();
      if (!f) break;
      const p = await probeOne(f.url);
      f.probeStatus = p.status;
      f.playable = p.ok;
      if (!p.ok && p.reason) f.probeError = p.reason;
    }
  });
  await Promise.all(workers);
  return formats;
}

// ─── メインフロー ────────────────────────────────────────────────────────
async function getStreams(videoId, { skipCache = false, probe = ENABLE_PROBE } = {}) {
  if (!isValidVideoId(videoId)) {
    const err = new Error('invalid videoId');
    err.statusCode = 400;
    throw err;
  }

  if (!skipCache) {
    const cached = cacheGet(videoId);
    if (cached) return { ...cached, _cache: 'HIT' };
  }

  const started = Date.now();
  const yt = await getInnertube();

  // 並列で全クライアント試行
  const innertubePromises = CLIENT_ORDER.map(c => fetchFromInnertubeClient(yt, videoId, c));
  const ytdlPromise = ENABLE_YTDL_CORE ? fetchFromYtdlCore(videoId) : Promise.resolve(null);

  const results = (await Promise.all([...innertubePromises, ytdlPromise])).filter(Boolean);

  // 共通メタデータ (最初に成功したクライアントから)
  const firstOk = results.find(r => r.ok && r.videoDetails) || results.find(r => r.ok);
  if (!firstOk) {
    const err = new Error('all clients failed');
    err.statusCode = 502;
    err.details = results.map(r => ({ client: r.client, reason: r.reason }));
    throw err;
  }

  const vd = firstOk.videoDetails || {};
  const expiresInSeconds = results
    .map(r => r.expiresInSeconds)
    .filter(Boolean)
    .reduce((a, b) => a == null ? b : Math.min(a, b), null);

  const hlsManifestUrl  = results.find(r => r.hlsManifestUrl)?.hlsManifestUrl  || null;
  const dashManifestUrl = results.find(r => r.dashManifestUrl)?.dashManifestUrl || null;

  const merged = mergeResults(results);
  const probed = probe ? await probeAll(merged) : merged.map(f => ({ ...f, playable: null, probeStatus: null }));

  const playableCount = probed.filter(f => f.playable).length;
  const successfulClients = results.filter(r => r.ok && r.formats.length).map(r => r.client);
  const errors = results
    .filter(r => !r.ok)
    .map(r => ({ client: r.client, error: r.reason }));

  const out = {
    ok: true,
    videoId,
    elapsedMs: Date.now() - started,
    playabilityStatus: firstOk.playabilityStatus,
    videoDetails: {
      title: vd.title || null,
      author: vd.author || null,
      channelId: vd.channelId || null,
      lengthSeconds: vd.lengthSeconds ? parseInt(vd.lengthSeconds, 10) : null,
      viewCount: vd.viewCount ? parseInt(vd.viewCount, 10) : null,
      isLive: !!vd.isLive,
      isLiveContent: !!vd.isLiveContent,
      keywords: vd.keywords || [],
      shortDescription: vd.shortDescription || null,
      thumbnails: vd.thumbnail?.thumbnails || []
    },
    expiresInSeconds,
    expiresAt: expiresInSeconds ? new Date(Date.now() + expiresInSeconds * 1000).toISOString() : null,
    hlsManifestUrl,
    dashManifestUrl,
    successfulClients,
    triedClients: CLIENT_ORDER.concat(ENABLE_YTDL_CORE ? ['YTDL_CORE'] : []),
    totalCount: probed.length,
    playableCount,
    formats: probed,
    errors,
    _cache: 'MISS'
  };

  // URL期限切れ前にキャッシュ (最大3分 or expiresInSeconds-30秒の小さい方)
  const safeTtl = expiresInSeconds
    ? Math.max(15000, Math.min(CACHE_TTL_MS, (expiresInSeconds - 30) * 1000))
    : CACHE_TTL_MS;
  cacheSet(videoId, out, safeTtl);

  return out;
}

// ─── HTTP サーバ ─────────────────────────────────────────────────────────
function sendJSON(res, status, body) {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(json),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-store'
  });
  res.end(json);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      });
      return res.end();
    }

    const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = u.pathname;

    if (path === '/' || path === '/index') {
      return sendJSON(res, 200, {
        name: 'yt-stream-api',
        version: '1.0.0',
        endpoints: {
          '/stream/:videoId': 'Get all playable streams for a YouTube video',
          '/health': 'Health check',
          '/cache': 'Cache statistics'
        },
        query: {
          probe: 'true|false (default: true) - HEAD-probe URLs to confirm playability',
          nocache: 'true|false (default: false) - bypass cache'
        }
      });
    }

    if (path === '/health') {
      return sendJSON(res, 200, {
        ok: true,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        clientOrder: CLIENT_ORDER,
        cacheSize: cache.size,
        ytdlCoreEnabled: ENABLE_YTDL_CORE,
        probeEnabled: ENABLE_PROBE
      });
    }

    if (path === '/cache') {
      const entries = [];
      for (const [k, v] of cache.entries()) {
        entries.push({ videoId: k, expiresInMs: Math.max(0, v.expiresAt - Date.now()) });
      }
      return sendJSON(res, 200, { size: cache.size, entries });
    }

    const streamMatch = path.match(/^\/stream\/([^/]+)\/?$/);
    if (streamMatch) {
      const videoId = streamMatch[1];
      if (!isValidVideoId(videoId)) {
        return sendJSON(res, 400, {
          ok: false,
          error: 'invalid videoId',
          hint: 'videoId must be 11 chars from [A-Za-z0-9_-]'
        });
      }
      const probe = u.searchParams.get('probe') !== 'false';
      const skipCache = u.searchParams.get('nocache') === 'true';
      try {
        const data = await getStreams(videoId, { skipCache, probe });
        return sendJSON(res, 200, data);
      } catch (e) {
        return sendJSON(res, e.statusCode || 500, {
          ok: false,
          videoId,
          error: e.message,
          details: e.details
        });
      }
    }

    return sendJSON(res, 404, { ok: false, error: 'not found', path });
  } catch (e) {
    return sendJSON(res, 500, { ok: false, error: e.message });
  }
});

// ─── 起動 (serverless 環境では起動しない) ─────────────────────────────────
if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[yt-stream-api] listening on http://${HOST}:${PORT}`);
    console.log(`[yt-stream-api] clients: ${CLIENT_ORDER.join(', ')}`);
    // Innertube を事前ウォームアップ
    getInnertube()
      .then(() => console.log('[yt-stream-api] innertube ready'))
      .catch(e => console.error('[yt-stream-api] innertube init failed:', e.message));
  });
}

// serverless ハンドラ (Vercel など)
module.exports = (req, res) => server.emit('request', req, res);
module.exports.server = server;
module.exports.getStreams = getStreams;
