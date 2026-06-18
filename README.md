# yt-stream-api

YouTube googlevideo raw stream URL extractor API — **pure original implementation**.
Zero npm dependencies (Node.js built-ins only). No `yt-dlp`, no `ytdl-core`, no `youtubei.js`.

## Endpoints

- `GET /stream/:videoId` — yt-dlp compatible JSON with `formats[]`, `hlsManifestUrl`, `dashManifestUrl`
- `GET /probe/:videoId`  — actively performs HEAD/Range probes on top formats and reports playability
- `GET /health`          — health check

## How it works

1. **Multi-client InnerTube fallback** — `ANDROID_VR → ANDROID → IOS → TV_EMBEDDED → WEB`.
   ANDROID_VR client is the primary because it does **not** require PO Token, does **not** require JS player, and returns un-ciphered stream URLs.
2. **Auto visitor_data** — fetched from `/sw.js_data` and cached for 6h. Falls back to deterministic generation if the endpoint is blocked.
3. **Pure-JS signature / n-signature decipher** — when a WEB / TV_EMBEDDED stream needs deciphering, `base.js` is fetched once and parsed by a vm-sandbox (no `vm2`).
4. **HEAD/Range probe** — `/probe/:videoId` confirms streams actually return HTTP 206 with valid `Content-Type`.
5. **Aggressive caching** — player.js decipher functions are cached per playerUrl. visitor_data cached for 6h.

## Deploy

| Platform | Config file       | Notes                                              |
|----------|-------------------|----------------------------------------------------|
| Vercel   | `vercel.json` + `api/`     | Serverless functions; 30 s max duration            |
| Railway  | `railway.json`    | Long-running; auto restart                         |
| Render   | `render.yaml`     | Free tier (sleeps after 15 min idle); port 10000   |
| Docker   | `Dockerfile`      | Fly.io / Koyeb / DigitalOcean App Platform / etc. |

## Sample response

```jsonc
{
  "ok": true,
  "elapsedMs": 256,
  "videoId": "60ItHLz5WEA",
  "title": "Alan Walker - Faded",
  "author": "Alan Walker",
  "lengthSeconds": 213,
  "formats": [
    {
      "itag": 137,
      "url": "https://rr3---sn-2onx5c-54.googlevideo.com/videoplayback?...",
      "mimeType": "video/mp4; codecs=\"avc1.640028\"",
      "ext": "mp4",
      "format_id": "137-vr",
      "qualityLabel": "1080p",
      "width": 1920, "height": 1080,
      "fps": 25,
      "bitrate": 2801690,
      "vcodec": "avc1.640028", "acodec": "none",
      "hasVideo": true, "hasAudio": false,
      "client": "ANDROID_VR"
    }
  ],
  "hlsManifestUrl":  null,
  "dashManifestUrl": null,
  "usedClients":     ["ANDROID_VR", "ANDROID"]
}
```

## Local dev

```bash
node index.js
curl http://localhost:3000/stream/60ItHLz5WEA
```
