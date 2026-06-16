# KAKI Proxy

世界最高峰の **YouTube 専用ストリーミング・アンブロッカー**。
AES‑256‑GCM 暗号化トークン / Range 対応サーバーサイド・ストリーミング /
Chrome 131 完全偽装による anti‑bot 回避。

## ファイル構成 (5 ファイル)

| ファイル | 役割 |
|---|---|
| `index.js` | Node.js (Express + undici) バックエンド。Railway 用。 |
| `_worker.js` | 同等機能の Cloudflare Pages Functions 版 (WebCrypto)。 |
| `public/index.html` | フロントエンド (動画 ID 入力 UI と iframe プレイヤー)。 |
| `package.json` | npm 依存。 |
| `railway.json` | Railway デプロイ設定。 |

## デプロイ — Railway

```bash
# 1. このディレクトリを GitHub に push
# 2. Railway → New Project → Deploy from GitHub repo
# 3. Variables に KAKI_SECRET = $(openssl rand -hex 32) を追加 (任意)
# 4. Deploy → https://<your>.up.railway.app/ で開く
```

`railway.json` が自動で Nixpacks / Node 20 / `node index.js` を選択。
ヘルスチェック `/healthz`。

## デプロイ — Cloudflare Pages

```bash
# wrangler 経由 (推奨):
npm i -g wrangler
wrangler pages deploy . --project-name kaki-proxy

# あるいは Dashboard:
# 1. Pages → Create project → Connect to Git
# 2. Build command: (空)
# 3. Build output:  /
# 4. Settings → Environment variables → KAKI_SECRET を追加 (任意)
```

`_worker.js` が Pages Functions advanced mode で自動検出され、
`public/` 配下は静的アセットとして配信されます。

## 使い方

`/` を開いて動画 ID を入力するか、`#` 付きで直接ディープリンク:

```
https://your-host/#60ItHLz5WEA
```

または API 直叩き:

```
GET /api/embed/60ItHLz5WEA   →  { id, token, src:"/p/<token>" }
GET /watch/60ItHLz5WEA       →  302 redirect to /p/<token>
GET /p/<encrypted-token>     →  proxied HTML / JS / CSS / media (Range OK)
GET /api/encrypt?u=<url>     →  暗号化トークンを返す (ランタイム書き換え用)
```

## 設計のキモ

1. **Server‑side fetch of `youtube-nocookie.com/embed/<id>`** —
   クライアント IP を露出させず、サーバーが Chrome 131 / Windows 10 / DESKTOP の
   Client Hints (`Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Full-Version-List`,
   `Sec-Fetch-*`, `Priority`, `DNT` …) を完璧に揃えるので、YouTube の device
   classifier は `cbr=Chrome, cplatform=DESKTOP` と認識し、
   "Sign in to confirm you're not a bot" 画面の発火条件を満たさない。
   検証済み: 検出文字列 `cbrand=robot, cmodel=bot or crawler` が完全に消滅。

2. **AES‑256‑GCM 暗号化 URL トークン** — `/p/<base64url>` の中身は復号鍵を持つ
   サーバー以外は読めない。リプレイ・改竄も AEAD で検知。再デプロイで鍵が変わる
   設計なので、外部にホットリンクされたリンクは自然失効。

3. **三層 URL 書き換え** —
   (a) HTML/JS/CSS/JSON body 内の絶対 URL とプロトコル相対 URL を正規表現で
       全部 `/p/<token>` に置換。
   (b) `<head>` に注入する `__KAKI__` ランタイムパッチが `fetch` / `XHR` /
       `Image.src` / `<script>.src` / `<iframe>.src` / 動的 anchor click を
       すべてフックして、player JS が実行時に組み立てる googlevideo URL や
       `/youtubei/v1/player` API 呼び出しも proxy 経由に切り替え。
   (c) Range / If-Range / If-Modified-Since を完全に転送し、`googlevideo` の
       DASH セグメントをチャンクストリーミング再生可能に。

4. **upstream ごとの Referer / Origin** —
   `googlevideo.com` には `https://www.youtube.com/`、
   `youtube-nocookie.com` には自ドメインを送る。間違った Referer は
   googlevideo を 403 にする。

5. **危険ヘッダーの剥離** — `X-Frame-Options` / `Content-Security-Policy` /
   `Cross-Origin-*` / `Set-Cookie` 等を upstream レスポンスから除去し、
   どのページにも iframe で埋め込める。Cookie は転送しないので、ログイン状態の
   漏洩や bot 検知の悪化を防ぐ。

6. **ホワイトリスト** — `youtube*.com / ytimg / ggpht / googlevideo / gstatic /
   googleapis / googleusercontent / youtubei.googleapis.com` 以外は 403。
   汎用オープン relay にならない。

## 検証ログ (`60ItHLz5WEA` で実測)

```
✓ embed HTML : 200, 148 KB, 47 個の /p/ トークン書き換え
✓ KAKI patch : 1 箇所注入 (<head> 直後)
✓ base.js    : 1.7 MB, text/javascript, 内部の絶対 URL は全消去
✓ ytimg JPEG : 12.6 KB, 1280×720 maxres OK
✓ Range      : 206 Partial Content, content-range: bytes 0-1023/66726
✓ DEVICE     : cbr=Chrome, cplatform=DESKTOP  (✗ bot/crawler 判定なし)
```

## 環境変数

| 変数 | 説明 |
|---|---|
| `PORT` | 待ち受けポート (Railway は自動注入。デフォルト 3000) |
| `KAKI_SECRET` | 任意。64桁 hex で URL 暗号鍵を固定。未設定なら起動ごとにランダム。 |
| `KAKI_UA` | 任意。User-Agent を上書き。 |

## 既知の限界

- YouTube が IP レンジ単位で大規模ブロックをかけた場合、サーバー IP を変える以外の
  回避手段はありません。Railway の IP は 2025-06 時点でクリーンですが、
  人気プロキシ化すると将来的にレートリミットされる可能性があります。
- 一部の年齢制限・地域制限動画は、ログイン Cookie が必要なため再生できません。
  これは仕様。

## ライセンス

教育・個人利用目的。YouTube の利用規約に従って使用してください。
