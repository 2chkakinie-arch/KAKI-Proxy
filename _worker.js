/* =========================================================================
 *  KAKI Proxy — Cloudflare Pages Functions (advanced mode) edition
 *  -----------------------------------------------------------------------
 *  Drop this file at the project root and Cloudflare Pages will run it
 *  as a single Worker for *every* request, with the static assets in
 *  /public served automatically through env.ASSETS.fetch().
 *
 *  Feature parity with the Railway/Node build:
 *   • AES-256-GCM encrypted URL tokens via WebCrypto.
 *   • youtube-nocookie /embed/<id> rewriting + client-side fetch patch.
 *   • Range / streaming pass-through (Workers stream binaries natively).
 *   • Anti-bot header set (Chrome 131 / Windows / Sec-CH-UA-*).
 *
 *  Secret:
 *   • Set `KAKI_SECRET` (64 hex chars) in the Pages project's environment
 *     variables. If absent, a per-deploy random key is used (links die on
 *     redeploy, which is fine).
 * ========================================================================= */

const ALLOWED_HOSTS = [
  'youtube.com','youtube-nocookie.com','youtubei.googleapis.com',
  'ytimg.com','ggpht.com','googlevideo.com','gstatic.com',
  'google.com','googleapis.com','googleusercontent.com',
  'doubleclick.net','jnn-pa.googleapis.com'
];
function hostAllowed(h){ h=String(h||'').toLowerCase();
  return ALLOWED_HOSTS.some(d => h===d || h.endsWith('.'+d)); }

const UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const SEC_UA          ='"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"';
const SEC_UA_FULL_VER ='"Google Chrome";v="131.0.6778.86", "Chromium";v="131.0.6778.86", "Not_A Brand";v="24.0.0.0"';

/* --- base64-url --- */
function b64u(buf){ const s=btoa(String.fromCharCode.apply(null,new Uint8Array(buf)));
  return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function unb64u(str){ str=str.replace(/-/g,'+').replace(/_/g,'/');
  while(str.length%4)str+='='; const b=atob(str); const a=new Uint8Array(b.length);
  for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i); return a; }

/* --- AES-GCM key cache --- */
let __keyPromise=null, __keySource='';
async function getKey(env){
  const hex = (env && env.KAKI_SECRET) || '';
  if (hex !== __keySource){
    __keySource = hex;
    __keyPromise = (async () => {
      let raw;
      if (/^[0-9a-fA-F]{64}$/.test(hex)){
        raw = new Uint8Array(32);
        for (let i=0;i<32;i++) raw[i] = parseInt(hex.substr(i*2,2),16);
      } else {
        raw = crypto.getRandomValues(new Uint8Array(32));
      }
      return crypto.subtle.importKey('raw', raw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
    })();
  }
  return __keyPromise;
}

async function encryptUrl(url, env){
  const key = await getKey(env);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, new TextEncoder().encode(url));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(ct), 12);
  return b64u(out.buffer);
}
async function decryptUrl(token, env){
  try {
    const key = await getKey(env);
    const data = unb64u(token);
    if (data.length < 28) return null;
    const iv = data.slice(0,12);
    const ct = data.slice(12);
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
    return new TextDecoder().decode(pt);
  } catch { return null; }
}

function pickReferer(host){
  host = host.toLowerCase();
  if (host.endsWith('googlevideo.com'))     return 'https://www.youtube.com/';
  if (host.endsWith('youtube-nocookie.com'))return 'https://www.youtube-nocookie.com/';
  return 'https://www.youtube.com/';
}
function pickOrigin(host){
  host = host.toLowerCase();
  if (host.endsWith('youtube-nocookie.com')) return 'https://www.youtube-nocookie.com';
  return 'https://www.youtube.com';
}

const HOST_RE_ALT = ALLOWED_HOSTS.map(h=>h.replace(/\./g,'\\.')).map(h=>'(?:[a-z0-9-]+\\.)*'+h).join('|');
const ABS_RE   = new RegExp('(https?:(?:\\\\?/){2})('+HOST_RE_ALT+')((?:[^\\s"\'<>`)\\\\]|\\\\/)*)','gi');
const PROTO_RE = new RegExp('((?<![:/\\\\])(?:\\\\?/){2})('+HOST_RE_ALT+')((?:[^\\s"\'<>`)\\\\]|\\\\/)*)','gi');

async function rewriteBody(text, baseOrigin, env){
  // Collect every URL we'll need to encrypt in one pass first, then encrypt
  // them in parallel (WebCrypto is async).
  const urls = new Map();
  function note(u){ if (!urls.has(u)) urls.set(u, null); return u; }
  // 1. absolute
  text.replace(ABS_RE, (m,proto,host,rest) => {
    const full = 'https://'+host+(rest||'').replace(/\\\//g,'/');
    note(full); return m;
  });
  // 2. protocol-relative
  text.replace(PROTO_RE, (m,_s,host,rest) => {
    const full = 'https://'+host+(rest||'').replace(/\\\//g,'/');
    note(full); return m;
  });
  // 3. attribute-style relatives
  text.replace(/(?:src|href|action|data-src|data-href|poster)\s*=\s*"(\/[^"\s>]+)/g, (m,p)=>{ note(baseOrigin+p); return m; });

  // Encrypt all of them in parallel
  const keys = [...urls.keys()];
  const tokens = await Promise.all(keys.map(u => encryptUrl(u, env)));
  keys.forEach((k,i) => urls.set(k, tokens[i]));

  // Rewrite
  text = text.replace(ABS_RE, (m,proto,host,rest) => {
    const full = 'https://'+host+(rest||'').replace(/\\\//g,'/');
    return '/p/'+urls.get(full);
  });
  text = text.replace(PROTO_RE, (m,_s,host,rest) => {
    const full = 'https://'+host+(rest||'').replace(/\\\//g,'/');
    return '/p/'+urls.get(full);
  });
  text = text.replace(/(\b(?:src|href|action|data-src|data-href|poster)\s*=\s*")(\/[^"\s>]+)/g,
    (m,attr,p) => attr + '/p/' + urls.get(baseOrigin+p));

  return text;
}

const CLIENT_PATCH = `<script>(function(){
  if (window.__KAKI__) return; window.__KAKI__ = 1;
  var BASE = location.origin + '/p/';
  var HOSTS = ${JSON.stringify(ALLOWED_HOSTS)};
  function ok(h){ h=String(h||'').toLowerCase();
    return HOSTS.some(function(d){return h===d||h.endsWith('.'+d);}); }
  function sp(u){ try{ if(!u) return false;
    u=String(u);
    if (u.indexOf('/p/')===0||u.indexOf(BASE)===0||u.indexOf('blob:')===0||u.indexOf('data:')===0) return false;
    if (/^https?:\\/\\//i.test(u)){ var a=new URL(u); return ok(a.hostname)?{rel:false,abs:a.href}:false; }
    if (u.indexOf('//')===0){ var a=new URL('https:'+u); return ok(a.hostname)?{rel:false,abs:a.href}:false; }
    if (u.charAt(0)==='/') return {rel:true,path:u};
    return false; }catch(e){return false;} }
  function tk(t){ return fetch('/api/encrypt?u='+encodeURIComponent(t)).then(function(r){return r.text();}).then(function(x){return BASE+x;}); }
  function tks(t){ var x=new XMLHttpRequest(); x.open('GET','/api/encrypt?u='+encodeURIComponent(t),false);
    try{x.send();}catch(e){return null;}
    return (x.status>=200&&x.status<300)?BASE+x.responseText:null; }
  var _f = window.fetch;
  window.fetch = function(inp, init){
    try{ var u=(typeof inp==='string')?inp:(inp&&inp.url); var s=sp(u);
      if(s){ var t=s.rel?('https://www.youtube-nocookie.com'+s.path):s.abs;
        return tk(t).then(function(p){ return _f(typeof inp==='string'?p:new Request(p,inp), init); }); }
    }catch(e){} return _f.apply(this,arguments); };
  var _o = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m,u){ try{ var s=sp(u);
    if(s){ var t=s.rel?('https://www.youtube-nocookie.com'+s.path):s.abs; var p=tks(t); if(p) arguments[1]=p; }
  }catch(e){} return _o.apply(this,arguments); };
  function pms(proto){ var d=Object.getOwnPropertyDescriptor(proto,'src'); if(!d||!d.set) return;
    Object.defineProperty(proto,'src',{configurable:true,enumerable:true,get:d.get,
      set:function(v){ try{ var s=sp(v); if(s){ var t=s.rel?('https://www.youtube-nocookie.com'+s.path):s.abs; var p=tks(t); if(p) v=p; } }catch(e){} return d.set.call(this,v); }}); }
  pms(HTMLImageElement.prototype);
  try{pms(HTMLMediaElement.prototype);}catch(e){}
  try{pms(HTMLSourceElement.prototype);}catch(e){}
  try{pms(HTMLScriptElement.prototype);}catch(e){}
  try{pms(HTMLIFrameElement.prototype);}catch(e){}
})();</script>`;

const STRIP_HEADERS = new Set([
  'content-security-policy','content-security-policy-report-only',
  'x-frame-options','cross-origin-opener-policy','cross-origin-embedder-policy',
  'cross-origin-resource-policy','permissions-policy','feature-policy',
  'report-to','nel','set-cookie','strict-transport-security','public-key-pins',
  'content-length','content-encoding','alt-svc'
]);

async function handleProxy(req, env, token){
  const target = await decryptUrl(token, env);
  if (!target) return new Response('bad token', {status:400});
  let u; try{ u=new URL(target); }catch{ return new Response('bad url',{status:400}); }
  if (!hostAllowed(u.hostname)) return new Response('host not allowed',{status:403});

  const isEmbedTop = u.pathname.startsWith('/embed/');
  const h = new Headers({
    'user-agent': UA,
    'accept': isEmbedTop
      ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
      : (req.headers.get('accept') || '*/*'),
    'accept-language': 'en-US,en;q=0.9',
    'accept-encoding': 'identity',
    'referer': pickReferer(u.hostname),
    'origin':  pickOrigin(u.hostname),
    'sec-fetch-dest': isEmbedTop ? 'iframe'   : 'empty',
    'sec-fetch-mode': isEmbedTop ? 'navigate' : 'cors',
    'sec-fetch-site': isEmbedTop ? 'cross-site' : 'same-site',
    'sec-ch-ua': SEC_UA,
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-ch-ua-platform-version': '"15.0.0"',
    'sec-ch-ua-arch': '"x86"',
    'sec-ch-ua-bitness': '"64"',
    'sec-ch-ua-full-version-list': SEC_UA_FULL_VER,
    'sec-ch-ua-model': '""',
    'priority': 'u=0, i',
    'dnt': '1',
  });
  if (isEmbedTop) h.set('upgrade-insecure-requests','1');
  const fwd = ['range','if-range','if-none-match','if-modified-since'];
  for (const k of fwd){ const v = req.headers.get(k); if (v) h.set(k,v); }

  let body;
  if (req.method !== 'GET' && req.method !== 'HEAD'){
    body = await req.arrayBuffer();
    const ct = req.headers.get('content-type'); if (ct) h.set('content-type', ct);
  }

  let up;
  try { up = await fetch(u.href, { method:req.method, headers:h, body, redirect:'follow' }); }
  catch(e){ return new Response('upstream_error: '+e.message, {status:502}); }

  const ct = (up.headers.get('content-type') || '').toLowerCase();
  const isText = /^(?:text\/html|text\/css|application\/(?:javascript|x-javascript|json)|text\/javascript|text\/plain|application\/xml)/i.test(ct);

  // Build response headers
  const outH = new Headers();
  up.headers.forEach((v,k) => { if (!STRIP_HEADERS.has(k.toLowerCase())) outH.set(k,v); });
  outH.set('access-control-allow-origin','*');
  outH.set('access-control-allow-headers','*');
  outH.set('access-control-allow-methods','GET,POST,HEAD,OPTIONS');
  outH.set('access-control-expose-headers','*');
  outH.set('timing-allow-origin','*');
  outH.set('x-kaki-upstream-host', u.hostname);

  if (isText){
    let text = await up.text();
    text = await rewriteBody(text, u.origin, env);
    if (/^text\/html/.test(ct)){
      if (/<head[^>]*>/i.test(text)) text = text.replace(/<head[^>]*>/i, m => m + CLIENT_PATCH);
      else                            text = CLIENT_PATCH + text;
      outH.set('x-kaki-rewritten','1');
    }
    return new Response(text, { status:up.status, headers:outH });
  }
  // binary stream
  return new Response(up.body, { status:up.status, headers:outH });
}

const RATES = new Map();
function rateLimit(ip){
  const now = Date.now();
  const rec = RATES.get(ip) || { c:0, t:now };
  if (now - rec.t > 10000) { rec.c=0; rec.t=now; }
  rec.c++; RATES.set(ip, rec);
  return rec.c <= 600;
}

export default {
  async fetch(req, env, ctx){
    const url = new URL(req.url);
    const ip  = req.headers.get('cf-connecting-ip') || '0';

    // --- /healthz
    if (url.pathname === '/healthz')
      return new Response(JSON.stringify({ok:true, name:'kaki-proxy', edge:'cloudflare'}),
        { headers:{'content-type':'application/json'} });

    // --- /api/embed/:id
    let m;
    if ((m = url.pathname.match(/^\/api\/embed\/([A-Za-z0-9_-]{6,20})$/))){
      const id  = m[1];
      const eu  = 'https://www.youtube-nocookie.com/embed/'+id+'?autoplay=1&playsinline=1&modestbranding=1&rel=0';
      const tok = await encryptUrl(eu, env);
      return new Response(JSON.stringify({id, token:tok, src:'/p/'+tok}),
        { headers:{'content-type':'application/json'} });
    }
    // --- /watch/:id
    if ((m = url.pathname.match(/^\/watch\/([A-Za-z0-9_-]{6,20})$/))){
      const id = m[1];
      const eu = 'https://www.youtube-nocookie.com/embed/'+id+'?autoplay=1&playsinline=1&modestbranding=1&rel=0';
      const tok = await encryptUrl(eu, env);
      return Response.redirect(url.origin+'/p/'+tok, 302);
    }
    // --- /api/encrypt
    if (url.pathname === '/api/encrypt'){
      if (!rateLimit(ip)) return new Response('rate_limited',{status:429});
      const u = url.searchParams.get('u');
      if (!u) return new Response('missing_u',{status:400});
      if (u.length > 4096) return new Response('too_long',{status:414});
      let target; try{ target = new URL(u, 'https://www.youtube-nocookie.com'); }catch{ return new Response('bad_url',{status:400}); }
      if (!hostAllowed(target.hostname)) return new Response('host_not_allowed',{status:403});
      return new Response(await encryptUrl(target.href, env),
        { headers:{'content-type':'text/plain','cache-control':'no-store'} });
    }
    // --- /p/:token
    if ((m = url.pathname.match(/^\/p\/(.+)$/))){
      return handleProxy(req, env, m[1]);
    }
    // --- static (delegated to Pages assets)
    if (env.ASSETS) return env.ASSETS.fetch(req);
    return new Response('Not found',{status:404});
  }
};
