// --- helpers ---
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function b64urlToUint8Array(b64url) {
  const pad = '==='.slice((b64url.length + 3) % 4);
  const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
function uint8ArrayToB64url(arr) {
  let s = '';
  for (const c of arr) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function parseJwtParts(jwt) {
  const parts = jwt.trim().split('.');
  if (parts.length !== 3) throw new Error('JWTは3パート（header.payload.signature）である必要があります。');
  const [h, p, s] = parts;
  return { h, p, s };
}
function safeJsonParse(bytes) {
  try {
    const txt = new TextDecoder().decode(bytes);
    return JSON.parse(txt);
  } catch (e) {
    return null;
  }
}
function pretty(obj) {
  return obj ? JSON.stringify(obj, null, 2) : '';
}
function nowSec() { return Math.floor(Date.now() / 1000); }

// --- tabs ---
function initTabs() {
  $$('.tab-button').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('.tab-button').forEach(b => b.classList.remove('active'));
      $$('.tab-content').forEach(s => s.classList.remove('active'));
      btn.classList.add('active');
      const id = btn.dataset.tab;
      $('#' + id).classList.add('active');
    });
  });
}

// --- decode & lint ---
function lintJwt(header, payload) {
  const out = [];

  if (!header) out.push(['ng', 'ヘッダが不正またはJSONとして解釈できません。']);
  if (!payload) out.push(['ng', 'ペイロードが不正またはJSONとして解釈できません。']);

  if (header) {
    const alg = header.alg;
    if (!alg) out.push(['ng', 'algが未指定。署名検証の前提が不明です。']);
    if (alg === 'none') out.push(['ng', 'alg=none は重大なリスク。許可しないでください。']);
    if (header.typ && header.typ !== 'JWT') out.push(['warn', `typ="${header.typ}"（一般的には"JWT"）`]);
    if (header.kid) out.push(['warn', 'kidヘッダあり。サーバ実装のキー選択ロジックに注意（パストラバーサル等）。']);
  }

  if (payload) {
    const now = nowSec();
    if (typeof payload.exp === 'number') {
      if (payload.exp < now) out.push(['ng', `exp（有効期限）切れ：${payload.exp} < now(${now})`]);
    } else {
      out.push(['warn', 'exp（有効期限）が未設定です。']);
    }
    if (typeof payload.nbf === 'number' && payload.nbf > now) {
      out.push(['ng', `nbf（有効化前）：${payload.nbf} > now(${now})`]);
    }
    if (typeof payload.iat === 'number' && payload.iat > now + 60) {
      out.push(['warn', `iat（発行時刻）が将来に設定されています：${payload.iat}`]);
    }
    if (payload.aud && typeof payload.aud === 'string' && payload.aud.length === 0) {
      out.push(['warn', 'audが空文字です。']);
    }
    out.push(['ok', 'デコード完了。署名検証は別タブで実施できます。']);
  }

  return out;
}

function renderLint(list) {
  const ul = $('#lintList');
  ul.innerHTML = '';
  list.forEach(([level, msg]) => {
    const li = document.createElement('li');
    li.textContent = msg;
    li.classList.add(level);
    ul.appendChild(li);
  });
}

// --- verify ---
async function verifyHS256(jwt, secretText) {
  const { h, p, s } = parseJwtParts(jwt);
  const data = new TextEncoder().encode(`${h}.${p}`);
  const sig = b64urlToUint8Array(s);

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secretText),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const ok = await crypto.subtle.verify('HMAC', key, sig, data);
  return ok;
}

function pemToBinary(pem) {
  const clean = pem.replace(/-----BEGIN PUBLIC KEY-----/, '')
                   .replace(/-----END PUBLIC KEY-----/, '')
                   .replace(/\s+/g, '');
  const raw = atob(clean);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}

async function verifyRS256(jwt, publicKeyPem) {
  const { h, p, s } = parseJwtParts(jwt);
  const data = new TextEncoder().encode(`${h}.${p}`);
  const sig = b64urlToUint8Array(s);

  const key = await crypto.subtle.importKey(
    'spki',
    pemToBinary(publicKeyPem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sig, data);
  return ok;
}

// --- UI bindings ---
function initDecode() {
  $('#btnDecode').addEventListener('click', () => {
    const jwt = $('#jwtInput').value.trim();
    if (!jwt) return;

    try {
      const { h, p, s } = parseJwtParts(jwt);
      const header = safeJsonParse(b64urlToUint8Array(h));
      const payload = safeJsonParse(b64urlToUint8Array(p));

      $('#headerOut').textContent = pretty(header);
      $('#payloadOut').textContent = pretty(payload);
      $('#sigOut').textContent = s || '';

      const lint = lintJwt(header, payload);
      renderLint(lint);
    } catch (e) {
      $('#headerOut').textContent = '';
      $('#payloadOut').textContent = '';
      $('#sigOut').textContent = '';
      renderLint([['ng', e.message]]);
    }
  });

  $('#btnClear').addEventListener('click', () => {
    $('#jwtInput').value = '';
    $('#headerOut').textContent = '';
    $('#payloadOut').textContent = '';
    $('#sigOut').textContent = '';
    renderLint([]);
  });
}

function initVerify() {
  const algSelect = $('#algSelect');
  const hsBox = $('#hsKeyBox');
  const rsBox = $('#rsKeyBox');

  algSelect.addEventListener('change', () => {
    const v = algSelect.value;
    if (v === 'HS256') { hsBox.classList.remove('hidden'); rsBox.classList.add('hidden'); }
    else { rsBox.classList.remove('hidden'); hsBox.classList.add('hidden'); }
  });

  $('#btnVerify').addEventListener('click', async () => {
    const jwt = $('#jwtInput').value.trim();
    if (!jwt) { $('#verifyResult').textContent = 'JWTを先に入力してください。'; return; }

    const alg = algSelect.value;
    const result = $('#verifyResult');
    result.classList.remove('ok', 'ng');
    result.textContent = '検証中...';

    try {
      let ok = false;
      if (alg === 'HS256') {
        const secret = $('#hsKey').value;
        if (!secret) throw new Error('HS鍵が未入力です。');
        ok = await verifyHS256(jwt, secret);
      } else {
        const pem = $('#rsPubKey').value.trim();
        if (!/^-----BEGIN PUBLIC KEY-----/.test(pem)) throw new Error('公開鍵PEMの形式が不正です。');
        ok = await verifyRS256(jwt, pem);
      }

      if (ok) {
        result.textContent = '署名検証：OK';
        result.classList.add('ok');
      } else {
        result.textContent = '署名検証：NG';
        result.classList.add('ng');
      }
    } catch (e) {
      result.textContent = `エラー：${e.message}`;
      result.classList.add('ng');
    }
  });
}

// --- init ---
window.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initDecode();
  initVerify();
});
