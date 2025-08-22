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

  if (!header) out.push(['ng', 'ヘッダーが不正またはJSONとして解釈できません。']);
  if (!payload) out.push(['ng', 'ペイロードが不正またはJSONとして解釈できません。']);

  if (header) {
    const alg = header.alg;
    if (!alg) out.push(['ng', 'algが未指定。署名検証の前提が不明です。']);
    if (alg === 'none') out.push(['ng', 'alg=none は重大なリスク。許可しないでください。']);
    if (header.typ && header.typ !== 'JWT') out.push(['warn', `typ="${header.typ}"（一般的には"JWT"）`]);
    if (header.kid) out.push(['warn', 'kidヘッダーあり。サーバー実装のキー選択ロジックに注意（パストラバーサル等）。']);
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

  // サンプル1: 正常なJWT（将来の有効期限）
  $('#btnSample1').addEventListener('click', () => {
    const sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzM0OTU5OTk5LCJleHAiOjE4NjY0OTU5OTksInJvbGUiOiJ1c2VyIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSJ9.d6HKTzQ5J2H-m1pLZYh0KcJhJ9YnCzWxTmYhAz4N0xE';
    $('#jwtInput').value = sampleJwt;
    document.getElementById('btnDecode').click();
  });

  // サンプル2: 期限切れJWT
  $('#btnSample2').addEventListener('click', () => {
    const sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyNDI2MjIsInJvbGUiOiJ1c2VyIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSJ9.79mMsGNl90k1w0XL4gGe4iWjW9Ni8ZWnJnTGpuZQYTI';
    $('#jwtInput').value = sampleJwt;
    document.getElementById('btnDecode').click();
  });

  // サンプル3: alg=none JWT（署名なし、危険）
  $('#btnSample3').addEventListener('click', () => {
    const sampleJwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJpYXQiOjE3MzQ5NTk5OTksImV4cCI6MTg2NjQ5NTk5OSwicm9sZSI6ImFkbWluIiwiZW1haWwiOiJhZG1pbkBleGFtcGxlLmNvbSJ9.';
    $('#jwtInput').value = sampleJwt;
    document.getElementById('btnDecode').click();
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

  // クイック検証：HS256サンプル
  $('#btnQuickHS256').addEventListener('click', async () => {
    const sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzM0OTU5OTk5LCJleHAiOjE4NjY0OTU5OTksInJvbGUiOiJ1c2VyIn0.UWrEuNWNd6F8WOjpOOtZi8pgtP5X6KrSDFhvqXhUa4c';
    const sampleKey = 'my-secret-key-for-demo';
    
    // JWTを入力欄に設定
    $('#jwtInput').value = sampleJwt;
    
    // HS256モードに切り替え
    algSelect.value = 'HS256';
    hsBox.classList.remove('hidden');
    rsBox.classList.add('hidden');
    $('#hsKey').value = sampleKey;
    
    // 検証実行
    await performVerification(sampleJwt, 'HS256', sampleKey);
  });

  // クイック検証：RS256サンプル
  $('#btnQuickRS256').addEventListener('click', async () => {
    const sampleJwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzM0OTU5OTk5LCJleHAiOjE4NjY0OTU5OTksInJvbGUiOiJ1c2VyIn0.demo_signature_for_educational_purposes_only';
    const samplePubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge9JlM0HJP8gqfvRAat6KH4t29Rr4Y6HTG6rYOLz9JiNsQjlxEJ4qfrA0K8G6H0eP34I2H+X6qT3Pn8t2wEJ4Jz7Qk5P3t4Q+Xb7EQf1Rz0O9Fvz6BQzYw8Q3l0e6+xQ4h4K6+a6+qwO3jXzO3K1LQQ3g3jNQ3eXQ3o4+Q3p5+Q6w7xQ8yQ9R0AQ1R2BQ3RQ4R5Q6R7Q8R9S0AS1S2BS3SQ4S5S6S7S8S9T0AT1T2BT3TQ4T5T6T7T8T9U0AU1U2BU3UQ4U5U6U7U8U9V0AV1V2BV3VQ4V5V6V7V8V9W0AW1W2BW3WQ4W5W6W7W8W9X0AX1X2BX3XQ4X5X6X7X8X9Y0AY1Y2BY3YQ4Y5Y6Y7Y8Y9Z0AZ1Z2BZ3ZQIDAQAB
-----END PUBLIC KEY-----`;
    
    // JWTを入力欄に設定
    $('#jwtInput').value = sampleJwt;
    
    // RS256モードに切り替え
    algSelect.value = 'RS256';
    rsBox.classList.remove('hidden');
    hsBox.classList.add('hidden');
    $('#rsPubKey').value = samplePubKey;
    
    // 検証実行（RS256はデモ用なので失敗するが、UIの動作確認は可能）
    await performVerification(sampleJwt, 'RS256', samplePubKey);
  });

  algSelect.addEventListener('change', () => {
    const v = algSelect.value;
    if (v === 'HS256') { hsBox.classList.remove('hidden'); rsBox.classList.add('hidden'); }
    else { rsBox.classList.remove('hidden'); hsBox.classList.add('hidden'); }
  });

  // 共通の検証処理
  async function performVerification(jwt, algorithm, keyData) {
    const result = $('#verifyResult');
    result.classList.remove('ok', 'ng');
    result.textContent = '検証中...';

    try {
      let ok = false;
      if (algorithm === 'HS256') {
        ok = await verifyHS256(jwt, keyData);
      } else if (algorithm === 'RS256') {
        ok = await verifyRS256(jwt, keyData);
      } else {
        throw new Error(`未対応のアルゴリズム：${algorithm}`);
      }

      if (ok) {
        result.textContent = '署名検証：OK ✅ 署名が正当です';
        result.classList.add('ok');
      } else {
        result.textContent = '署名検証：NG ❌ 署名が不正か、鍵が間違っています';
        result.classList.add('ng');
      }
    } catch (e) {
      const errorMessage = e.message || e.toString() || '検証処理でエラーが発生しました';
      result.textContent = `検証エラー：${errorMessage}`;
      result.classList.add('ng');
      console.error('performVerification エラー:', e);
    }
  }

  $('#btnVerify').addEventListener('click', async () => {
    const jwt = $('#jwtInput').value.trim();
    if (!jwt) { 
      const result = $('#verifyResult');
      result.textContent = 'JWTを先に入力してください。デコードタブでJWTを入力してからお試しください。';
      result.classList.remove('ok');
      result.classList.add('ng');
      return; 
    }

    const alg = algSelect.value;
    
    try {
      if (alg === 'HS256') {
        const secret = $('#hsKey').value.trim();
        if (!secret) throw new Error('HS鍵が未入力です。共有秘密鍵を入力してください。');
        await performVerification(jwt, 'HS256', secret);
      } else if (alg === 'RS256') {
        const pem = $('#rsPubKey').value.trim();
        if (!pem) throw new Error('RS公開鍵が未入力です。PEM形式の公開鍵を入力してください。');
        if (!/^-----BEGIN PUBLIC KEY-----/.test(pem)) throw new Error('公開鍵PEMの形式が不正です。"-----BEGIN PUBLIC KEY-----"で始まる形式で入力してください。');
        await performVerification(jwt, 'RS256', pem);
      } else {
        throw new Error(`未対応のアルゴリズムです：${alg}`);
      }
    } catch (e) {
      const result = $('#verifyResult');
      const errorMessage = e.message || e.toString() || '不明なエラーが発生しました';
      result.textContent = `エラー：${errorMessage}`;
      result.classList.remove('ok');
      result.classList.add('ng');
      console.error('署名検証エラー:', e);
    }
  });
}

// --- init ---
window.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initDecode();
  initVerify();
});
