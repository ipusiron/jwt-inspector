// JWT Inspector - 署名検証の計算部（Web Crypto を使う。DOM は使わない）。globalThis.JwtVerify に置く
// HS・RS・PS・ES の256〜512に対応する。鍵は HS が文字列、RS/PS/ES が PEM（SPKI）か JWK
(() => {
  'use strict';

  const C = globalThis.JwtCore;
  const fail = (code, detail) => ({ ...(detail || {}), ok: false, code });

  // Web Crypto の名前と、鍵の取り込み方
  const WEBCRYPTO = {
    HS: (bits) => ({ name: 'HMAC', hash: `SHA-${bits}` }),
    RS: (bits) => ({ name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${bits}` }),
    PS: (bits) => ({ name: 'RSA-PSS', hash: `SHA-${bits}` }),
    ES: (bits, curve) => ({ name: 'ECDSA', namedCurve: curve })
  };

  // RFC 7518 の鍵の長さの決まり
  const MIN_HS_BITS = { 256: 256, 384: 384, 512: 512 }; // §3.2 ハッシュの出力以上
  const MIN_RSA_BITS = 2048; // §3.3・§3.5

  // ===== PEM =====
  const PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

  // PEM を読んで、種類（label）とバイト列を返す
  function parsePem(text) {
    const m = PEM_RE.exec(String(text).trim());
    if (!m) return fail('pem.format');
    const label = m[1];
    const body = m[2].replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body)) return fail('pem.base64');
    let bytes;
    try {
      const bin = atob(body);
      bytes = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
    } catch {
      return fail('pem.base64');
    }
    return { ok: true, label, bytes };
  }

  // ===== JWK =====
  // 公開鍵として使える形か確かめる（秘密の成分が入っていたら拒む）
  const PRIVATE_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];

  function parseJwk(text) {
    let value;
    try {
      value = JSON.parse(String(text));
    } catch {
      return fail('jwk.syntax');
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return fail('jwk.notObject');
    if (value.keys !== undefined) return fail('jwk.set'); // JWK Set（RFC 7517 §5）はこのツールでは扱わない
    const present = PRIVATE_FIELDS.filter((f) => value[f] !== undefined);
    if (present.length) return fail('jwk.private', { fields: present.join(', ') });
    if (typeof value.kty !== 'string') return fail('jwk.kty');
    return { ok: true, value };
  }

  // ===== 鍵の取り込み =====
  async function importKey(alg, keyInput) {
    if (!C.ALG_NAMES.includes(alg)) return fail('alg.unsupported', { alg });
    const spec = C.ALGORITHMS[alg];
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    if (!subtle) return fail('crypto.missing');
    const { family, bits, curve } = spec;
    const params = WEBCRYPTO[family](bits, curve);

    if (family === 'HS') {
      const raw = C.utf8(keyInput);
      if (!raw.length) return fail('key.empty');
      const key = await subtle.importKey('raw', raw, params, false, ['verify']);
      return { ok: true, key, keyBits: raw.length * 8, kind: 'raw' };
    }

    const text = String(keyInput).trim();
    if (!text) return fail('key.empty');
    let key;
    let keyBits = null;
    const looksJson = text.startsWith('{') || text.startsWith('[');
    if (looksJson) {
      const jwk = parseJwk(text);
      if (!jwk.ok) return jwk;
      try {
        key = await subtle.importKey('jwk', jwk.value, params, true, ['verify']);
      } catch (e) {
        return fail('key.import', { detail: String(e && e.name ? e.name : e) });
      }
      if (jwk.value.n) keyBits = C.decodeB64url(jwk.value.n).ok ? C.decodeB64url(jwk.value.n).bytes.length * 8 : null;
    } else {
      const pem = parsePem(text);
      if (!pem.ok) return pem;
      if (pem.label.includes('PRIVATE')) return fail('pem.private', { label: pem.label });
      if (pem.label === 'RSA PUBLIC KEY') return fail('pem.pkcs1'); // PKCS#1 は Web Crypto が読めない
      if (pem.label === 'CERTIFICATE') return fail('pem.certificate');
      if (pem.label !== 'PUBLIC KEY') return fail('pem.label', { label: pem.label });
      try {
        key = await subtle.importKey('spki', pem.bytes, params, true, ['verify']);
      } catch (e) {
        return fail('key.import', { detail: String(e && e.name ? e.name : e) });
      }
    }
    // RSA は法の長さ、EC は曲線の名前から鍵の大きさを出す
    const CURVE_BITS = { 'P-256': 256, 'P-384': 384, 'P-521': 521 };
    if (keyBits === null && key.algorithm) keyBits = key.algorithm.modulusLength || CURVE_BITS[key.algorithm.namedCurve] || null;
    return { ok: true, key, keyBits, kind: looksJson ? 'jwk' : 'pem' };
  }

  // 鍵の長さを RFC 7518 に照らす
  function keyWarnings(alg, keyBits) {
    const spec = C.ALGORITHMS[alg];
    const out = [];
    if (!C.ALG_NAMES.includes(alg) || keyBits === null || keyBits === undefined) return out;
    if (spec.family === 'HS') {
      const min = MIN_HS_BITS[spec.bits];
      if (keyBits < min) out.push({ code: 'key.hsShort', vars: { bits: keyBits, min } });
    } else if (spec.family === 'RS' || spec.family === 'PS') {
      if (keyBits < MIN_RSA_BITS) out.push({ code: 'key.rsaShort', vars: { bits: keyBits, min: MIN_RSA_BITS } });
    }
    return out;
  }

  // ===== 検証 =====
  // token は JwtCore.parseToken の結果。alg は検証側が選んだアルゴリズム（RFC 8725 §3.1 は検証側が決めることを求める）
  async function verify(token, alg, keyInput) {
    if (!C.ALG_NAMES.includes(alg)) return fail('alg.unsupported', { alg });
    const spec = C.ALGORITHMS[alg];
    if (!token.signature.length) return fail('signature.empty');
    const imported = await importKey(alg, keyInput);
    if (!imported.ok) return imported;
    const params = WEBCRYPTO[spec.family](spec.bits, spec.curve);
    const verifyParams = spec.family === 'PS'
      ? { name: 'RSA-PSS', saltLength: spec.bits / 8 } // RFC 7518 §3.5 塩の長さはハッシュの出力と同じ
      : spec.family === 'ES' ? { name: 'ECDSA', hash: `SHA-${spec.bits}` } : params;
    let valid;
    try {
      valid = await globalThis.crypto.subtle.verify(verifyParams, imported.key, token.signature, C.utf8(token.signingInput));
    } catch (e) {
      return fail('verify.error', { detail: String(e && e.name ? e.name : e) });
    }
    const headerAlg = token.header.alg;
    return {
      ok: true,
      valid,
      alg,
      headerAlg,
      // RFC 8725 §2.1: ヘッダーの alg をそのまま信じると、none や RS256→HS256 の取り違えに弱い
      mismatch: typeof headerAlg === 'string' && headerAlg !== alg,
      keyBits: imported.keyBits,
      keyKind: imported.kind,
      warnings: keyWarnings(alg, imported.keyBits)
    };
  }

  globalThis.JwtVerify = {
    MIN_HS_BITS,
    MIN_RSA_BITS,
    parsePem,
    parseJwk,
    importKey,
    keyWarnings,
    verify
  };
})();
