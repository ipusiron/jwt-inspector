// JWT Inspector - ローカルで鍵を生成し、JWT に署名する。秘密鍵はメモリーの中だけで扱う
(() => {
  'use strict';

  const C = globalThis.JwtCore;
  const V = globalThis.JwtVerify;
  const generatedKeys = new WeakMap();
  const fail = (code, detail) => ({ ...(detail || {}), ok: false, code });
  const knownAlgorithm = (alg) => typeof alg === 'string' && C.ALG_NAMES.includes(alg);
  const subtle = () => globalThis.crypto && globalThis.crypto.subtle;

  function keyParams(spec) {
    if (spec.family === 'HS') return { name: 'HMAC', hash: `SHA-${spec.bits}` };
    if (spec.family === 'ES') return { name: 'ECDSA', namedCurve: spec.curve };
    return {
      name: spec.family === 'RS' ? 'RSASSA-PKCS1-v1_5' : 'RSA-PSS',
      hash: `SHA-${spec.bits}`,
      modulusLength: V.MIN_RSA_BITS,
      publicExponent: new Uint8Array([1, 0, 1])
    };
  }

  function signParams(spec) {
    if (spec.family === 'PS') return { name: 'RSA-PSS', saltLength: spec.bits / 8 };
    if (spec.family === 'ES') return { name: 'ECDSA', hash: `SHA-${spec.bits}` };
    return { name: spec.family === 'HS' ? 'HMAC' : 'RSASSA-PKCS1-v1_5' };
  }

  function publicPem(bytes) {
    let binary = '';
    for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
    const lines = btoa(binary).match(/.{1,64}/g);
    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
  }

  async function generateKey(alg) {
    if (!knownAlgorithm(alg)) return fail('alg.unsupported', { alg });
    if (!subtle() || typeof globalThis.crypto.getRandomValues !== 'function') return fail('crypto.missing');
    const spec = C.ALGORITHMS[alg];
    try {
      if (spec.family === 'HS') {
        // ランダムなバイトを Base64url の文字列にし、その文字列を UTF-8 の共有鍵として使う
        const bytes = globalThis.crypto.getRandomValues(new Uint8Array(spec.bits / 8));
        return { ok: true, alg, secret: C.encodeB64url(bytes) };
      }
      const pair = await subtle().generateKey(keyParams(spec), false, ['sign', 'verify']);
      const pem = publicPem(await subtle().exportKey('spki', pair.publicKey));
      generatedKeys.set(pair.privateKey, alg);
      return { ok: true, alg, privateKey: pair.privateKey, publicKey: pem };
    } catch {
      return fail('key.generate');
    }
  }

  function parsePart(text, part) {
    const parsed = C.parseJsonObject(C.utf8(text));
    if (!parsed.ok) return fail(`${part}.${parsed.code}`);
    if (parsed.duplicates.length) return fail(`${part}.json.duplicate`, { names: parsed.duplicates.join(', ') });
    return parsed;
  }

  function signatureBytes(spec) {
    if (spec.family === 'HS') return spec.bits / 8;
    if (spec.family === 'ES') return 2 * Math.ceil((spec.curve === 'P-521' ? 521 : spec.bits) / 8);
    return V.MIN_RSA_BITS / 8;
  }

  async function create(options = {}) {
    const { alg, key } = options;
    if (!knownAlgorithm(alg)) return fail('alg.unsupported', { alg });
    const headerText = String(options.headerText ?? '');
    const payloadText = String(options.payloadText ?? '');
    if (headerText.length + payloadText.length > C.MAX_TOKEN_CHARS) return fail('token.long', { max: C.MAX_TOKEN_CHARS });
    const header = parsePart(headerText, 'header');
    if (!header.ok) return header;
    const payload = parsePart(payloadText, 'payload');
    if (!payload.ok) return payload;
    if (header.value.alg !== alg) return fail('alg.mismatch', { alg, headerAlg: header.value.alg });
    if (header.value.crit !== undefined || header.value.b64 === false) return fail('header.unsupported');
    const spec = C.ALGORITHMS[alg];
    const signingInput = `${C.encodeB64url(C.utf8(headerText))}.${C.encodeB64url(C.utf8(payloadText))}`;
    // 出力を既存のデコード・検証へ渡せる長さに限る。署名前に最終的な長さを求める
    const length = signingInput.length + 1 + Math.ceil(signatureBytes(spec) * 4 / 3);
    if (length > C.MAX_TOKEN_CHARS) return fail('token.long', { max: C.MAX_TOKEN_CHARS, length });
    if (!subtle()) return fail('crypto.missing');
    let signingKey;
    let keyBits;
    if (spec.family === 'HS') {
      if (typeof key !== 'string') return fail('key.type');
      const bytes = C.utf8(key);
      if (!bytes.length) return fail('key.empty');
      keyBits = bytes.length * 8;
      try {
        signingKey = await subtle().importKey('raw', bytes, keyParams(spec), false, ['sign']);
      } catch {
        return fail('key.import');
      }
    } else {
      const generatedAlg = generatedKeys.get(key);
      if (!generatedAlg) return fail('key.generatedRequired');
      if (generatedAlg !== alg) return fail('key.algorithm', { alg, keyAlg: generatedAlg });
      signingKey = key;
      keyBits = spec.family === 'ES' ? (spec.curve === 'P-521' ? 521 : spec.bits) : V.MIN_RSA_BITS;
    }
    try {
      const signature = new Uint8Array(await subtle().sign(signParams(spec), signingKey, C.utf8(signingInput)));
      return { ok: true, token: `${signingInput}.${C.encodeB64url(signature)}`, warnings: V.keyWarnings(alg, keyBits) };
    } catch {
      return fail('sign.error');
    }
  }

  globalThis.JwtCreate = { generateKey, create };
})();
