// JWT Inspector - 小辞書による検査と、公開サンプルだけを使うアルゴリズム取り違えの学習
(() => {
  'use strict';

  const C = globalThis.JwtCore;
  const V = globalThis.JwtVerify;
  const fail = (code, detail) => ({ ...(detail || {}), ok: false, code });
  const MAX_CANDIDATES = 1000;
  const MAX_CANDIDATE_BYTES = 1024;
  const MAX_CANDIDATES_CHARS = 1024 * 1024;
  const DEFAULT_CANDIDATES = Object.freeze([
    'secret', 'password', '123456', '123456789', '1234567890', 'jwt', 'jwt-secret', 'jwtsecret',
    'your-256-bit-secret', 'your-secret-key', 'your-secret', 'mysecret', 'changeme', 'change-me',
    'development', 'test', 'admin', 'qwerty', 'letmein', 'key'
  ]);
  const yieldToUi = () => new Promise((resolve) => setTimeout(resolve, 0));

  function parseCandidates(input) {
    const text = input === undefined ? DEFAULT_CANDIDATES.join('\n') : String(input);
    if (text.length > MAX_CANDIDATES_CHARS) return fail('candidates.long', { max: MAX_CANDIDATES_CHARS });
    const lines = text.split(/\r\n|\n|\r/);
    const candidates = [];
    for (let i = 0; i < lines.length; i++) {
      const key = lines[i];
      if (key === '') continue; // 空行だけを除く。鍵の先頭・末尾の空白はそのまま使う
      const bytes = C.utf8(key).length;
      if (bytes > MAX_CANDIDATE_BYTES) return fail('candidate.long', { line: i + 1, bytes, max: MAX_CANDIDATE_BYTES });
      candidates.push(key);
      if (candidates.length > MAX_CANDIDATES) return fail('candidates.count', { max: MAX_CANDIDATES });
    }
    if (!candidates.length) return fail('candidates.empty');
    return { ok: true, candidates };
  }

  async function checkWeakKey(tokenText, candidatesText, options = {}) {
    const token = C.parseToken(tokenText);
    if (!token.ok) return token;
    if (token.header.alg !== 'HS256') return fail('alg.hs256');
    if (token.duplicates.header.length) return fail('header.json.duplicate', { names: token.duplicates.header.join(', ') });
    if (token.header.crit !== undefined || token.header.b64 === false) return fail('header.unsupported');
    if (!token.signature.length) return fail('signature.empty');
    if (token.signature.length !== 32) return fail('signature.length', { expected: 32, actual: token.signature.length });
    const parsed = parseCandidates(candidatesText);
    if (!parsed.ok) return parsed;
    const { candidates } = parsed;
    const total = candidates.length;
    let tested = 0;
    const cancelled = () => Boolean(options.signal && options.signal.aborted);
    const result = (status, extra) => ({ ok: true, status, tested, total, ...(extra || {}) });
    const progress = () => {
      if (typeof options.onProgress === 'function') options.onProgress({ tested, total });
    };
    if (cancelled()) return result('cancelled');
    progress();
    await yieldToUi();
    for (const key of candidates) {
      if (cancelled()) return result('cancelled');
      let verified;
      try {
        verified = await V.verify(token, 'HS256', key);
      } catch {
        return fail('verify.error');
      }
      // Web Crypto 自体は中止できないため、完了後にも確認して結果を破棄する
      if (cancelled()) return result('cancelled');
      if (!verified.ok) return verified;
      tested++;
      progress();
      if (cancelled()) return result('cancelled');
      if (verified.valid) return result('found', { key });
      if (tested % 16 === 0) await yieldToUi();
    }
    return result('notFound');
  }

  async function fixedAlgorithmGate(token, expectedAlg, key) {
    if (token.header.alg !== expectedAlg) {
      return { ok: true, accepted: false, code: 'alg.mismatch', expectedAlg, headerAlg: token.header.alg };
    }
    const verified = await V.verify(token, expectedAlg, key);
    return { ...verified, accepted: Boolean(verified.ok && verified.valid && !verified.mismatch) };
  }

  async function runDemo(mode) {
    if (mode !== 'none' && mode !== 'confusion') return fail('demo.mode');
    const sample = globalThis.JwtSamples.verify.RS256;
    const source = C.parseToken(sample.token);
    if (!source.ok) return fail('demo.sample');
    try {
      const original = await fixedAlgorithmGate(source, 'RS256', sample.key);
      if (!original.accepted) return fail('demo.sample');
      const header = { ...source.header, alg: mode === 'none' ? 'none' : 'HS256' };
      const payload = { ...source.payload, role: 'admin' };
      const headerText = JSON.stringify(header);
      const payloadText = JSON.stringify(payload);
      let token;
      if (mode === 'none') {
        token = `${C.encodeB64url(C.utf8(headerText))}.${C.encodeB64url(C.utf8(payloadText))}.`;
      } else {
        const signed = await globalThis.JwtCreate.create({ headerText, payloadText, alg: 'HS256', key: sample.key });
        if (!signed.ok) return signed;
        token = signed.token;
      }
      const forged = C.parseToken(token);
      if (!forged.ok) return fail('demo.sample');
      // ここだけが故意に脆弱な学習用の分岐。通常の検証 API へは組み込まない
      const unsafe = mode === 'none'
        ? { ok: true, valid: forged.header.alg === 'none', code: 'none.accepted' }
        : await V.verify(forged, forged.header.alg, sample.key);
      const fixed = await fixedAlgorithmGate(forged, 'RS256', sample.key);
      return {
        ok: true, mode, originalToken: sample.token, token, publicKey: sample.key, expectedAlg: 'RS256',
        unsafeAccepted: Boolean(unsafe.ok && unsafe.valid), fixedAccepted: fixed.accepted,
        details: { original, unsafe, fixed }
      };
    } catch {
      return fail('demo.error');
    }
  }

  globalThis.JwtLab = {
    DEFAULT_CANDIDATES, MAX_CANDIDATES, MAX_CANDIDATE_BYTES, MAX_CANDIDATES_CHARS, checkWeakKey, runDemo
  };
})();
