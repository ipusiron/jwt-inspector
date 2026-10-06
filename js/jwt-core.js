// JWT Inspector - JWT の読み取りと検査の計算部（DOM を使わない）。globalThis.JwtCore に置く
// 文言は持たず、コードと値だけを返す（画面と README が文言を当てる）
(() => {
  'use strict';

  // RFC 7515 §4.1.1 の alg は大文字と小文字を区別する。このツールが検証できるもの（Web Crypto で扱える範囲）
  const ALGORITHMS = {
    HS256: { family: 'HS', bits: 256 },
    HS384: { family: 'HS', bits: 384 },
    HS512: { family: 'HS', bits: 512 },
    RS256: { family: 'RS', bits: 256 },
    RS384: { family: 'RS', bits: 384 },
    RS512: { family: 'RS', bits: 512 },
    PS256: { family: 'PS', bits: 256 },
    PS384: { family: 'PS', bits: 384 },
    PS512: { family: 'PS', bits: 512 },
    ES256: { family: 'ES', bits: 256, curve: 'P-256' },
    ES384: { family: 'ES', bits: 384, curve: 'P-384' },
    ES512: { family: 'ES', bits: 512, curve: 'P-521' }
  };
  const ALG_NAMES = Object.keys(ALGORITHMS);

  // RFC 7518 §3.1 の表にある、このツールが検証しないもの（名前は知っていて、未対応と答える）
  const KNOWN_UNSUPPORTED = ['none', 'EdDSA', 'Ed25519', 'Ed448'];

  // RFC 7515 §4.1 のヘッダーパラメーター（登録済み）
  const HEADER_PARAMS = ['alg', 'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'typ', 'cty', 'crit'];
  // RFC 7519 §4.1 の登録済みクレーム
  const REGISTERED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

  const MAX_TOKEN_CHARS = 16384; // 読み取る文字数の上限
  const DEFAULT_LEEWAY = 60; // 時計のずれの猶予（秒）。RFC 7519 §4.1.4・§4.1.5 は数分までを認める

  // detail を先に展開する（元の結果に code があっても、ここで渡した code が残る）
  const fail = (code, detail) => ({ ...detail, ok: false, code });

  // ===== Base64url（RFC 7515 §2。末尾の = は付けない） =====
  const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const B64URL_INDEX = new Map([...B64URL].map((c, i) => [c, i]));

  // 1文字ずつ検査して復号する。= と + / は、標準の Base64 と取り違えた可能性があるので別のコードで返す
  function decodeB64url(text) {
    const s = String(text);
    const values = [];
    let pos = 0;
    for (const ch of s) {
      pos++;
      const v = B64URL_INDEX.get(ch);
      if (v === undefined) {
        if (ch === '=') return fail('b64.padding', { pos, ch });
        if (ch === '+' || ch === '/') return fail('b64.standard', { pos, ch });
        return fail('b64.char', { pos, ch });
      }
      values.push(v);
    }
    if (values.length % 4 === 1) return fail('b64.length', { length: values.length });
    const out = [];
    let acc = 0;
    let n = 0;
    for (const v of values) {
      acc = (acc << 6) | v;
      n += 6;
      if (n >= 8) {
        n -= 8;
        out.push((acc >> n) & 255);
      }
      acc &= (1 << n) - 1;
    }
    // 最後の文字の余りのビットは0でなければならない（0でなくても同じバイト列になる別の文字列がある）
    return { ok: true, bytes: Uint8Array.from(out), loose: acc !== 0 };
  }

  function encodeB64url(bytes) {
    let out = '';
    let acc = 0;
    let n = 0;
    for (const b of bytes) {
      acc = (acc << 8) | b;
      n += 8;
      while (n >= 6) {
        n -= 6;
        out += B64URL[(acc >> n) & 63];
      }
      acc &= (1 << n) - 1;
    }
    if (n) out += B64URL[(acc << (6 - n)) & 63];
    return out;
  }

  const utf8 = (text) => new TextEncoder().encode(String(text));

  function readUtf8(bytes) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      return null;
    }
  }

  // ===== JSON（RFC 7515 §4 は、重複したメンバー名を含まない JSON オブジェクトを求める） =====
  // JSON.parse はあとの値で上書きするので、重複を見つけるには文字列を数える
  function duplicateKeys(json) {
    const names = [];
    const re = /"((?:[^"\\]|\\.)*)"\s*:/g;
    let depth = 0;
    let i = 0;
    while (i < json.length) {
      const ch = json[i];
      if (ch === '"') {
        re.lastIndex = i;
        const m = re.exec(json);
        if (m && m.index === i) {
          if (depth === 1) names.push(JSON.parse('"' + m[1] + '"'));
          i = re.lastIndex;
          continue;
        }
        // 値としての文字列を読み飛ばす
        i++;
        while (i < json.length && json[i] !== '"') i += json[i] === '\\' ? 2 : 1;
        i++;
        continue;
      }
      if (ch === '{' || ch === '[') depth++;
      if (ch === '}' || ch === ']') depth--;
      i++;
    }
    return [...new Set(names.filter((n, k) => names.indexOf(n) !== k))];
  }

  function parseJsonObject(bytes) {
    const text = readUtf8(bytes);
    if (text === null) return fail('json.utf8');
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      return fail('json.syntax', { text });
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return fail('json.notObject', { text });
    return { ok: true, value, text, duplicates: duplicateKeys(text) };
  }

  // ===== トークンの分解 =====
  // JWS の Compact Serialization（RFC 7515 §7.1）は header.payload.signature の3つ
  function parseToken(token) {
    const text = String(token).trim();
    if (!text) return fail('token.empty');
    if (text.length > MAX_TOKEN_CHARS) return fail('token.long', { max: MAX_TOKEN_CHARS, length: text.length });
    const parts = text.split('.');
    if (parts.length !== 3) return fail('token.parts', { count: parts.length });
    const [h, p, s] = parts;
    const headerB64 = decodeB64url(h);
    if (!headerB64.ok) return fail('header.' + headerB64.code, headerB64);
    const payloadB64 = decodeB64url(p);
    if (!payloadB64.ok) return fail('payload.' + payloadB64.code, payloadB64);
    const sigB64 = s === '' ? { ok: true, bytes: new Uint8Array(0), loose: false } : decodeB64url(s);
    if (!sigB64.ok) return fail('signature.' + sigB64.code, sigB64);
    const header = parseJsonObject(headerB64.bytes);
    if (!header.ok) return fail('header.' + header.code, header);
    const payload = parseJsonObject(payloadB64.bytes);
    if (!payload.ok) return fail('payload.' + payload.code, payload);
    return {
      ok: true,
      raw: { header: h, payload: p, signature: s },
      signingInput: `${h}.${p}`,
      header: header.value,
      payload: payload.value,
      headerText: header.text,
      payloadText: payload.text,
      duplicates: { header: header.duplicates, payload: payload.duplicates },
      signature: sigB64.bytes,
      loose: headerB64.loose || payloadB64.loose || sigB64.loose
    };
  }

  // ===== 時刻（RFC 7519 §2 の NumericDate は秒の数） =====
  const isNumericDate = (v) => typeof v === 'number' && Number.isFinite(v);

  // 秒数を、いちばん大きい単位に丸める（画面はこの単位の文言を当てる）
  const UNITS = [['day', 86400], ['hour', 3600], ['minute', 60]];
  function duration(seconds) {
    const n = Math.abs(Math.round(seconds));
    for (const [unit, size] of UNITS) {
      if (n >= size) return { unit, n: Math.floor(n / size) };
    }
    return { unit: 'second', n };
  }
  // NumericDateの範囲とJavaScriptの日時表示の範囲は異なる。表示できなくても検査は続ける。
  const toIso = (sec) => {
    const date = new Date(sec * 1000);
    return Number.isNaN(date.getTime()) ? '-' : date.toISOString().replace('.000', '');
  };

  // exp・nbf・iat を、いまの時刻と猶予で判定する
  function timeStatus(payload, now, leeway = DEFAULT_LEEWAY) {
    const out = {};
    for (const claim of ['exp', 'nbf', 'iat']) {
      const v = payload[claim];
      if (v === undefined) {
        out[claim] = { state: 'missing' };
        continue;
      }
      if (!isNumericDate(v)) {
        out[claim] = { state: 'type', value: v };
        continue;
      }
      const delta = v - now;
      let state = 'ok';
      // RFC 7519 §4.1.4: 現在時刻が exp より前でなければ受け付けない（exp と同じ秒も期限切れ）
      if (claim === 'exp') state = now >= v ? (now < v + leeway ? 'leeway' : 'expired') : 'ok';
      // §4.1.5: 現在時刻が nbf 以後でなければ受け付けない
      if (claim === 'nbf') state = now < v ? (now >= v - leeway ? 'leeway' : 'notYet') : 'ok';
      // §4.1.6: iat は発行時刻。未来のものは猶予を超えていれば注意
      if (claim === 'iat') state = v > now + leeway ? 'future' : 'ok';
      out[claim] = { state, value: v, iso: toIso(v), delta };
    }
    return out;
  }

  // ===== 検査（Lint） =====
  // level は 'danger' | 'warn' | 'info' | 'ok'。code と値だけを返し、文言は画面側に置く
  const F = (level, code, vars) => ({ level, code, ...(vars ? { vars } : {}) });

  function lintHeader(header, out) {
    const alg = header.alg;
    if (alg === undefined) {
      out.push(F('danger', 'alg.missing')); // RFC 7515 §4.1.1 は alg を必須とする
    } else if (typeof alg !== 'string') {
      out.push(F('danger', 'alg.type', { type: typeof alg }));
    } else if (alg === 'none') {
      out.push(F('danger', 'alg.none'));
    } else if (alg.toLowerCase() === 'none') {
      // 大文字小文字を区別せずに比べる実装では none として扱われうる（RFC 7515 §4.1.1 は区別すると定める）
      out.push(F('danger', 'alg.noneCase', { alg }));
    } else if (!ALG_NAMES.includes(alg)) {
      const known = KNOWN_UNSUPPORTED.includes(alg);
      out.push(F(known ? 'info' : 'warn', known ? 'alg.unsupported' : 'alg.unknown', { alg }));
    } else {
      out.push(F('info', 'alg.ok', { alg }));
    }

    if (header.typ === undefined) out.push(F('info', 'typ.missing')); // RFC 8725 §3.11 は種類の明示を勧める
    else if (typeof header.typ !== 'string') out.push(F('warn', 'typ.type'));
    else if (!/^(JWT|[\w.+-]+\+jwt)$/i.test(header.typ)) out.push(F('warn', 'typ.unusual', { typ: header.typ }));

    // RFC 8725 §3.10: jku・x5u は任意の URL を指しうる（SSRF）、jwk はトークン自身が鍵を運ぶ
    for (const key of ['jku', 'x5u']) {
      if (header[key] !== undefined) out.push(F('danger', 'header.url', { param: key, value: String(header[key]) }));
    }
    if (header.jwk !== undefined) out.push(F('danger', 'header.jwk'));
    if (header.kid !== undefined) out.push(F('warn', 'header.kid', { kid: String(header.kid) }));
    if (header.crit !== undefined) out.push(F('warn', 'header.crit', { value: JSON.stringify(header.crit) })); // RFC 7515 §4.1.11
    const unknown = Object.keys(header).filter((k) => !HEADER_PARAMS.includes(k));
    if (unknown.length) out.push(F('info', 'header.extra', { names: unknown.join(', ') }));
  }

  function lintPayload(payload, times, out) {
    for (const claim of ['exp', 'nbf', 'iat']) {
      const t = times[claim];
      if (t.state === 'type') out.push(F('danger', `${claim}.type`, { value: JSON.stringify(t.value) }));
    }
    const exp = times.exp;
    if (exp.state === 'missing') out.push(F('warn', 'exp.missing'));
    else if (exp.state === 'expired' || exp.state === 'leeway') out.push(F('danger', 'exp.expired', { iso: exp.iso, ago: -exp.delta }));
    else if (exp.state === 'ok') out.push(F('ok', 'exp.ok', { iso: exp.iso, left: exp.delta }));
    if (times.nbf.state === 'notYet' || times.nbf.state === 'leeway') out.push(F('danger', 'nbf.notYet', { iso: times.nbf.iso, left: times.nbf.delta }));
    if (times.iat.state === 'future') out.push(F('warn', 'iat.future', { iso: times.iat.iso, ahead: times.iat.delta }));

    // RFC 8725 §3.8・§3.9: iss と aud は検証されるべきもの。型は RFC 7519 §4.1.1・§4.1.3
    if (payload.iss === undefined) out.push(F('warn', 'iss.missing'));
    else if (typeof payload.iss !== 'string') out.push(F('warn', 'iss.type'));
    if (payload.aud === undefined) {
      out.push(F('warn', 'aud.missing'));
    } else if (typeof payload.aud === 'string') {
      if (!payload.aud) out.push(F('warn', 'aud.empty'));
    } else if (Array.isArray(payload.aud)) {
      if (!payload.aud.length) out.push(F('warn', 'aud.empty'));
      else if (!payload.aud.every((v) => typeof v === 'string')) out.push(F('warn', 'aud.type'));
    } else {
      out.push(F('warn', 'aud.type'));
    }
    if (payload.sub !== undefined && typeof payload.sub !== 'string') out.push(F('warn', 'sub.type'));
    if (payload.jti === undefined) out.push(F('info', 'jti.missing'));
  }

  // 値が長い文字列のクレームは、トークンに秘密を入れている可能性がある（ペイロードは誰でも読める）
  function lintPrivacy(payload, out) {
    const SENSITIVE = /^(password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|credit_?card|card_?number|ssn|session|cookie)$/i;
    const names = Object.keys(payload).filter((k) => SENSITIVE.test(k));
    if (names.length) out.push(F('danger', 'payload.sensitive', { names: names.join(', ') }));
    out.push(F('info', 'payload.readable'));
  }

  // token は parseToken の結果。now は秒
  function lint(token, now, leeway = DEFAULT_LEEWAY) {
    const out = [];
    if (token.duplicates.header.length) out.push(F('danger', 'json.duplicate', { part: 'header', names: token.duplicates.header.join(', ') }));
    if (token.duplicates.payload.length) out.push(F('danger', 'json.duplicate', { part: 'payload', names: token.duplicates.payload.join(', ') }));
    if (token.loose) out.push(F('warn', 'b64.loose'));
    lintHeader(token.header, out);
    const times = timeStatus(token.payload, now, leeway);
    lintPayload(token.payload, times, out);
    lintPrivacy(token.payload, out);
    if (token.signature.length === 0 && token.header.alg !== 'none') out.push(F('danger', 'signature.empty'));
    return { findings: out, times };
  }

  // 検査の結果のうち、いちばん重い level
  const ORDER = ['danger', 'warn', 'info', 'ok'];
  const worst = (findings) => ORDER.find((l) => findings.some((f) => f.level === l)) || 'ok';

  globalThis.JwtCore = {
    ALGORITHMS,
    ALG_NAMES,
    KNOWN_UNSUPPORTED,
    HEADER_PARAMS,
    REGISTERED_CLAIMS,
    MAX_TOKEN_CHARS,
    DEFAULT_LEEWAY,
    decodeB64url,
    encodeB64url,
    utf8,
    readUtf8,
    duplicateKeys,
    parseJsonObject,
    parseToken,
    isNumericDate,
    toIso,
    duration,
    timeStatus,
    lint,
    worst
  };
})();
