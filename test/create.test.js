import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import '../js/jwt-core.js';
import '../js/jwt-verify.js';
import '../js/jwt-create.js';

const C = globalThis.JwtCore;
const V = globalThis.JwtVerify;
const G = globalThis.JwtCreate;
const options = (alg, key, payload = { sub: 'local-test', role: 'reader' }) => ({
  alg, key, headerText: JSON.stringify({ alg, typ: 'JWT' }), payloadText: JSON.stringify(payload)
});

test('12種の生成鍵で署名し、既存の検証と独立したNode cryptoの両方で確認する', async () => {
  for (const alg of C.ALG_NAMES) {
    const spec = C.ALGORITHMS[alg];
    const generated = await G.generateKey(alg);
    assert.ok(generated.ok, `${alg}: ${generated.code}`);
    assert.equal(generated.alg, alg);
    const key = spec.family === 'HS' ? generated.secret : generated.privateKey;
    const signed = await G.create(options(alg, key));
    assert.ok(signed.ok, `${alg}: ${signed.code}`);
    assert.deepEqual(signed.warnings, [], alg);
    const parsed = C.parseToken(signed.token);
    assert.ok(parsed.ok);
    assert.equal(parsed.header.alg, alg);
    const checked = await V.verify(parsed, alg, generated.secret ?? generated.publicKey);
    assert.ok(checked.ok && checked.valid && !checked.mismatch, alg);
    if (spec.family === 'HS') {
      assert.equal(C.decodeB64url(generated.secret).bytes.length, spec.bits / 8);
      const expected = crypto.createHmac(`sha${spec.bits}`, generated.secret).update(parsed.signingInput).digest();
      assert.deepEqual(Buffer.from(parsed.signature), expected, alg);
      assert.equal(generated.privateKey, undefined);
    } else {
      assert.equal(generated.privateKey.type, 'private');
      assert.equal(generated.privateKey.extractable, false);
      assert.deepEqual(generated.privateKey.usages, ['sign']);
      await assert.rejects(crypto.webcrypto.subtle.exportKey('pkcs8', generated.privateKey));
      assert.match(generated.publicKey, /^-----BEGIN PUBLIC KEY-----\n/);
      assert.doesNotMatch(generated.publicKey, /PRIVATE/);
      const verifyOptions = { key: generated.publicKey };
      if (spec.family === 'PS') Object.assign(verifyOptions, { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: spec.bits / 8 });
      if (spec.family === 'ES') verifyOptions.dsaEncoding = 'ieee-p1363';
      assert.ok(crypto.verify(`sha${spec.bits}`, Buffer.from(parsed.signingInput), verifyOptions, parsed.signature), alg);
      if (spec.family === 'ES') assert.equal(parsed.signature.length, { ES256: 64, ES384: 96, ES512: 132 }[alg]);
      if (spec.family === 'PS') {
        assert.equal(crypto.verify(`sha${spec.bits}`, Buffer.from(parsed.signingInput), {
          ...verifyOptions, saltLength: spec.bits / 8 - 1
        }, parsed.signature), false, alg);
      }
    }
  }
});

test('Unicodeの共有鍵とJSONをUTF-8で署名し、入力した空白も署名対象に残す', async () => {
  const key = '  鍵😀 café  ';
  const headerText = ' { "alg" : "HS256", "typ" : "JWT" } ';
  const payloadText = JSON.stringify({ sub: '利用者😀', note: 'é / é' });
  const signed = await G.create({ alg: 'HS256', key, headerText, payloadText });
  assert.ok(signed.ok);
  const parsed = C.parseToken(signed.token);
  assert.equal(parsed.headerText, headerText);
  assert.equal(parsed.payloadText, payloadText);
  const expected = crypto.createHmac('sha256', Buffer.from(key, 'utf8')).update(parsed.signingInput).digest();
  assert.deepEqual(Buffer.from(parsed.signature), expected);
  assert.deepEqual(signed.warnings, V.keyWarnings('HS256', Buffer.byteLength(key, 'utf8') * 8));
  assert.equal((await V.verify(parsed, 'HS256', key.trim())).valid, false);
});

test('作成用JSONはオブジェクトで、重複・alg不一致・未対応のcrit/b64を拒む', async () => {
  const base = options('HS256', 'synthetic-test-secret');
  const cases = [
    ['headerText', '{', 'header.json.syntax'],
    ['headerText', '[]', 'header.json.notObject'],
    ['payloadText', 'null', 'payload.json.notObject'],
    ['payloadText', '{', 'payload.json.syntax'],
    ['headerText', '{"alg":"HS256","alg":"HS256"}', 'header.json.duplicate'],
    ['headerText', String.raw`{"alg":"HS256","\u0061lg":"HS256"}`, 'header.json.duplicate'],
    ['payloadText', '{"sub":"a","sub":"b"}', 'payload.json.duplicate'],
    ['payloadText', String.raw`{"sub":"a","\u0073ub":"b"}`, 'payload.json.duplicate'],
    ['headerText', '{}', 'alg.mismatch'],
    ['headerText', '{"alg":"RS256"}', 'alg.mismatch'],
    ['headerText', '{"alg":"HS256","crit":[]}', 'header.unsupported'],
    ['headerText', '{"alg":"HS256","crit":null}', 'header.unsupported'],
    ['headerText', '{"alg":"HS256","b64":false}', 'header.unsupported']
  ];
  for (const [field, value, code] of cases) assert.equal((await G.create({ ...base, [field]: value })).code, code, value);
});

test('noneと継承プロパティ名はアルゴリズムとして使えず、共有鍵は空でない文字列に限る', async () => {
  for (const alg of ['none', 'HS1024', 'constructor', 'toString', '__proto__', undefined]) {
    assert.equal((await G.generateKey(alg)).code, 'alg.unsupported');
    assert.equal((await G.create(options(alg, 'test'))).code, 'alg.unsupported');
  }
  assert.equal((await G.create(options('HS256', ''))).code, 'key.empty');
  for (const key of [null, undefined, {}, new Uint8Array([1, 2, 3])]) {
    assert.equal((await G.create(options('HS256', key))).code, 'key.type');
  }
  const short = await G.create(options('HS256', 'short'));
  assert.ok(short.ok);
  assert.equal(short.warnings[0].code, 'key.hsShort');
});

test('秘密鍵はこのモジュールの生成鍵だけを受け付け、生成時のアルゴリズムに固定する', async () => {
  const generated = await G.generateKey('ES256');
  assert.ok(generated.ok);
  assert.equal((await G.create(options('ES384', generated.privateKey))).code, 'key.algorithm');
  assert.equal((await G.create(options('RS256', generated.privateKey))).code, 'key.algorithm');
  for (const key of [generated.publicKey, { type: 'private', extractable: false }, undefined]) {
    assert.equal((await G.create(options('ES256', key))).code, 'key.generatedRequired');
  }
  const other = await crypto.webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  assert.equal((await G.create(options('ES256', other.privateKey))).code, 'key.generatedRequired');
});

test('作ったトークンは既存の文字数上限内に限る。Unicodeのエンコードによる増加も数える', async () => {
  const base = options('HS256', 'test');
  const payload = (n) => JSON.stringify({ value: 'a'.repeat(n) });
  const length = (n) => Buffer.from(base.headerText).toString('base64url').length
    + Buffer.from(payload(n)).toString('base64url').length + 2 + 43;
  let low = 0;
  let high = C.MAX_TOKEN_CHARS;
  while (low + 1 < high) {
    const mid = Math.floor((low + high) / 2);
    if (length(mid) <= C.MAX_TOKEN_CHARS) low = mid;
    else high = mid;
  }
  const signed = await G.create({ ...base, payloadText: payload(low) });
  assert.ok(signed.ok);
  assert.equal(signed.token.length, length(low));
  assert.ok(C.parseToken(signed.token).ok);
  assert.equal((await G.create({ ...base, payloadText: payload(high) })).code, 'token.long');
  assert.equal((await G.create(options('HS256', 'test', { value: '鍵'.repeat(5000) }))).code, 'token.long');
  assert.equal((await G.create({ ...base, payloadText: 'x'.repeat(C.MAX_TOKEN_CHARS + 1) })).code, 'token.long');
});

test('Web Cryptoを使えない環境では理由を返す', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
    assert.equal((await G.generateKey('HS256')).code, 'crypto.missing');
    assert.equal((await G.create(options('HS256', 'test'))).code, 'crypto.missing');
  } finally {
    Object.defineProperty(globalThis, 'crypto', descriptor);
  }
});
