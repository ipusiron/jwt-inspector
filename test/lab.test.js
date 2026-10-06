import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import '../js/jwt-core.js';
import '../js/jwt-verify.js';
import '../js/samples.js';
import '../js/jwt-create.js';
import '../js/jwt-lab.js';

const C = globalThis.JwtCore;
const V = globalThis.JwtVerify;
const L = globalThis.JwtLab;
const S = globalThis.JwtSamples;
const nativeToken = (key, header = { alg: 'HS256', typ: 'JWT' }) => {
  const input = [header, { sub: 'local-test' }].map((value) => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${input}.${crypto.createHmac('sha256', key).update(input).digest('base64url')}`;
};

test('HS256の小辞書で一致した鍵・件数・進捗を返し、候補になければnotFoundを返す', async () => {
  const progress = [];
  const token = nativeToken('local-key');
  const found = await L.checkWeakKey(token, 'one\nlocal-key\nthree', { onProgress: (value) => progress.push(value) });
  assert.deepEqual(found, { ok: true, status: 'found', tested: 2, total: 3, key: 'local-key' });
  assert.deepEqual(progress, [{ tested: 0, total: 3 }, { tested: 1, total: 3 }, { tested: 2, total: 3 }]);
  assert.deepEqual(await L.checkWeakKey(token, 'one\ntwo'), { ok: true, status: 'notFound', tested: 2, total: 2 });
  const defaults = await L.checkWeakKey(nativeToken('secret'));
  assert.equal(defaults.status, 'found');
  assert.equal(defaults.total, L.DEFAULT_CANDIDATES.length);
  assert.equal(defaults.key, 'secret');
});

test('候補はUnicodeと前後の空白をそのまま使い、LF・CRLF・CRを行区切りとして読む', async () => {
  const key = '  鍵😀  ';
  const found = await L.checkWeakKey(nativeToken(key), '\r\nwrong\n  鍵😀  \r\nlast\r');
  assert.deepEqual(found, { ok: true, status: 'found', tested: 2, total: 3, key });
  const spaces = await L.checkWeakKey(nativeToken(' '), '\n \n');
  assert.equal(spaces.status, 'found');
  assert.equal(spaces.key, ' ');
  assert.equal((await L.checkWeakKey(nativeToken(key), key.trim())).status, 'notFound');
});

test('候補数・候補UTF-8バイト数・全体文字数は上限まで受け付け、上限を超えると拒む', async () => {
  const token = nativeToken('secret');
  const maximum = ['secret', ...Array.from({ length: L.MAX_CANDIDATES - 1 }, (_, i) => `k${i}`)];
  const found = await L.checkWeakKey(token, maximum.join('\n'));
  assert.equal(found.total, L.MAX_CANDIDATES);
  assert.equal(found.status, 'found');
  assert.equal((await L.checkWeakKey(token, [...maximum, 'extra'].join('\n'))).code, 'candidates.count');
  const longKey = 'a'.repeat(L.MAX_CANDIDATE_BYTES);
  assert.equal((await L.checkWeakKey(nativeToken(longKey), longKey)).status, 'found');
  assert.equal((await L.checkWeakKey(token, longKey + 'a')).code, 'candidate.long');
  const unicodeKey = '鍵'.repeat(Math.floor(L.MAX_CANDIDATE_BYTES / 3));
  assert.equal((await L.checkWeakKey(nativeToken(unicodeKey), unicodeKey)).status, 'found');
  assert.equal((await L.checkWeakKey(token, unicodeKey + '鍵')).code, 'candidate.long');
  assert.equal((await L.checkWeakKey(token, 'x'.repeat(L.MAX_CANDIDATES_CHARS + 1))).code, 'candidates.long');
  assert.equal((await L.checkWeakKey(token, '\n\r\n')).code, 'candidates.empty');
});

test('壊れたトークン、HS256以外、空・長さの違う署名、未対応のヘッダーを検査しない', async () => {
  assert.equal((await L.checkWeakKey('x.y', 'secret')).code, 'token.parts');
  for (const alg of ['HS384', 'none', 'RS256', 'constructor']) {
    assert.equal((await L.checkWeakKey(nativeToken('secret', { alg }), 'secret')).code, 'alg.hs256');
  }
  const input = nativeToken('secret').split('.').slice(0, 2).join('.');
  assert.equal((await L.checkWeakKey(`${input}.`, 'secret')).code, 'signature.empty');
  assert.equal((await L.checkWeakKey(`${input}.AA`, 'secret')).code, 'signature.length');
  const duplicate = Buffer.from('{"alg":"HS256","alg":"HS256"}').toString('base64url');
  assert.equal((await L.checkWeakKey(`${duplicate}.${input.split('.')[1]}.${'A'.repeat(43)}`, 'secret')).code, 'header.json.duplicate');
  assert.equal((await L.checkWeakKey(nativeToken('secret', { alg: 'HS256', crit: ['x'] }), 'secret')).code, 'header.unsupported');
  assert.equal((await L.checkWeakKey(nativeToken('secret', { alg: 'HS256', b64: false }), 'secret')).code, 'header.unsupported');
});

test('開始前と途中に中止でき、中止したあとは一致した鍵を返さない', async () => {
  const before = new AbortController();
  before.abort();
  const token = nativeToken('secret');
  const cancelled = await L.checkWeakKey(token, 'one\nsecret', { signal: before.signal });
  assert.deepEqual(cancelled, { ok: true, status: 'cancelled', tested: 0, total: 2 });
  const during = new AbortController();
  const progress = [];
  const result = await L.checkWeakKey(token, 'one\nsecret', {
    signal: during.signal,
    onProgress: (value) => {
      progress.push(value.tested);
      if (value.tested === 1) during.abort();
    }
  });
  assert.deepEqual(result, { ok: true, status: 'cancelled', tested: 1, total: 2 });
  assert.deepEqual(progress, [0, 1]);
});

test('Web Cryptoの完了待ち中に中止した場合も、遅れて返った一致結果を破棄する', async () => {
  const original = V.verify;
  const controller = new AbortController();
  try {
    V.verify = async () => {
      controller.abort();
      return { ok: true, valid: true };
    };
    const result = await L.checkWeakKey(nativeToken('secret'), 'secret', { signal: controller.signal });
    assert.deepEqual(result, { ok: true, status: 'cancelled', tested: 0, total: 1 });
  } finally {
    V.verify = original;
  }
});

test('多数の候補を調べる途中でUIへ制御を返し、イベントによる中止を受け付ける', async () => {
  const original = V.verify;
  const controller = new AbortController();
  try {
    V.verify = async () => ({ ok: true, valid: false });
    const result = await L.checkWeakKey(nativeToken('secret'), Array(L.MAX_CANDIDATES).fill('wrong').join('\n'), {
      signal: controller.signal,
      onProgress: ({ tested }) => {
        if (tested === 1) setTimeout(() => controller.abort(), 0);
      }
    });
    assert.equal(result.status, 'cancelled');
    assert.ok(result.tested > 0 && result.tested < result.total);
  } finally {
    V.verify = original;
  }
});

test('noneの再現は署名を空にしてroleを書き換え、脆弱側だけが受理する', async () => {
  const snapshot = JSON.stringify(S.verify.RS256);
  const result = await L.runDemo('none');
  assert.ok(result.ok);
  assert.equal(result.originalToken, S.verify.RS256.token);
  assert.equal(result.publicKey, S.verify.RS256.key);
  assert.equal(result.expectedAlg, 'RS256');
  assert.equal(result.details.original.accepted, true);
  assert.equal(result.unsafeAccepted, true);
  assert.equal(result.fixedAccepted, false);
  assert.equal(result.details.fixed.code, 'alg.mismatch');
  const parsed = C.parseToken(result.token);
  assert.equal(parsed.header.alg, 'none');
  assert.equal(parsed.payload.role, 'admin');
  assert.equal(parsed.signature.length, 0);
  assert.equal(JSON.stringify(S.verify.RS256), snapshot);
});

test('confusionの再現はHS256へ変更し公開PEMでHMACを作る。RS256固定側はヘッダー段階で拒む', async () => {
  const snapshot = JSON.stringify(S.verify.RS256);
  const result = await L.runDemo('confusion');
  assert.ok(result.ok);
  assert.equal(result.details.original.accepted, true);
  assert.equal(result.unsafeAccepted, true);
  assert.equal(result.fixedAccepted, false);
  assert.equal(result.details.fixed.code, 'alg.mismatch');
  const original = C.parseToken(result.originalToken);
  assert.equal(original.header.alg, 'RS256');
  assert.ok(crypto.verify('sha256', Buffer.from(original.signingInput), result.publicKey, original.signature));
  const parsed = C.parseToken(result.token);
  assert.equal(parsed.header.alg, 'HS256');
  assert.equal(parsed.payload.role, 'admin');
  const expected = crypto.createHmac('sha256', result.publicKey).update(parsed.signingInput).digest();
  assert.deepEqual(Buffer.from(parsed.signature), expected);
  const differentPem = crypto.createHmac('sha256', result.publicKey + '\n').update(parsed.signingInput).digest();
  assert.notDeepEqual(Buffer.from(parsed.signature), differentPem);
  assert.equal((await V.verify(parsed, 'RS256', result.publicKey)).valid, false);
  assert.equal(JSON.stringify(S.verify.RS256), snapshot);
  assert.equal((await L.runDemo('unknown')).code, 'demo.mode');
});
