import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { core, verifier, fixtures } from './load.js';

const C = core();
const V = verifier();
const parsed = (t) => {
  const r = C.parseToken(t);
  assert.ok(r.ok, JSON.stringify(r));
  return r;
};

test('12のアルゴリズムすべてで、正しい署名を PEM と JWK の両方から検証できる', async () => {
  assert.equal(Object.keys(fixtures.algs).length, 12);
  for (const [alg, v] of Object.entries(fixtures.algs)) {
    const token = parsed(v.token);
    assert.equal(token.header.alg, alg);
    const keys = v.key !== undefined ? [v.key] : [v.pem, JSON.stringify(v.jwk)];
    for (const key of keys) {
      const r = await V.verify(token, alg, key);
      assert.ok(r.ok, `${alg}: ${JSON.stringify(r)}`);
      assert.equal(r.valid, true, alg);
      assert.equal(r.mismatch, false, alg);
      assert.deepEqual(r.warnings, [], alg);
    }
  }
});

test('署名が1ビットでも変わると検証は通らない。鍵が違っても通らない', async () => {
  for (const [alg, v] of Object.entries(fixtures.algs)) {
    const key = v.key !== undefined ? v.key : v.pem;
    const [h, p, s] = v.token.split('.');
    const bytes = C.decodeB64url(s).bytes;
    bytes[0] ^= 1;
    const r = await V.verify(parsed(`${h}.${p}.${C.encodeB64url(bytes)}`), alg, key);
    assert.ok(r.ok && r.valid === false, `${alg}: ${JSON.stringify(r)}`);
  }
  const hs = parsed(fixtures.algs.HS256.token);
  assert.equal((await V.verify(hs, 'HS256', 'wrong-key')).valid, false);
  const rs = parsed(fixtures.algs.RS256.token);
  assert.equal((await V.verify(rs, 'RS256', fixtures.algs.ES256.pem)).code, 'key.import');
});

test('ペイロードを書き換えると検証は通らない（署名はヘッダーとペイロードにかかる）', async () => {
  const [h, , s] = fixtures.algs.HS256.token.split('.');
  const payload = { ...parsed(fixtures.algs.HS256.token).payload, role: 'admin' };
  const forged = `${h}.${C.encodeB64url(C.utf8(JSON.stringify(payload)))}.${s}`;
  const r = await V.verify(parsed(forged), 'HS256', fixtures.demoKey);
  assert.ok(r.ok);
  assert.equal(r.valid, false);
});

test('検証側が選んだアルゴリズムとヘッダーの alg が違えば mismatch を返す（RFC 8725 §2.1・§3.1）', async () => {
  const hs = parsed(fixtures.algs.HS256.token);
  const r = await V.verify(hs, 'HS384', fixtures.demoKey);
  assert.ok(r.ok);
  assert.deepEqual([r.valid, r.mismatch, r.alg, r.headerAlg], [false, true, 'HS384', 'HS256']);
  const same = await V.verify(hs, 'HS256', fixtures.demoKey);
  assert.deepEqual([same.valid, same.mismatch], [true, false]);
});

test('RS256 の公開鍵を HS256 の鍵として渡しても、検証は通らない（公開鍵を HMAC の鍵にする取り違え）', async () => {
  const rsPem = fixtures.algs.RS256.pem;
  const token = parsed(fixtures.algs.RS256.token);
  const forgedInput = token.signingInput;
  // 攻撃者が公開鍵を鍵として HS256 で署名し直したトークン
  const sig = crypto.createHmac('sha256', rsPem).update(forgedInput).digest();
  const forged = `${forgedInput}.${sig.toString('base64url')}`;
  const asHs = await V.verify(parsed(forged), 'HS256', rsPem);
  assert.equal(asHs.valid, true); // 鍵を固定しない実装では通ってしまう
  assert.equal(asHs.mismatch, true); // ヘッダーは RS256 なので食い違いとして知らせる
  const asRs = await V.verify(parsed(forged), 'RS256', rsPem);
  assert.equal(asRs.valid, false); // 検証側で RS256 に固定すれば通らない
});

test('鍵の長さは RFC 7518 に照らす（HS はハッシュの出力以上、RSA は2048ビット以上）', async () => {
  const r = await V.verify(parsed(fixtures.rsa1024.token), 'RS256', fixtures.rsa1024.pem);
  assert.ok(r.ok && r.valid);
  assert.deepEqual(r.warnings.map((w) => w.code), ['key.rsaShort']);
  assert.deepEqual(r.warnings[0].vars, { bits: 1024, min: 2048 });
  assert.equal(r.keyBits, 1024);
  const short = await V.verify(parsed(fixtures.algs.HS256.token), 'HS256', 'short');
  assert.deepEqual(short.warnings.map((w) => w.code), ['key.hsShort']);
  assert.deepEqual(V.keyWarnings('HS256', 256), []);
  assert.deepEqual(V.keyWarnings('HS384', 256).map((w) => w.code), ['key.hsShort']);
  assert.deepEqual(V.keyWarnings('HS512', 512), []);
  assert.deepEqual(V.keyWarnings('PS256', 1024).map((w) => w.code), ['key.rsaShort']);
  assert.deepEqual(V.keyWarnings('ES256', 256), []); // EC は曲線で決まるので長さの注意はしない
  assert.equal(V.MIN_RSA_BITS, 2048);
});

test('鍵の形が合わないものは、理由を返す（PKCS#1・証明書・秘密鍵・JWK Set・壊れた PEM）', async () => {
  const token = parsed(fixtures.algs.RS256.token);
  const es = parsed(fixtures.algs.ES256.token);
  assert.equal((await V.verify(token, 'RS256', fixtures.pkcs1)).code, 'pem.pkcs1');
  assert.equal((await V.verify(token, 'RS256', fixtures.privatePem)).code, 'pem.private');
  assert.equal((await V.verify(es, 'ES256', JSON.stringify(fixtures.privateJwk))).code, 'jwk.private');
  assert.equal((await V.verify(token, 'RS256', 'not a key')).code, 'pem.format');
  assert.equal((await V.verify(token, 'RS256', '-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----')).code, 'pem.base64');
  assert.equal((await V.verify(token, 'RS256', '{"keys":[]}')).code, 'jwk.set');
  assert.equal((await V.verify(token, 'RS256', '{"n":"a"}')).code, 'jwk.kty');
  assert.equal((await V.verify(token, 'RS256', '{bad json')).code, 'jwk.syntax');
  assert.equal((await V.verify(token, 'RS256', '[]')).code, 'jwk.notObject');
  assert.equal((await V.verify(token, 'RS256', '')).code, 'key.empty');
  assert.equal((await V.verify(token, 'HS1024', 'x')).code, 'alg.unsupported');
  const emptySig = parsed(`${fixtures.algs.RS256.token.split('.').slice(0, 2).join('.')}.`);
  assert.equal((await V.verify(emptySig, 'RS256', fixtures.algs.RS256.pem)).code, 'signature.empty');
});

test('PEM と JWK の読み取り（種類の判別と、秘密の成分の検出）', () => {
  const pem = V.parsePem(fixtures.algs.RS256.pem);
  assert.ok(pem.ok);
  assert.equal(pem.label, 'PUBLIC KEY');
  assert.equal(V.parsePem(fixtures.pkcs1).label, 'RSA PUBLIC KEY');
  assert.equal(V.parsePem('  ' + fixtures.algs.RS256.pem + '  ').ok, true); // 前後の空白は無視する
  assert.equal(V.parsePem('-----BEGIN PUBLIC KEY-----\nAA\n-----END OTHER-----').code, 'pem.format');
  const jwk = V.parseJwk(JSON.stringify(fixtures.algs.ES256.jwk));
  assert.ok(jwk.ok && jwk.value.kty === 'EC');
  for (const field of ['d', 'p', 'q', 'k']) {
    const r = V.parseJwk(JSON.stringify({ kty: 'RSA', n: 'a', e: 'AQAB', [field]: 'secret' }));
    assert.deepEqual([r.code, r.fields], ['jwk.private', field], field);
  }
});

test('サンプルの検証（HS256・RS256・PS256・ES256）はすべて通り、弱い鍵のサンプルは注意が出る', async () => {
  for (const [alg, v] of Object.entries(fixtures.verify)) {
    if (alg === 'weak') continue;
    const r = await V.verify(parsed(v.token), alg, v.key);
    assert.ok(r.ok && r.valid, `${alg}: ${JSON.stringify(r)}`);
    assert.deepEqual(r.warnings, [], alg);
  }
  const weak = fixtures.verify.weak;
  const r = await V.verify(parsed(weak.token), 'HS256', weak.key);
  assert.ok(r.ok && r.valid);
  assert.deepEqual(r.warnings.map((w) => w.code), ['key.hsShort']);
  assert.equal(fixtures.demoKey.length * 8, 512); // デモ鍵は HS512 まで満たす長さ
});
