import test from 'node:test';
import assert from 'node:assert/strict';
import { core, fixtures } from './load.js';

const C = core();
const NOW = 1800000000; // 2027-01-15T08:00:00Z（固定の「いま」）
const codes = (r) => r.findings.map((f) => f.code);
const byCode = (r, code) => r.findings.find((f) => f.code === code);
const parsed = (t) => {
  const r = C.parseToken(t);
  assert.ok(r.ok, JSON.stringify(r));
  return r;
};
const b64 = (obj) => C.encodeB64url(C.utf8(JSON.stringify(obj)));
const makeToken = (header, payload, sig = 'AAAA') => `${b64(header)}.${b64(payload)}.${sig}`;

test('Base64url は RFC 7515 §2 の形（= を付けない）で読み書きし、誤りは種類と位置を返す', () => {
  assert.equal(C.encodeB64url(C.utf8('f')), 'Zg');
  assert.equal(C.encodeB64url(C.utf8('fo')), 'Zm8');
  assert.equal(C.encodeB64url(C.utf8('foobar')), 'Zm9vYmFy');
  assert.equal(C.encodeB64url(Uint8Array.from([0xfb, 0xff])), '-_8');
  assert.deepEqual([...C.decodeB64url('-_8').bytes], [0xfb, 0xff]);
  assert.deepEqual(C.decodeB64url('Zg=='), { ok: false, code: 'b64.padding', pos: 3, ch: '=' });
  assert.deepEqual(C.decodeB64url('+/8').code, 'b64.standard');
  assert.deepEqual(C.decodeB64url('Zm9v!').code, 'b64.char');
  assert.equal(C.decodeB64url('Zm9v!').pos, 5);
  assert.equal(C.decodeB64url('Zm9vY').code, 'b64.length');
  assert.equal(C.decodeB64url('Zh').loose, true); // 余りのビットが0でない
  assert.equal(C.decodeB64url('Zg').loose, false);
  for (let n = 0; n < 40; n++) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 255);
    const r = C.decodeB64url(C.encodeB64url(bytes));
    assert.ok(r.ok && [...r.bytes].join() === [...bytes].join(), String(n));
  }
});

test('JSON は重複したメンバー名を見つける（RFC 7515 §4 は重複しないことを求める）', () => {
  assert.deepEqual(C.duplicateKeys('{"a":1,"b":2}'), []);
  assert.deepEqual(C.duplicateKeys('{"a":1,"a":2}'), ['a']);
  assert.deepEqual(C.duplicateKeys('{"alg":"HS256","alg":"none"}'), ['alg']);
  assert.deepEqual(C.duplicateKeys('{"a":{"b":1,"b":2}}'), []); // 入れ子の中は数えない
  assert.deepEqual(C.duplicateKeys('{"a":"x\\":1,\\"a","a":2}'), ['a']); // 値の中の " は名前でない
  assert.deepEqual(C.duplicateKeys('{"a":["x","y"],"a":1}'), ['a']);
});

test('トークンの分解は3つの部分を読み、誤りの場所（header・payload・signature）を前に付ける', () => {
  const t = parsed(fixtures.decode.valid);
  assert.equal(t.header.alg, 'HS256');
  assert.equal(t.payload.iss, 'https://issuer.example');
  assert.equal(t.signingInput, `${t.raw.header}.${t.raw.payload}`);
  assert.equal(C.parseToken('').code, 'token.empty');
  assert.deepEqual([C.parseToken('a.b').code, C.parseToken('a.b').count], ['token.parts', 2]);
  assert.equal(C.parseToken('a.b.c.d').code, 'token.parts');
  assert.equal(C.parseToken('e!!.e30.x').code, 'header.b64.char');
  assert.equal(C.parseToken('e30.e!!.x').code, 'payload.b64.char');
  assert.equal(C.parseToken('e30.e30.!').code, 'signature.b64.char');
  assert.equal(C.parseToken(`${b64({ alg: 'none' })}.MTIz.`).code, 'payload.json.notObject');
  assert.equal(C.parseToken('eyJ9.e30.AAAA').code, 'header.json.syntax');
  assert.equal(C.parseToken('x'.repeat(C.MAX_TOKEN_CHARS + 1)).code, 'token.long');
  assert.equal(parsed(`${b64({ alg: 'none' })}.${b64({ a: 1 })}.`).signature.length, 0);
});

test('時刻の判定は RFC 7519 §4.1.4〜§4.1.6（exp と同じ秒は期限切れ、猶予は時計のずれの分）', () => {
  const t = (p) => C.timeStatus(p, 1000, 60);
  assert.equal(t({ exp: 1001 }).exp.state, 'ok');
  assert.equal(t({ exp: 1000 }).exp.state, 'leeway'); // exp と同じ秒は受け付けない
  assert.equal(t({ exp: 999 }).exp.state, 'leeway');
  assert.equal(t({ exp: 940 }).exp.state, 'expired');
  assert.equal(t({ nbf: 1000 }).nbf.state, 'ok');
  assert.equal(t({ nbf: 1001 }).nbf.state, 'leeway');
  assert.equal(t({ nbf: 1061 }).nbf.state, 'notYet');
  assert.equal(t({ iat: 1060 }).iat.state, 'ok');
  assert.equal(t({ iat: 1061 }).iat.state, 'future');
  assert.equal(t({}).exp.state, 'missing');
  assert.equal(t({ exp: '1001' }).exp.state, 'type');
  assert.equal(C.toIso(1767225600), '2026-01-01T00:00:00Z');
  assert.equal(C.DEFAULT_LEEWAY, 60);
});

test('alg の検査（none、大文字小文字違い、未対応、未登録）', () => {
  const lintOf = (header, payload = {}) => C.lint(parsed(makeToken(header, payload)), NOW);
  assert.ok(codes(lintOf({ alg: 'none' })).includes('alg.none'));
  for (const alg of ['None', 'NONE', 'nOnE']) {
    const r = lintOf({ alg });
    assert.ok(codes(r).includes('alg.noneCase'), alg);
    assert.equal(byCode(r, 'alg.noneCase').level, 'danger');
  }
  assert.ok(codes(lintOf({})).includes('alg.missing'));
  assert.ok(codes(lintOf({ alg: 123 })).includes('alg.type'));
  assert.equal(byCode(lintOf({ alg: 'EdDSA' }), 'alg.unsupported').level, 'info');
  assert.equal(byCode(lintOf({ alg: 'HS1024' }), 'alg.unknown').level, 'warn');
  for (const alg of C.ALG_NAMES) assert.ok(codes(lintOf({ alg })).includes('alg.ok'), alg);
  assert.equal(C.ALG_NAMES.length, 12);
  assert.deepEqual(C.ALG_NAMES.filter((a) => a.startsWith('ES')).map((a) => C.ALGORITHMS[a].curve), ['P-256', 'P-384', 'P-521']);
});

test('ヘッダーの検査（jku・x5u・jwk・kid・crit・typ・登録外）', () => {
  const lintOf = (header) => C.lint(parsed(makeToken({ alg: 'HS256', ...header }, {})), NOW);
  for (const param of ['jku', 'x5u']) {
    const r = lintOf({ [param]: 'https://attacker.example/jwks.json' });
    assert.equal(byCode(r, 'header.url').level, 'danger');
    assert.equal(byCode(r, 'header.url').vars.param, param);
  }
  assert.equal(byCode(lintOf({ jwk: { kty: 'RSA' } }), 'header.jwk').level, 'danger');
  assert.equal(byCode(lintOf({ kid: '../../etc/passwd' }), 'header.kid').vars.kid, '../../etc/passwd');
  assert.ok(codes(lintOf({ crit: ['exp'] })).includes('header.crit'));
  assert.ok(codes(lintOf({})).includes('typ.missing'));
  assert.ok(!codes(lintOf({ typ: 'JWT' })).includes('typ.unusual'));
  assert.ok(!codes(lintOf({ typ: 'secevent+jwt' })).includes('typ.unusual')); // RFC 8725 §3.11
  assert.ok(codes(lintOf({ typ: 'JWS' })).includes('typ.unusual'));
  assert.equal(byCode(lintOf({ foo: 1, bar: 2 }), 'header.extra').vars.names, 'foo, bar');
});

test('クレームの検査（exp・nbf・iat・iss・aud・jti・型）', () => {
  const lintOf = (payload) => C.lint(parsed(makeToken({ alg: 'HS256', typ: 'JWT' }, payload)), NOW);
  const full = { iss: 'https://i.example', aud: 'a', sub: 's', jti: '1', exp: NOW + 100, iat: NOW - 100 };
  assert.deepEqual(codes(lintOf(full)).filter((c) => c !== 'alg.ok' && c !== 'payload.readable'), ['exp.ok']);
  assert.equal(byCode(lintOf({ ...full, exp: NOW - 1000 }), 'exp.expired').vars.ago, 1000);
  assert.ok(codes(lintOf({ ...full, exp: undefined })).includes('exp.missing'));
  assert.equal(byCode(lintOf({ ...full, nbf: NOW + 1000 }), 'nbf.notYet').vars.left, 1000);
  assert.equal(byCode(lintOf({ ...full, iat: NOW + 1000 }), 'iat.future').vars.ahead, 1000);
  assert.ok(codes(lintOf({ ...full, iss: undefined })).includes('iss.missing'));
  assert.ok(codes(lintOf({ ...full, iss: 1 })).includes('iss.type'));
  assert.ok(codes(lintOf({ ...full, aud: undefined })).includes('aud.missing'));
  assert.ok(codes(lintOf({ ...full, aud: '' })).includes('aud.empty'));
  assert.ok(codes(lintOf({ ...full, aud: [] })).includes('aud.empty'));
  assert.ok(!codes(lintOf({ ...full, aud: ['a', 'b'] })).includes('aud.type')); // 配列も認める
  assert.ok(codes(lintOf({ ...full, aud: [1] })).includes('aud.type'));
  assert.ok(codes(lintOf({ ...full, aud: { a: 1 } })).includes('aud.type'));
  assert.ok(codes(lintOf({ ...full, sub: 1 })).includes('sub.type'));
  assert.ok(codes(lintOf({ ...full, jti: undefined })).includes('jti.missing'));
  assert.ok(codes(lintOf({ ...full, exp: '123' })).includes('exp.type'));
});

test('ペイロードは誰でも読めるので、秘密らしい名前のクレームを知らせる', () => {
  const lintOf = (payload) => C.lint(parsed(makeToken({ alg: 'HS256' }, payload)), NOW);
  assert.ok(codes(lintOf({ sub: 'a' })).includes('payload.readable'));
  for (const name of ['password', 'api_key', 'apiKey', 'secret', 'credit_card', 'session']) {
    assert.ok(codes(lintOf({ [name]: 'x' })).includes('payload.sensitive'), name);
  }
  assert.equal(byCode(lintOf({ password: 'x', token: 'y' }), 'payload.sensitive').vars.names, 'password, token');
  assert.ok(!codes(lintOf({ name: 'x', role: 'y' })).includes('payload.sensitive'));
});

test('重複したメンバー名と、余りのビットが0でない部分、空の署名を知らせる', () => {
  const dup = `${C.encodeB64url(C.utf8('{"alg":"HS256","alg":"none"}'))}.${b64({ sub: 'a' })}.AAAA`;
  const r = C.lint(parsed(dup), NOW);
  assert.equal(byCode(r, 'json.duplicate').vars.part, 'header');
  assert.equal(byCode(r, 'json.duplicate').level, 'danger');
  const dup2 = `${b64({ alg: 'HS256' })}.${C.encodeB64url(C.utf8('{"sub":"a","sub":"b"}'))}.AAAA`;
  assert.equal(byCode(C.lint(parsed(dup2), NOW), 'json.duplicate').vars.part, 'payload');
  const empty = `${b64({ alg: 'HS256' })}.${b64({ sub: 'a' })}.`;
  assert.ok(codes(C.lint(parsed(empty), NOW)).includes('signature.empty'));
  assert.ok(!codes(C.lint(parsed(`${b64({ alg: 'none' })}.${b64({ sub: 'a' })}.`), NOW)).includes('signature.empty'));
});

test('いちばん重い level を返す（danger > warn > info > ok）', () => {
  assert.equal(C.worst([{ level: 'ok' }, { level: 'info' }]), 'info');
  assert.equal(C.worst([{ level: 'ok' }, { level: 'warn' }, { level: 'info' }]), 'warn');
  assert.equal(C.worst([{ level: 'warn' }, { level: 'danger' }]), 'danger');
  assert.equal(C.worst([]), 'ok');
});

test('サンプルのトークンは、意図した検査結果になる', () => {
  const r = (t) => C.lint(parsed(t), NOW);
  assert.equal(C.worst(r(fixtures.decode.valid).findings), 'info');
  assert.ok(codes(r(fixtures.decode.valid)).includes('exp.ok'));
  assert.ok(codes(r(fixtures.decode.expired)).includes('exp.expired'));
  assert.ok(codes(r(fixtures.decode.none)).includes('alg.none'));
  const risky = codes(r(fixtures.decode.risky));
  assert.ok(risky.includes('header.url') && risky.includes('header.kid'));
});
