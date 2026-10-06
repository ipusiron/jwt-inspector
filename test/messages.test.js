import test from 'node:test';
import assert from 'node:assert/strict';
import { read, load, core, verifier, fixtures } from './load.js';

const { MESSAGES, t } = load('js/messages.js').JwtMessages;
const C = core();
const V = verifier();
// かな・カタカナ・漢字・全角の記号
const JAPANESE = new RegExp('[' + [[0x3000, 0x303f], [0x3040, 0x30ff], [0x3400, 0x9fff], [0xff00, 0xffef]]
  .map(([a, b]) => String.fromCharCode(a) + '-' + String.fromCharCode(b)).join('') + ']');

const placeholders = (s) => [...s.matchAll(/\{([a-z0-9]+)\}/g)].map((m) => m[1]).sort();

test('日本語と英語の辞書は同じキーを持ち、置き場所 {name} と太字の数もそろう', () => {
  assert.deepEqual(Object.keys(MESSAGES.en).sort(), Object.keys(MESSAGES.ja).sort());
  assert.ok(Object.keys(MESSAGES.ja).length >= 170);
  for (const k of Object.keys(MESSAGES.ja)) {
    assert.deepEqual(placeholders(MESSAGES.en[k]), placeholders(MESSAGES.ja[k]), k);
    for (const lang of ['ja', 'en']) assert.equal((MESSAGES[lang][k].match(/\*\*/g) || []).length % 2, 0, `${lang} ${k}`);
  }
});

test('英語の辞書に日本語の文字がない（言語の切り替えボタンの「日本語」を除く）', () => {
  for (const [k, v] of Object.entries(MESSAGES.en)) {
    if (k === 'ui.langButton' || k === 'ui.langLabel') continue;
    assert.doesNotMatch(v, JAPANESE, k);
  }
});

test('日本語の文言は、日本語と英数字のあいだに半角空白を入れない。「ブラウザ」でなく「ブラウザー」', () => {
  const bad = new RegExp(`(${JAPANESE.source} [A-Za-z0-9(])|([A-Za-z0-9)] ${JAPANESE.source})`);
  for (const [k, v] of Object.entries(MESSAGES.ja)) {
    assert.doesNotMatch(v, bad, k);
    assert.doesNotMatch(v, /ブラウザ(?!ー)/, k);
  }
});

test('計算部が返しうるコードは、すべて辞書にある（検査・読み取りの誤り・検証の誤り）', () => {
  // 検査（lint.*）
  const lintCodes = new Set();
  const src = read('js/jwt-core.js');
  for (const m of src.matchAll(/F\('(?:danger|warn|info|ok)', '([a-zA-Z0-9.]+)'/g)) lintCodes.add(m[1]);
  for (const m of src.matchAll(/F\(known \? 'info' : 'warn', known \? '([a-zA-Z0-9.]+)' : '([a-zA-Z0-9.]+)'/g)) {
    lintCodes.add(m[1]);
    lintCodes.add(m[2]);
  }
  for (const m of src.matchAll(/F\('(?:danger|warn)', `\$\{claim\}\.([a-z]+)`/g)) for (const c of ['exp', 'nbf', 'iat']) lintCodes.add(`${c}.${m[1]}`);
  assert.ok(lintCodes.size >= 25, String(lintCodes.size));
  for (const code of lintCodes) assert.ok(MESSAGES.ja[`lint.${code}`], `lint.${code}`);

  // 読み取りの誤り（err.*）。部分の前置きと組み合わせる
  const base = ['b64.char', 'b64.padding', 'b64.standard', 'b64.length', 'json.utf8', 'json.syntax', 'json.notObject'];
  for (const part of ['header', 'payload']) for (const code of base) assert.ok(MESSAGES.ja[`err.${part}.${code}`], `${part}.${code}`);
  for (const code of base.filter((c) => c.startsWith('b64'))) assert.ok(MESSAGES.ja[`err.signature.${code}`], code);
  for (const code of ['token.empty', 'token.long', 'token.parts']) assert.ok(MESSAGES.ja[`err.${code}`], code);

  // 検証の誤り（verr.*）
  const vsrc = read('js/jwt-verify.js');
  const vcodes = new Set([...vsrc.matchAll(/fail\('([a-zA-Z0-9.#]+)'/g)].map((m) => m[1]));
  for (const m of vsrc.matchAll(/code: '([a-zA-Z0-9.]+)'/g)) vcodes.add(m[1]);
  assert.ok(vcodes.size >= 12, String(vcodes.size));
  for (const code of vcodes) assert.ok(MESSAGES.ja[`verr.${code}`], `verr.${code}`);
});

test('画面のスクリプトが使うキーは、すべて辞書にある（組み立てるキーも含む）', () => {
  const src = ['script.js', 'js/theme.js', 'js/workbench-ui.js'].map(read).join('\n');
  const keys = [...src.matchAll(/\bt\('([a-z0-9]+\.[A-Za-z0-9.]+)'/g)].map((m) => m[1]);
  assert.ok(keys.length >= 14, String(keys.length));
  for (const k of keys) assert.ok(MESSAGES.ja[k] !== undefined, k);
  for (const level of ['danger', 'warn', 'info', 'ok']) assert.ok(MESSAGES.ja[`level.${level}`], level);
  for (const state of ['ok', 'expired', 'leeway', 'notYet', 'future', 'missing', 'type']) assert.ok(MESSAGES.ja[`time.${state}`], state);
  for (const unit of ['day', 'hour', 'minute', 'second']) assert.ok(MESSAGES.ja[`dur.${unit}`], unit);
  for (const claim of C.REGISTERED_CLAIMS) assert.ok(MESSAGES.ja[`claim.${claim}`], claim);
  for (const group of ['HS', 'RS']) for (const part of ['keyLabel', 'keyHint']) assert.ok(MESSAGES.ja[`verify.${part}.${group}`], group);
  for (const kind of ['pem', 'jwk', 'raw']) assert.ok(MESSAGES.ja[`verify.keyKind.${kind}`], kind);
  for (const part of ['header', 'payload']) assert.ok(MESSAGES.ja[`decode.${part}`], part);
  for (const name of Object.keys(load('js/samples.js').JwtSamples.decode)) assert.ok(MESSAGES.ja[`decode.sample.${name}`], name);
});

test('画面のスクリプトと計算部に日本語の文字列を直接書かない（文言は辞書に置く）', () => {
  for (const f of ['script.js', 'js/jwt-core.js', 'js/jwt-verify.js', 'js/jwt-create.js', 'js/jwt-lab.js',
    'js/workbench-ui.js', 'js/theme.js', 'js/i18n.js']) {
    const code = read(f).split('\n').filter((line) => !/^\s*\/\//.test(line)).map((line) => line.replace(/\s\/\/.*$/, '')).join('\n');
    for (const m of code.matchAll(/'[^'\n]*'|`[^`\n]*`/g)) assert.doesNotMatch(m[0], JAPANESE, `${f}: ${m[0]}`);
  }
});

test('t は置き場所を値で埋め、未知のキーはキーのまま返す', () => {
  assert.equal(t('err.token.parts', { count: 2 }, 'ja'), 'ドットで区切られた3つの部分が必要です（いまは2個）。');
  assert.equal(t('err.token.parts', { count: 2 }, 'en'), 'Three dot-separated parts are required (now 2).');
  assert.equal(t('no.such.key', {}, 'ja'), 'no.such.key');
});

test('文言の中の数値は、計算部や RFC の値と同じ（鍵の長さ・猶予・対応アルゴリズム）', () => {
  assert.match(MESSAGES.ja['verify.keyHint.HS'], new RegExp(`HS256なら${V.MIN_HS_BITS[256]}ビット＝${V.MIN_HS_BITS[256] / 8}バイト以上`));
  assert.match(MESSAGES.en['verify.keyHint.HS'], new RegExp(`${V.MIN_HS_BITS[256]} bits, or ${V.MIN_HS_BITS[256] / 8} bytes, for HS256`));
  assert.match(MESSAGES.ja['learn.key.body'], new RegExp(`HS256なら${V.MIN_HS_BITS[256]}ビット`));
  assert.match(MESSAGES.ja['learn.key.body'], new RegExp(`RSAは${V.MIN_RSA_BITS}ビット以上`));
  assert.match(MESSAGES.en['learn.key.body'], new RegExp(`${V.MIN_RSA_BITS} bits or more`));
  assert.ok(MESSAGES.ja['ui.subtitle'].includes('HS・RS・PS・ES'));
  // 猶予の秒数は画面が計算部の値を入れるので、文言には埋め込まない
  assert.ok(MESSAGES.ja['decode.now'].includes('{leeway}'));
  assert.equal(C.DEFAULT_LEEWAY, 60);
});

test('サンプルの鍵の長さは、文言が求める長さを満たす（弱い鍵の例を除く）', () => {
  const samples = load('js/samples.js').JwtSamples;
  assert.equal(samples.verify.HS256.key.length * 8, 512);
  assert.ok(samples.verify.weak.key.length * 8 < V.MIN_HS_BITS[256]);
  assert.equal(samples.verify.HS256.key, fixtures.demoKey);
});

test('作成・小辞書・再現実験の全エラーと動的状態に日英の文言がある', () => {
  const src = ['js/jwt-create.js', 'js/jwt-lab.js'].map(read).join('\n');
  const codes = new Set([...src.matchAll(/fail\('([a-zA-Z0-9.]+)'/g)].map((m) => m[1]));
  for (const part of ['header', 'payload']) {
    for (const code of ['json.syntax', 'json.notObject', 'json.utf8', 'json.duplicate']) codes.add(`${part}.${code}`);
  }
  assert.ok(codes.size >= 25, String(codes.size));
  for (const lang of ['ja', 'en']) {
    for (const code of codes) {
      assert.ok(['werr', 'err', 'verr'].some((prefix) => MESSAGES[lang][`${prefix}.${code}`]), `${lang}: ${code}`);
    }
    for (const suffix of ['found', 'notFound', 'cancelled']) assert.ok(MESSAGES[lang][`audit.${suffix}`], suffix);
    for (const mode of ['none', 'confusion']) assert.ok(MESSAGES[lang][`lab.detail.${mode}`], mode);
    for (const suffix of ['copied', 'copyFailed', 'sentDecode', 'sentVerify']) assert.ok(MESSAGES[lang][`work.${suffix}`], suffix);
    for (const suffix of ['original', 'modified', 'accepted', 'rejected']) assert.ok(MESSAGES[lang][`lab.${suffix}`], suffix);
  }
});

test('小辞書の説明にある上限と既定候補数は計算部に一致する', () => {
  load('js/jwt-create.js');
  const L = load('js/jwt-lab.js').JwtLab;
  for (const lang of ['ja', 'en']) {
    for (const value of [L.MAX_CANDIDATES, L.MAX_CANDIDATE_BYTES, L.MAX_CANDIDATES_CHARS]) {
      assert.ok(MESSAGES[lang]['audit.limits'].includes(String(value)), `${lang}: ${value}`);
    }
    assert.ok(MESSAGES[lang]['audit.defaults'].includes(String(L.DEFAULT_CANDIDATES.length)), lang);
  }
});
