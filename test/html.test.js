import test from 'node:test';
import assert from 'node:assert/strict';
import { read, load, core } from './load.js';

const html = read('index.html');
const C = core();
const { MESSAGES, t } = load('js/messages.js').JwtMessages;
const { parseVars } = load('js/i18n.js').JwtI18n;
const SCRIPTS = ['script.js', 'js/jwt-core.js', 'js/jwt-verify.js', 'js/jwt-create.js', 'js/jwt-lab.js', 'js/workbench-ui.js',
  'js/samples.js', 'js/messages.js', 'js/i18n.js', 'js/theme.js', 'js/theme-init.js'];
const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
const TABS = ['decode', 'verify', 'create', 'audit', 'lab', 'learn'];

test('CSP はスクリプト・スタイルを同じ場所のファイルだけに限り、unsafe-inline と外部の通信を許さない', () => {
  const csp = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/)[1];
  assert.equal(csp, "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    + "connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'");
  assert.match(html, /<meta name="referrer" content="no-referrer">/);
  assert.match(html, /<link rel="icon" href="data:,">/);
  assert.match(html, /<noscript>/);
});

test('HTML に style 属性・インラインのスクリプト・イベントハンドラーがない。外部リンクは noopener noreferrer', () => {
  assert.doesNotMatch(html, /\sstyle=/);
  assert.doesNotMatch(html, /\son[a-z]+=/i);
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  assert.deepEqual(scripts, ['js/theme-init.js', 'js/jwt-core.js', 'js/jwt-verify.js', 'js/samples.js',
    'js/jwt-create.js', 'js/jwt-lab.js', 'js/messages.js', 'js/i18n.js', 'js/theme.js', 'js/workbench-ui.js', 'script.js']);
  assert.equal((html.match(/<script/g) || []).length, scripts.length);
  for (const a of html.match(/<a [^>]*>/g)) assert.match(a, /target="_blank" rel="noopener noreferrer"/, a);
});

test('タブは WAI-ARIA の形（tablist の中はタブだけ、aria-controls の先が実在、最初のタブだけ選択）', () => {
  const nav = html.match(/<nav class="tabs" role="tablist"[\s\S]*?<\/nav>/)[0];
  assert.equal((nav.match(/<button/g) || []).length, TABS.length);
  const tabs = [...nav.matchAll(/role="tab" id="(tab-[a-z]+)" data-tab="([a-z]+)" aria-controls="(panel-[a-z]+)" aria-selected="(true|false)"/g)];
  assert.deepEqual(tabs.map((m) => [m[2], m[4]]), TABS.map((k, i) => [k, i === 0 ? 'true' : 'false']));
  for (const [, id, , panel, selected] of tabs) {
    const tag = html.match(new RegExp(`<section [^>]*id="${panel}"[^>]*>`))[0];
    assert.match(tag, new RegExp(`role="tabpanel" aria-labelledby="${id}"`), panel);
    assert.equal(/\shidden/.test(tag), selected === 'false', panel);
  }
});

test('ボタンは type="button"。入力欄には label があり、鍵とトークンの欄はスペルチェックと自動補正を切る', () => {
  for (const b of html.match(/<button[^>]*>/g)) assert.match(b, /type="button"/, b);
  for (const m of html.matchAll(/<(textarea|select|input) [^>]*id="([^"]+)"/g)) {
    assert.match(html, new RegExp(`<label [^>]*for="${m[2]}"`), m[2]);
  }
  // 入力した鍵やトークンが、スペルチェックの機能で外部へ送られないようにする
  for (const tag of html.match(/<textarea [^>]*>/g)) {
    for (const attr of ['spellcheck="false"', 'autocomplete="off"', 'autocapitalize="off"', 'autocorrect="off"']) {
      assert.ok(tag.includes(attr), `${tag}: ${attr}`);
    }
  }
});

test('動的に変わるところには aria-live がある', () => {
  for (const id of ['decode-status', 'findings-summary', 'copy-status', 'verify-result', 'verify-header-alg',
    'create-key-status', 'create-status', 'create-feedback', 'audit-status', 'lab-status', 'lab-feedback']) {
    assert.match(html, new RegExp(`id="${id}"[^>]*aria-live="polite"`), id);
  }
});

// 文言の太字（**）と改行（\n）は HTML の strong と br に当たる。HTML 側のタグを外して比べる
const plain = (s) => s.replace(/\n\s*/g, '').replace(/<br>/g, '\n').replace(/<[^>]+>/g, '')
  .replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&').trim();
const fromDict = (s) => s.replace(/\*\*/g, '');

test('data-i18n のキーは辞書にあり、HTML に書いた日本語は辞書の日本語と同じ', () => {
  let n = 0;
  for (const m of html.matchAll(/<([a-z0-9]+)([^>]*?)data-i18n="([^"]+)"([^>]*)>([\s\S]*?)<\/\1>/g)) {
    const key = m[3];
    assert.ok(MESSAGES.ja[key] !== undefined, key);
    const vars = parseVars(((m[2] + m[4]).match(/data-i18n-vars="([^"]*)"/) || [])[1]);
    assert.equal(plain(m[5]), fromDict(t(key, vars, 'ja')), key);
    n++;
  }
  assert.ok(n >= 40, String(n));
  for (const m of html.matchAll(/data-i18n-attr="([^"]+)"/g)) {
    for (const pair of m[1].split(';')) assert.ok(MESSAGES.ja[pair.split(':')[1]] !== undefined, pair);
  }
});

test('画面のスクリプトが参照する id は、すべて HTML にある', () => {
  const src = ['script.js', 'js/workbench-ui.js'].map(read).join('\n');
  const used = [...src.matchAll(/\$\('([a-z0-9-]+)'\)/g)].map((m) => m[1]);
  assert.ok(used.length >= 15, String(used.length));
  for (const id of used) assert.ok(ids.has(id), id);
  for (const part of ['header', 'payload']) assert.ok(ids.has(`out-${part}`) && ids.has(`copy-${part}`), part);
});

test('JS は innerHTML・eval を使わず、style を書き換えない。document 全体の keydown を拾わない', () => {
  for (const f of SCRIPTS) {
    const src = read(f);
    assert.doesNotMatch(src, /innerHTML|outerHTML|insertAdjacentHTML|\beval\(|new Function|document\.write/, f);
    assert.doesNotMatch(src, /\.style\b|setAttribute\('style'|cssText/, f);
    assert.doesNotMatch(src, /console\.(log|debug|info|error|warn)/, f);
    assert.doesNotMatch(src, /document\.addEventListener\('keydown'/, f);
  }
});

test('localStorage は try で囲んで読み書きする（使えない環境でも画面が止まらない）', () => {
  for (const f of SCRIPTS) {
    const src = read(f);
    const uses = (src.match(/localStorage\./g) || []).length;
    const guarded = [...src.matchAll(/try \{\s*(?:const [a-z]+ = |return )?localStorage\./g)].length;
    assert.equal(guarded, uses, f);
  }
});

test('アルゴリズムを選ぶ欄は、計算部が対応する12種類を画面の処理が入れる', () => {
  const src = read('script.js');
  assert.match(src, /for \(const alg of C\.ALG_NAMES\)/);
  assert.match(html, /<select id="alg-select" class="select"><\/select>/);
  assert.equal(C.ALG_NAMES.length, 12);
});

test('サンプルのボタンは、samples.js にあるものだけを指す', () => {
  const samples = load('js/samples.js').JwtSamples;
  const decode = [...html.matchAll(/data-sample="([a-z]+)"/g)].map((m) => m[1]);
  assert.deepEqual(decode, Object.keys(samples.decode));
  const verify = [...html.matchAll(/data-verify-sample="([A-Za-z0-9]+)"/g)].map((m) => m[1]);
  assert.deepEqual(verify, Object.keys(samples.verify));
  for (const v of Object.values(samples.verify)) assert.ok(C.ALGORITHMS[v.alg], v.alg);
});

test('サンプルのトークンは、どれも読める形になっている', () => {
  const samples = load('js/samples.js').JwtSamples;
  for (const [name, token] of Object.entries(samples.decode)) assert.ok(C.parseToken(token).ok, name);
  for (const [name, v] of Object.entries(samples.verify)) assert.ok(C.parseToken(v.token).ok, name);
});

test('samples.js に秘密鍵が入っていない（公開鍵とデモ用の共有鍵だけ）', () => {
  const src = read('js/samples.js');
  assert.doesNotMatch(src, /BEGIN (RSA |EC )?PRIVATE KEY/);
  assert.doesNotMatch(src, /"d"\s*:/); // JWK の秘密の成分
});

test('IDは重複せず、再現実験の入力は組み込みモードだけ、生成結果は読み取り専用', () => {
  assert.equal(ids.size, [...html.matchAll(/\sid="([^"]+)"/g)].length);
  const lab = html.match(/<section [^>]*id="panel-lab"[\s\S]*?<\/section>/)[0];
  const modes = [...lab.matchAll(/<option value="([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual(modes, ['none', 'confusion']);
  assert.equal((lab.match(/<input/g) || []).length, 0);
  for (const id of ['create-public', 'create-output', 'audit-key', 'lab-original', 'lab-token', 'lab-public']) {
    assert.match(html.match(new RegExp(`<textarea id="${id}"[^>]*>`))[0], /\sreadonly(?:\s|>)/, id);
  }
});

test('作成・辞書・再現実験に通信と保存のAPIを入れない', () => {
  for (const f of ['js/jwt-create.js', 'js/jwt-lab.js', 'js/workbench-ui.js']) {
    assert.doesNotMatch(read(f), /\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|localStorage|sessionStorage|indexedDB/, f);
  }
});
