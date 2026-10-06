import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { read } from './load.js';

// DOMの見た目はブラウザーで確認する。ここではイベントと非同期処理の順序を固定して試験する。
class Element {
  constructor(tag, attrs = {}) {
    this.tagName = tag.toUpperCase();
    this.attrs = { ...attrs };
    this.dataset = {};
    for (const [key, value] of Object.entries(attrs)) {
      if (key.startsWith('data-')) this.dataset[key.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
    }
    this.className = attrs.class || '';
    this.classList = {
      add: (name) => { this.className = [...new Set([...this.className.split(' '), name])].join(' '); },
      remove: (name) => { this.className = this.className.split(' ').filter((c) => c !== name).join(' '); }
    };
    this.value = attrs.value || '';
    this.disabled = Object.hasOwn(attrs, 'disabled');
    this.hidden = Object.hasOwn(attrs, 'hidden');
    this.children = [];
    this.listeners = {};
    this.text = '';
  }

  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map((child) => child.textContent).join(''); }
  setAttribute(name, value) { this.attrs[name] = String(value); }
  getAttribute(name) { return this.attrs[name] ?? null; }
  removeAttribute(name) { delete this.attrs[name]; }
  focus() { this.focused = true; }
  append(...children) {
    this.children.push(...children);
    if (this.tagName === 'SELECT' && this.value === '' && children.length) this.value = children[0].value;
  }
  replaceChildren(...children) { this.text = ''; this.children = [...children]; }
  addEventListener(type, callback) { (this.listeners[type] ??= []).push(callback); }
  fire(type) {
    if (type === 'click' && this.disabled) return Promise.resolve();
    return Promise.all((this.listeners[type] || []).map((callback) => callback({ preventDefault() {} })));
  }
}

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
};

function setup(realWorkbench = false) {
  const elements = [...read('index.html').matchAll(/<([a-z][a-z0-9]*)\b([^>]*)>/gi)].map(([, tag, raw]) => {
    const attrs = Object.fromEntries([...raw.matchAll(/([\w:-]+)(?:="([^"]*)")?/g)].map((m) => [m[1], m[2] ?? '']));
    return new Element(tag, attrs);
  });
  const byId = new Map(elements.filter((e) => e.attrs.id).map((e) => [e.attrs.id, e]));
  const get = (id) => {
    assert.ok(byId.has(id), `Missing element: ${id}`);
    return byId.get(id);
  };
  for (const [, id, value] of read('index.html').matchAll(/<select[^>]*id="([^"]+)"[^>]*>\s*<option value="([^"]+)"/g)) {
    get(id).value = value;
  }
  const query = (selector) => elements.filter((e) => selector.startsWith('.')
    ? e.className.split(' ').includes(selector.slice(1)) : Object.hasOwn(e.attrs, selector.slice(1, -1)));
  const document = {
    documentElement: new Element('html'), getElementById: get, querySelectorAll: query,
    createElement: (tag) => new Element(tag),
    createTextNode: (text) => { const node = new Element('text'); node.textContent = text; return node; }
  };
  const checks = [];
  const copies = [];
  const generated = [];
  const signed = [];
  const audits = [];
  const demos = [];
  const enqueue = (queue, args) => { const task = deferred(); queue.push({ args, ...task }); return task.promise; };
  const workbench = { clears: 0, renders: 0 };
  const context = vm.createContext({
    document, TextEncoder, TextDecoder, URL, URLSearchParams, AbortController,
    navigator: {
      language: 'ja',
      clipboard: { writeText: (text) => { const task = deferred(); copies.push({ text, ...task }); return task.promise; } }
    },
    location: { href: 'https://local.invalid/?lang=ja', search: '?lang=ja' }, history: { replaceState() {} },
    localStorage: { getItem: () => null, setItem() {} },
    JwtTheme: { refresh() {}, toggle() {} },
    JwtVerify: { verify: (...args) => { const task = deferred(); checks.push({ args, ...task }); return task.promise; } },
    JwtCreate: { generateKey: (...args) => enqueue(generated, args), create: (...args) => enqueue(signed, args) },
    JwtLab: {
      DEFAULT_CANDIDATES: ['secret', 'password'],
      checkWeakKey: (...args) => enqueue(audits, args), runDemo: (...args) => enqueue(demos, args)
    },
    JwtWorkbench: {
      init: (options) => {
        workbench.options = options;
        return { render: () => { workbench.renders++; }, clear: () => { workbench.clears++; } };
      }
    }
  });
  for (const file of ['js/jwt-core.js', 'js/samples.js', 'js/messages.js', 'js/i18n.js']) {
    vm.runInContext(read(file), context, { filename: file });
  }
  if (realWorkbench) vm.runInContext(read('js/workbench-ui.js'), context, { filename: 'js/workbench-ui.js' });
  vm.runInContext(read('script.js'), context, { filename: 'script.js' });
  const sample = (kind, name) => query(`[data-${kind}]`).find((e) => e.attrs[`data-${kind}`] === name).fire('click');
  const fire = (id, event = 'click') => get(id).fire(event);
  const edit = (id, value, event = 'input') => { get(id).value = value; return fire(id, event); };
  const translated = (key, vars) => context.JwtMessages.t(key, vars);
  return { get, fire, edit, sample, context, checks, copies, generated, signed, audits, demos, workbench, translated };
}

const valid = (extra = {}) => ({
  ok: true, valid: true, alg: 'HS256', headerAlg: 'HS256', mismatch: false,
  keyBits: 256, keyKind: 'raw', warnings: [], ...extra
});
const makeToken = (header, payload) => [header, payload].map((value) => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.') + '.AA';

test('入力を変える全経路で検証を無効化し、遅れて返る結果を表示しない', async () => {
  const mutations = {
    token: (ui) => ui.edit('jwt-input', ui.context.JwtSamples.decode.expired),
    key: (ui) => ui.edit('key-input', 'another-key'),
    algorithm: (ui) => ui.edit('alg-select', 'HS384', 'change'),
    decodeSample: (ui) => ui.sample('sample', 'expired'),
    verifySample: (ui) => ui.sample('verify-sample', 'RS256'),
    clear: (ui) => ui.fire('btn-clear'),
    headerAlgorithm: (ui) => ui.fire('btn-use-header-alg'),
    transfer: (ui) => ui.workbench.options.sendToken({ token: ui.context.JwtSamples.decode.valid, tab: 'decode' }),
    clearAll: (ui) => ui.fire('btn-clear-all')
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const ui = setup();
    await ui.sample('verify-sample', 'HS256');
    const pending = ui.fire('btn-verify');
    assert.equal(ui.get('btn-verify').disabled, true, name);
    await mutate(ui);
    assert.equal(ui.get('btn-verify').disabled, false, name);
    assert.equal(ui.get('verify-result').textContent, '', name);
    ui.checks[0].resolve(valid());
    await pending;
    assert.equal(ui.get('verify-result').textContent, '', name);
    assert.equal(ui.get('verify-notes').children.length, 0, name);
  }
});

test('新しい検証が始まっていれば古い完了は無視し、inputイベントなしの値変更も検出する', async () => {
  const ui = setup();
  await ui.sample('verify-sample', 'HS256');
  const first = ui.fire('btn-verify');
  await ui.edit('key-input', 'new-key');
  const second = ui.fire('btn-verify');
  ui.checks[0].resolve(valid());
  await first;
  assert.equal(ui.get('verify-result').textContent, ui.translated('verify.running'));
  assert.equal(ui.get('btn-verify').disabled, true);
  ui.checks[1].resolve(valid({ valid: false }));
  await second;
  assert.equal(ui.get('verify-result').textContent, ui.translated('verify.invalid', { alg: 'HS256' }));
  const third = ui.fire('btn-verify');
  ui.get('key-input').value = 'silent-change';
  ui.checks[2].resolve(valid());
  await third;
  assert.equal(ui.get('verify-result').textContent, '');
  assert.equal(ui.get('btn-verify').disabled, false);
});

test('隠れた検証結果・注記と実行中・エラーの状態も言語切替で翻訳し直す', async () => {
  const ui = setup();
  await ui.sample('verify-sample', 'HS256');
  const pending = ui.fire('btn-verify');
  await ui.fire('btn-lang');
  assert.equal(ui.get('verify-result').textContent, ui.translated('verify.running'));
  ui.checks[0].resolve(valid({ mismatch: true, headerAlg: 'RS256', warnings: [{ code: 'key.hsShort', vars: { bits: 40, min: 256 } }] }));
  await pending;
  assert.equal(ui.get('panel-verify').hidden, true);
  assert.equal(ui.get('verify-result').textContent, ui.translated('verify.valid', { alg: 'HS256' }));
  const english = ui.get('verify-notes').textContent;
  await ui.fire('btn-lang');
  assert.notEqual(ui.get('verify-notes').textContent, english);
  assert.ok(ui.get('verify-notes').textContent.includes(ui.translated('verify.keyBits', { bits: 256 })));
  const rejected = ui.fire('btn-verify');
  ui.checks[1].reject(new TypeError('synthetic failure'));
  await rejected;
  assert.equal(ui.get('btn-verify').disabled, false);
  await ui.fire('btn-lang');
  assert.equal(ui.get('verify-result').textContent, ui.translated('verr.verify.error', { detail: 'TypeError' }));
  await ui.edit('jwt-input', 'broken');
  await ui.fire('btn-verify');
  await ui.fire('btn-lang');
  assert.equal(ui.get('verify-result').textContent, ui.translated('err.token.parts', { count: 1 }));
});

test('不正な入力とクリアで非表示のデコード結果・コピー対象・ARIAラベルも破棄する', async () => {
  const ui = setup();
  for (const mutation of [() => ui.edit('jwt-input', 'broken'), () => ui.fire('btn-clear')]) {
    await ui.sample('sample', 'valid');
    assert.notEqual(ui.get('out-header').textContent, '');
    assert.equal(ui.get('copy-header').disabled, false);
    await mutation();
    for (const id of ['out-header', 'out-payload', 'out-signature', 'signature-title', 'findings-summary', 'times-now', 'copy-status']) {
      assert.equal(ui.get(id).textContent, '', id);
    }
    for (const id of ['findings-list', 'times-body', 'claims-body']) assert.equal(ui.get(id).children.length, 0, id);
    for (const id of ['decode-result', 'times-card', 'claims-card']) assert.equal(ui.get(id).hidden, true, id);
    for (const part of ['header', 'payload']) {
      assert.equal(ui.get(`copy-${part}`).disabled, true);
      assert.equal(ui.get(`copy-${part}`).getAttribute('aria-label'), null);
    }
  }
  await ui.fire('btn-lang');
  assert.equal(ui.get('decode-status').textContent, ui.translated('decode.cleared'));
});

test('コピーの完了は現在の入力だけに通知し、成功・失敗の通知を言語切替で描き直す', async () => {
  const ui = setup();
  await ui.sample('sample', 'valid');
  const old = ui.fire('copy-header');
  await ui.fire('btn-clear');
  ui.copies[0].resolve();
  await old;
  assert.equal(ui.get('copy-status').textContent, '');
  await ui.sample('sample', 'valid');
  const success = ui.fire('copy-payload');
  await ui.fire('btn-lang');
  ui.copies[1].resolve();
  await success;
  assert.equal(ui.get('copy-status').textContent, ui.translated('decode.copied', { name: ui.translated('decode.payload') }));
  await ui.fire('btn-lang');
  assert.equal(ui.get('copy-status').textContent, ui.translated('decode.copied', { name: ui.translated('decode.payload') }));
  const failure = ui.fire('copy-header');
  ui.copies[2].reject(new Error('clipboard'));
  await failure;
  await ui.fire('btn-lang');
  assert.equal(ui.get('copy-status').textContent, ui.translated('decode.copyFailed'));
});

test('全消去は共有鍵と新タブの鍵も破棄し、転送は検証入力と選択タブを揃える', async () => {
  const ui = setup();
  const sample = ui.context.JwtSamples.verify.RS256;
  ui.workbench.options.sendToken({ ...sample, tab: 'verify' });
  assert.equal(ui.workbench.options.getToken(), sample.token);
  assert.equal(ui.get('alg-select').value, sample.alg);
  assert.equal(ui.get('key-input').value, sample.key);
  assert.equal(ui.get('panel-verify').hidden, false);
  assert.equal(ui.get('tab-verify').focused, true);
  await ui.fire('btn-clear-all');
  assert.equal(ui.get('jwt-input').value, '');
  assert.equal(ui.get('key-input').value, '');
  assert.equal(ui.workbench.clears, 1);
  assert.equal(ui.get('out-header').textContent, '');
  assert.equal(ui.get('verify-result').textContent, '');
  assert.ok(ui.workbench.renders > 0);
});

test('継承名をヘッダーのalgに使えず、日時表示の範囲外は端末時刻もハイフンになる', async () => {
  const ui = setup();
  for (const alg of ['constructor', 'toString', '__proto__']) {
    await ui.edit('jwt-input', makeToken({ alg }, { exp: 1e20 }));
    assert.equal(ui.get('btn-use-header-alg').disabled, true, alg);
    const selected = ui.get('alg-select').value;
    await ui.fire('btn-use-header-alg');
    assert.equal(ui.get('alg-select').value, selected);
    const row = ui.get('times-body').children[0];
    assert.equal(row.children[2].textContent, '-');
    assert.equal(row.children[3].textContent, '-');
  }
  await ui.edit('alg-select', 'constructor', 'change');
  assert.equal(ui.get('verify-result').textContent, '');
});

test('鍵生成中の入力変更・例の読み込み・クリア・alg変更で遅い生成結果を破棄する', async () => {
  const mutations = {
    header: (ui) => ui.edit('create-header', '{"alg":"HS256","kid":"changed"}'),
    payload: (ui) => ui.edit('create-payload', '{"sub":"changed"}'),
    secret: (ui) => ui.edit('create-secret', 'manual-key'),
    algorithm: (ui) => ui.edit('create-alg', 'RS256', 'change'),
    example: (ui) => ui.fire('btn-create-example'),
    clear: (ui) => ui.fire('btn-create-clear'),
    all: (ui) => ui.fire('btn-clear-all')
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const ui = setup(true);
    const pending = ui.fire('btn-create-key');
    assert.equal(ui.get('btn-create-key').disabled, true, name);
    await mutate(ui);
    ui.generated[0].resolve({ ok: true, alg: 'HS256', secret: 'late-secret' });
    await pending;
    assert.notEqual(ui.get('create-secret').value, 'late-secret', name);
    assert.equal(ui.get('btn-create-key').disabled, false, name);
    assert.equal(ui.get('create-output').value, '', name);
  }
});

test('作成中の入力変更とクリアは遅い署名を捨て、保持していた公開鍵・秘密鍵も全消去で捨てる', async () => {
  const mutations = [
    (ui) => ui.edit('create-header', '{}'), (ui) => ui.edit('create-payload', '{}'),
    (ui) => ui.edit('create-secret', 'changed'), (ui) => ui.edit('create-alg', 'HS384', 'change'),
    (ui) => ui.fire('btn-create-example'), (ui) => ui.fire('btn-create-clear'), (ui) => ui.fire('btn-clear-all')
  ];
  for (const mutate of mutations) {
    const ui = setup(true);
    await ui.edit('create-secret', 'initial');
    const pending = ui.fire('btn-create-run');
    await mutate(ui);
    ui.signed[0].resolve({ ok: true, token: 'late-token', warnings: [] });
    await pending;
    assert.equal(ui.get('create-output').value, '');
    assert.equal(ui.get('create-output-group').hidden, true);
    assert.equal(ui.get('btn-create-run').disabled, false);
  }
  const ui = setup(true);
  await ui.edit('create-alg', 'RS256', 'change');
  const generating = ui.fire('btn-create-key');
  const privateKey = { type: 'private', extractable: false };
  ui.generated[0].resolve({ ok: true, alg: 'RS256', privateKey, publicKey: 'synthetic-public' });
  await generating;
  assert.equal(ui.get('create-public').value, 'synthetic-public');
  await ui.fire('btn-clear-all');
  assert.equal(ui.get('create-public').value, '');
  assert.equal(ui.get('create-secret').value, '');
  await ui.edit('create-alg', 'RS256', 'change');
  const signing = ui.fire('btn-create-run');
  assert.equal(ui.signed[0].args[0].key, null);
  ui.signed[0].resolve({ ok: false, code: 'key.generatedRequired' });
  await signing;
});

test('生成・署名完了と転送・コピー通知は言語変更後にも現在の文言を使う', async () => {
  const ui = setup(true);
  const generating = ui.fire('btn-create-key');
  await ui.fire('btn-lang');
  assert.equal(ui.get('create-key-status').textContent, ui.translated('create.keyGenerating', { alg: 'HS256' }));
  ui.generated[0].resolve({ ok: true, alg: 'HS256', secret: 'synthetic-secret' });
  await generating;
  assert.equal(ui.get('create-key-status').textContent, ui.translated('create.keyReady', { alg: 'HS256' }));
  const signing = ui.fire('btn-create-run');
  await ui.fire('btn-lang');
  assert.equal(ui.get('create-status').textContent, ui.translated('create.running'));
  const token = ui.context.JwtSamples.verify.HS256.token;
  ui.signed[0].resolve({ ok: true, token, warnings: [] });
  await signing;
  await ui.fire('btn-create-verify');
  assert.equal(ui.get('jwt-input').value, token);
  assert.equal(ui.get('key-input').value, 'synthetic-secret');
  assert.equal(ui.get('panel-verify').hidden, false);
  await ui.fire('btn-lang');
  assert.equal(ui.get('create-status').textContent, ui.translated('create.done'));
  assert.equal(ui.get('create-feedback').textContent, ui.translated('work.sentVerify'));
  const copying = ui.fire('btn-create-copy');
  await ui.fire('btn-create-clear');
  ui.copies[0].resolve();
  await copying;
  assert.equal(ui.get('create-feedback').textContent, '');
});

test('辞書検査中の全入力経路が中止し、古い進捗・発見鍵を表示しない', async () => {
  const mutations = {
    token: (ui) => ui.edit('audit-token', 'changed'),
    candidates: (ui) => ui.edit('audit-candidates', 'changed'),
    defaults: (ui) => ui.fire('btn-audit-defaults'),
    example: (ui) => ui.fire('btn-audit-example'),
    current: (ui) => ui.fire('btn-audit-current'),
    clear: (ui) => ui.fire('btn-audit-clear'),
    all: (ui) => ui.fire('btn-clear-all')
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const ui = setup(true);
    await ui.fire('btn-audit-example');
    const pending = ui.fire('btn-audit-run');
    const options = ui.audits[0].args[2];
    options.onProgress({ tested: 16, total: 32 });
    assert.equal(ui.get('audit-progress').value, 16, name);
    await mutate(ui);
    assert.equal(options.signal.aborted, true, name);
    options.onProgress({ tested: 32, total: 32 });
    ui.audits[0].resolve({ ok: true, status: 'found', key: 'late-secret', tested: 32, total: 32 });
    await pending;
    assert.equal(ui.get('audit-key').value, '', name);
    assert.equal(ui.get('audit-key-group').hidden, true, name);
    assert.equal(ui.get('audit-progress').value, 0, name);
    assert.equal(ui.get('btn-audit-run').disabled, false, name);
    assert.equal(ui.get('btn-audit-stop').disabled, true, name);
  }
});

test('辞書の進捗・中止・未発見・発見を言語切替で描き直す', async () => {
  const ui = setup(true);
  await ui.fire('btn-audit-example');
  const pending = ui.fire('btn-audit-run');
  const options = ui.audits[0].args[2];
  options.onProgress({ tested: 16, total: 32 });
  await ui.fire('btn-lang');
  assert.equal(ui.get('audit-status').textContent, ui.translated('audit.running', { tested: 16, total: 32 }));
  assert.equal(ui.get('audit-progress').getAttribute('aria-valuetext'), ui.translated('audit.running', { tested: 16, total: 32 }));
  await ui.fire('btn-audit-stop');
  assert.equal(options.signal.aborted, true);
  const cancelled = { ok: true, status: 'cancelled', tested: 16, total: 32 };
  ui.audits[0].resolve(cancelled);
  await pending;
  await ui.fire('btn-lang');
  assert.equal(ui.get('audit-status').textContent, ui.translated('audit.cancelled', cancelled));
  for (const status of ['notFound', 'found']) {
    const task = ui.fire('btn-audit-run');
    const result = { ok: true, status, tested: 32, total: 32, ...(status === 'found' ? { key: 'secret' } : {}) };
    ui.audits.at(-1).resolve(result);
    await task;
    await ui.fire('btn-lang');
    assert.equal(ui.get('audit-status').textContent, ui.translated(`audit.${status}`, result));
    assert.equal(ui.get('audit-key').value, result.key || '');
  }
});

const demoResult = (mode, token) => ({
  ok: true, mode, token, originalToken: token, publicKey: 'synthetic-public', expectedAlg: 'RS256',
  unsafeAccepted: true, fixedAccepted: false, details: { original: { accepted: true } }
});

test('再現実験はモード変更とクリアで遅い結果を破棄する', async () => {
  for (const mutate of [
    (ui) => ui.edit('lab-mode', 'confusion', 'change'), (ui) => ui.fire('btn-lab-clear'), (ui) => ui.fire('btn-clear-all')
  ]) {
    const ui = setup(true);
    const pending = ui.fire('btn-lab-run');
    await mutate(ui);
    ui.demos[0].resolve(demoResult('none', 'late-token'));
    await pending;
    for (const id of ['lab-original', 'lab-token', 'lab-public']) assert.equal(ui.get(id).value, '', id);
    assert.equal(ui.get('lab-comparison').children.length, 0);
    assert.equal(ui.get('lab-output-group').hidden, true);
    assert.equal(ui.get('btn-lab-run').disabled, false);
  }
});

test('再現実験の比較表と説明は隠れていても再翻訳し、検証転送で固定RS256を使う', async () => {
  const ui = setup(true);
  const pending = ui.fire('btn-lab-run');
  await ui.fire('btn-lang');
  assert.equal(ui.get('lab-status').textContent, ui.translated('lab.running'));
  const token = ui.context.JwtSamples.verify.RS256.token;
  ui.demos[0].resolve(demoResult('none', token));
  await pending;
  assert.equal(ui.get('lab-comparison').children[1].children[2].textContent, ui.translated('lab.rejected'));
  await ui.fire('btn-lab-verify');
  assert.equal(ui.get('jwt-input').value, token);
  assert.equal(ui.get('alg-select').value, 'RS256');
  assert.equal(ui.get('key-input').value, 'synthetic-public');
  await ui.fire('btn-lang');
  assert.equal(ui.get('panel-lab').hidden, true);
  assert.equal(ui.get('lab-detail').textContent, ui.translated('lab.detail.none'));
  assert.equal(ui.get('lab-comparison').children[1].children[2].textContent, ui.translated('lab.rejected'));
  assert.equal(ui.get('lab-feedback').textContent, ui.translated('work.sentVerify'));
});

test('イベントなしの値変更でも古い完了を捨て、生成・署名・辞書・再現のbusyを解除する', async () => {
  const cases = [
    {
      button: 'btn-create-key', input: 'create-alg', value: 'RS256', queue: 'generated',
      result: { ok: true, alg: 'HS256', secret: 'late-secret' }, outputs: ['create-secret', 'create-public', 'create-output']
    },
    {
      button: 'btn-create-run', input: 'create-payload', value: '{"sub":"silent-change"}', queue: 'signed',
      result: { ok: true, token: 'late-token', warnings: [] }, outputs: ['create-output']
    },
    {
      button: 'btn-audit-run', input: 'audit-candidates', value: 'silent-change', queue: 'audits',
      result: { ok: true, status: 'found', key: 'late-secret', tested: 32, total: 32 }, outputs: ['audit-key']
    },
    {
      button: 'btn-lab-run', input: 'lab-mode', value: 'confusion', queue: 'demos',
      result: demoResult('none', 'late-token'), outputs: ['lab-original', 'lab-token', 'lab-public']
    }
  ];
  for (const scenario of cases) {
    const ui = setup(true);
    if (scenario.queue === 'audits') await ui.fire('btn-audit-example');
    const pending = ui.fire(scenario.button);
    assert.equal(ui.get(scenario.button).disabled, true, scenario.queue);
    ui.get(scenario.input).value = scenario.value;
    ui[scenario.queue][0].resolve(scenario.result);
    await pending;
    assert.equal(ui.get(scenario.button).disabled, false, scenario.queue);
    assert.equal(ui.get(scenario.input).value, scenario.value, scenario.queue);
    for (const id of scenario.outputs) assert.equal(ui.get(id).value, '', id);
    if (scenario.queue === 'audits') {
      assert.equal(ui.audits[0].args[2].signal.aborted, true);
      assert.equal(ui.get('btn-audit-stop').disabled, true);
      assert.equal(ui.get('audit-progress').value, 0);
    }
  }
});

test('JSON例の読み込みは選択algと共有鍵・生成済み秘密鍵を保持する', async () => {
  const hs = setup(true);
  await hs.edit('create-alg', 'HS384', 'change');
  await hs.edit('create-secret', 'keep-this-secret');
  await hs.edit('create-payload', '{"sub":"replace-me"}');
  await hs.fire('btn-create-example');
  assert.equal(hs.get('create-alg').value, 'HS384');
  assert.equal(hs.get('create-secret').value, 'keep-this-secret');
  assert.equal(JSON.parse(hs.get('create-header').value).alg, 'HS384');
  assert.equal(JSON.parse(hs.get('create-payload').value).sub, 'demo-user');
  const hsSigning = hs.fire('btn-create-run');
  assert.equal(hs.signed[0].args[0].alg, 'HS384');
  assert.equal(hs.signed[0].args[0].key, 'keep-this-secret');
  hs.signed[0].resolve({ ok: true, token: 'synthetic-hs-token', warnings: [] });
  await hsSigning;

  const es = setup(true);
  await es.edit('create-alg', 'ES256', 'change');
  const generating = es.fire('btn-create-key');
  const privateKey = { type: 'private', extractable: false };
  es.generated[0].resolve({ ok: true, alg: 'ES256', privateKey, publicKey: 'synthetic-es-public' });
  await generating;
  await es.edit('create-header', '{"alg":"ES256","kid":"replace-me"}');
  await es.fire('btn-create-example');
  assert.equal(es.get('create-alg').value, 'ES256');
  assert.equal(es.get('create-public').value, 'synthetic-es-public');
  assert.equal(JSON.parse(es.get('create-header').value).alg, 'ES256');
  assert.equal(JSON.parse(es.get('create-header').value).kid, undefined);
  assert.equal(es.get('create-key-status').textContent, es.translated('create.keyReady', { alg: 'ES256' }));
  const esSigning = es.fire('btn-create-run');
  assert.equal(es.signed[0].args[0].alg, 'ES256');
  assert.equal(es.signed[0].args[0].key, privateKey);
  es.signed[0].resolve({ ok: true, token: 'synthetic-es-token', warnings: [] });
  await esSigning;
});
