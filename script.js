// JWT Inspector - 画面の処理（DOM）。計算は js/jwt-core.js と js/jwt-verify.js、文言は js/messages.js に置く
// 入力の状態を1つ持ち、render で描き直す（言語を切り替えたときも同じ関数で描き直す）
(() => {
  'use strict';

  const C = globalThis.JwtCore;
  const V = globalThis.JwtVerify;
  const S = globalThis.JwtSamples;
  const I18n = globalThis.JwtI18n;
  const Theme = globalThis.JwtTheme;
  const t = (key, vars) => globalThis.JwtMessages.t(key, vars);
  const $ = (id) => document.getElementById(id);
  const renders = [];

  function el(tag, className, text) {
    const e = document.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  const nowSec = () => Math.floor(Date.now() / 1000);

  // この端末の時計での表示（UTC は計算部の toIso）
  const toLocal = (sec) => C.toIso(sec) === '-' ? '-' : new Date(sec * 1000).toLocaleString();

  // 秒数の値（left・ago・ahead）は、いちばん大きい単位に丸めてから文言に入れる
  const DURATION_VARS = ['left', 'ago', 'ahead'];
  function findingText(f) {
    const vars = { ...f.vars };
    for (const name of DURATION_VARS) {
      if (typeof vars[name] === 'number') {
        const d = C.duration(vars[name]);
        vars[name] = t(`dur.${d.unit}`, { n: d.n });
      }
    }
    return t(`lint.${f.code}`, vars);
  }
  const errorText = (r) => t(`err.${r.code}`, r); // 読み取りの誤り
  const verifyErrorText = (r) => t(`verr.${r.code}`, r); // 検証の誤り

  // ===== タブ（矢印キー・Home・End で移動、選んだタブだけ tabindex=0） =====
  const tabs = [...document.querySelectorAll('.tab-btn')];

  function selectTab(tab, focus) {
    for (const b of tabs) {
      const on = b === tab;
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
      $(b.getAttribute('aria-controls')).hidden = !on;
    }
    if (focus) tab.focus();
  }

  tabs.forEach((b, i) => {
    b.addEventListener('click', () => selectTab(b, false));
    b.addEventListener('keydown', (e) => {
      const target = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
      if (target === undefined) return;
      e.preventDefault();
      selectTab(tabs[(target + tabs.length) % tabs.length], true);
    });
  });

  // ===== デコードと検査 =====
  const state = { token: null, copy: {}, copyFeedback: null, copyJob: 0, revision: 0, cleared: false, verify: null, verifyJob: 0 };

  function renderParts(token) {
    const pretty = (text) => JSON.stringify(JSON.parse(text), null, 2);
    state.copy.header = pretty(token.headerText);
    state.copy.payload = pretty(token.payloadText);
    $('out-header').textContent = state.copy.header;
    $('out-payload').textContent = state.copy.payload;
    const n = token.signature.length;
    $('signature-title').textContent = n ? t('decode.signature', { n }) : t('decode.signatureEmpty');
    $('out-signature').textContent = token.raw.signature;
    for (const part of ['header', 'payload']) {
      $(`copy-${part}`).disabled = false;
      $(`copy-${part}`).setAttribute('aria-label', t('decode.copyLabel', { name: t(`decode.${part}`) }));
    }
  }

  function clearDecodeOutput() {
    state.token = null;
    state.copy = {};
    state.copyFeedback = null;
    for (const id of ['out-header', 'out-payload', 'out-signature', 'signature-title', 'findings-summary', 'times-now', 'copy-status']) {
      $(id).textContent = '';
    }
    for (const id of ['findings-list', 'times-body', 'claims-body']) $(id).replaceChildren();
    for (const id of ['decode-result', 'times-card', 'claims-card']) $(id).hidden = true;
    for (const part of ['header', 'payload']) {
      $(`copy-${part}`).disabled = true;
      $(`copy-${part}`).removeAttribute('aria-label');
    }
  }

  function renderCopyStatus() {
    const feedback = state.copyFeedback;
    $('copy-status').textContent = feedback
      ? t(feedback.key, feedback.part ? { name: t(`decode.${feedback.part}`) } : undefined) : '';
  }

  function renderFindings(result) {
    const counts = { danger: 0, warn: 0, info: 0, ok: 0 };
    for (const f of result.findings) counts[f.level]++;
    $('findings-summary').textContent = result.findings.length
      ? t('decode.summary', { danger: counts.danger, warn: counts.warn, info: counts.info })
      : t('decode.noFindings');
    const order = { danger: 0, warn: 1, ok: 2, info: 3 };
    const sorted = [...result.findings].sort((a, b) => order[a.level] - order[b.level]);
    $('findings-list').replaceChildren(...sorted.map((f) => {
      const li = el('li', `finding ${f.level}`);
      li.append(el('span', `tag ${f.level}`, t(`level.${f.level}`)), el('span', 'finding-text', findingText(f)));
      return li;
    }));
  }

  function renderTimes(result, now) {
    $('times-now').textContent = t('decode.now', { iso: C.toIso(now), unix: now, leeway: C.DEFAULT_LEEWAY });
    const rows = ['exp', 'nbf', 'iat'].filter((claim) => result.times[claim].state !== 'missing');
    $('times-card').hidden = rows.length === 0;
    $('times-body').replaceChildren(...rows.map((claim) => {
      const info = result.times[claim];
      const th = el('th', '', claim);
      th.scope = 'row';
      const known = info.state !== 'type';
      const tr = el('tr');
      tr.append(th, el('td', 'mono', known ? String(info.value) : JSON.stringify(info.value)),
        el('td', 'mono', known ? info.iso : '-'), el('td', '', known ? toLocal(info.value) : '-'),
        el('td', '', t(`time.${info.state}`)));
      return tr;
    }));
  }

  function renderClaims(token) {
    const rows = C.REGISTERED_CLAIMS.filter((c) => token.payload[c] !== undefined);
    $('claims-card').hidden = rows.length === 0;
    $('claims-body').replaceChildren(...rows.map((claim) => {
      const th = el('th', '', claim);
      th.scope = 'row';
      const value = token.payload[claim];
      const tr = el('tr');
      tr.append(th, el('td', 'mono', typeof value === 'string' ? value : JSON.stringify(value)), el('td', '', t(`claim.${claim}`)));
      return tr;
    }));
  }

  function renderDecode() {
    const text = $('jwt-input').value;
    const status = $('decode-status');
    const box = $('decode-result');
    if (!text.trim()) {
      clearDecodeOutput();
      status.classList.remove('error');
      status.textContent = t(state.cleared ? 'decode.cleared' : 'decode.prompt');
      renderVerifyHeaderAlg();
      return;
    }
    const token = C.parseToken(text);
    if (!token.ok) {
      clearDecodeOutput();
      status.classList.add('error');
      status.textContent = errorText(token);
      renderVerifyHeaderAlg();
      return;
    }
    state.token = token;
    status.classList.remove('error');
    status.textContent = '';
    box.hidden = false;
    const now = nowSec();
    const result = C.lint(token, now);
    renderParts(token);
    renderFindings(result);
    renderTimes(result, now);
    renderClaims(token);
    renderVerifyHeaderAlg();
  }

  function tokenChanged(cleared = false) {
    state.revision++;
    state.copyJob++;
    state.copyFeedback = null;
    state.cleared = cleared;
    invalidateVerify();
    renderDecode();
    renderCopyStatus();
  }

  for (const b of document.querySelectorAll('[data-sample]')) {
    b.addEventListener('click', () => {
      $('jwt-input').value = S.decode[b.dataset.sample];
      tokenChanged();
    });
  }
  $('btn-clear').addEventListener('click', () => {
    $('jwt-input').value = '';
    tokenChanged(true);
  });
  $('jwt-input').addEventListener('input', () => tokenChanged());

  for (const b of document.querySelectorAll('[data-copy]')) {
    b.addEventListener('click', async () => {
      const part = b.dataset.copy;
      const text = state.copy[part];
      if (text === undefined) return;
      const job = ++state.copyJob;
      const revision = state.revision;
      let key;
      try {
        if (!navigator.clipboard) throw new Error('clipboard');
        await navigator.clipboard.writeText(text);
        key = 'decode.copied';
      } catch {
        key = 'decode.copyFailed';
      }
      if (job !== state.copyJob || revision !== state.revision || state.copy[part] !== text) return;
      state.copyFeedback = { key, part };
      renderCopyStatus();
    });
  }
  renders.push(renderDecode);
  renders.push(renderCopyStatus);

  // ===== 署名検証 =====
  const algSelect = $('alg-select');
  for (const alg of C.ALG_NAMES) {
    const option = document.createElement('option');
    option.value = alg;
    option.textContent = alg;
    algSelect.append(option);
  }

  // HS は共有鍵、それ以外は公開鍵（PEM か JWK）
  const keyGroup = () => C.ALG_NAMES.includes(algSelect.value) && C.ALGORITHMS[algSelect.value].family === 'HS' ? 'HS' : 'RS';

  function renderKeyLabels() {
    const group = keyGroup();
    $('key-label').textContent = t(`verify.keyLabel.${group}`);
    $('key-hint').textContent = t(`verify.keyHint.${group}`);
  }

  function renderVerifyHeaderAlg() {
    const alg = state.token && state.token.header ? state.token.header.alg : undefined;
    const known = typeof alg === 'string';
    $('verify-header-alg').textContent = known ? t('verify.headerAlg', { alg }) : t('verify.headerAlgNone');
    $('btn-use-header-alg').disabled = !known || !C.ALG_NAMES.includes(alg);
  }

  const renderVerify = () => {
    renderKeyLabels();
    renderVerifyHeaderAlg();
    const current = state.verify;
    $('btn-verify').disabled = Boolean(current && current.phase === 'running');
    if (!current) {
      showVerifyResult('', '', []);
      return;
    }
    if (current.phase === 'running') {
      showVerifyResult('', t('verify.running'), []);
      return;
    }
    const r = current.result;
    if (current.phase === 'readError' || !r.ok) {
      showVerifyResult('danger', current.phase === 'readError' ? errorText(r) : verifyErrorText(r), []);
      return;
    }
    const notes = [];
    if (r.mismatch) notes.push(['warn', t('verify.mismatch', { alg: r.alg, headerAlg: r.headerAlg })]);
    for (const w of r.warnings) notes.push(['danger', t(`verr.${w.code}`, w.vars)]);
    if (r.keyBits) notes.push(['info', t('verify.keyBits', { bits: r.keyBits })]);
    notes.push(['info', t(`verify.keyKind.${r.keyKind}`)]);
    showVerifyResult(r.valid ? 'ok' : 'danger', t(r.valid ? 'verify.valid' : 'verify.invalid', { alg: r.alg }), notes);
  };

  function invalidateVerify() {
    state.verifyJob++;
    state.verify = null;
    renderVerify();
  }

  algSelect.addEventListener('change', invalidateVerify);
  $('key-input').addEventListener('input', invalidateVerify);
  $('btn-use-header-alg').addEventListener('click', () => {
    const alg = state.token && state.token.header ? state.token.header.alg : undefined;
    if (typeof alg === 'string' && C.ALG_NAMES.includes(alg)) {
      algSelect.value = alg;
      invalidateVerify();
    }
  });

  for (const b of document.querySelectorAll('[data-verify-sample]')) {
    b.addEventListener('click', () => {
      const sample = S.verify[b.dataset.verifySample];
      $('jwt-input').value = sample.token;
      algSelect.value = sample.alg;
      $('key-input').value = sample.key;
      tokenChanged();
    });
  }

  function showVerifyResult(level, text, notes) {
    const box = $('verify-result');
    box.className = level ? `verdict ${level}` : 'verdict';
    box.textContent = text;
    $('verify-notes').replaceChildren(...(notes || []).map(([noteLevel, noteText]) => {
      const li = el('li', `finding ${noteLevel}`);
      li.append(el('span', `tag ${noteLevel}`, t(`level.${noteLevel}`)), el('span', 'finding-text', noteText));
      return li;
    }));
  }

  $('btn-verify').addEventListener('click', async () => {
    const job = ++state.verifyJob;
    const text = $('jwt-input').value;
    const alg = algSelect.value;
    const key = $('key-input').value;
    const token = C.parseToken(text);
    if (!token.ok) {
      state.verify = { phase: 'readError', result: token };
      renderVerify();
      return;
    }
    state.verify = { phase: 'running' };
    renderVerify();
    let result;
    try {
      result = await V.verify(token, alg, key);
    } catch (error) {
      result = { ok: false, code: 'verify.error', detail: typeof error?.name === 'string' ? error.name : 'Error' };
    }
    if (job !== state.verifyJob) return;
    if ($('jwt-input').value !== text || algSelect.value !== alg || $('key-input').value !== key) {
      invalidateVerify();
      return;
    }
    state.verify = { phase: 'finished', result };
    renderVerify();
  });
  renders.push(renderVerify);

  // 新しいタブから渡すときも、手入力と同じ状態の更新を通す。
  const workbench = globalThis.JwtWorkbench.init({
    getToken: () => $('jwt-input').value,
    sendToken: ({ token, alg, key, tab }) => {
      $('jwt-input').value = token;
      if (tab === 'verify') {
        if (C.ALG_NAMES.includes(alg)) algSelect.value = alg;
        $('key-input').value = key ?? '';
      }
      tokenChanged();
      selectTab($(`tab-${tab === 'verify' ? 'verify' : 'decode'}`), true);
    }
  });
  renders.push(workbench.render);
  $('btn-clear-all').addEventListener('click', () => {
    $('jwt-input').value = '';
    $('key-input').value = '';
    tokenChanged(true);
    workbench.clear();
  });

  // ===== テーマ・言語・初期表示 =====
  const themeBtn = $('btn-theme');
  themeBtn.addEventListener('click', () => Theme.toggle(themeBtn));

  function applyLanguage() {
    I18n.applyStaticText();
    Theme.refresh(themeBtn);
    for (const render of renders) render();
  }

  // 切り替えたら、URL に ?lang= があればそれも書き換える（再読み込みで元の言語に戻らないように）
  $('btn-lang').addEventListener('click', () => {
    I18n.set(I18n.lang === 'ja' ? 'en' : 'ja');
    const url = new URL(location.href);
    if (url.searchParams.has('lang')) {
      url.searchParams.set('lang', I18n.lang);
      history.replaceState(null, '', url);
    }
    applyLanguage();
  });

  I18n.init();
  applyLanguage();
})();
