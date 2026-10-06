// JWT Inspector - 作成・小辞書検査・再現実験の画面。非同期の結果は入力の世代ごとに管理する
(() => {
  'use strict';

  const C = globalThis.JwtCore;
  const G = globalThis.JwtCreate;
  const L = globalThis.JwtLab;
  const t = (key, vars) => globalThis.JwtMessages.t(key, vars);
  const $ = (id) => document.getElementById(id);

  function errorText(result) {
    const dict = globalThis.JwtMessages.MESSAGES.en;
    for (const prefix of ['werr', 'err', 'verr']) {
      const key = `${prefix}.${result.code}`;
      if (Object.prototype.hasOwnProperty.call(dict, key)) return t(key, result);
    }
    return t('werr.verify.error');
  }

  function verdict(id, level, text) {
    const box = $(id);
    box.className = level ? `verdict ${level}` : 'verdict';
    box.textContent = text;
  }

  function init({ getToken, sendToken }) {
    const create = { epoch: 0, key: null, busy: '', result: null, feedback: '' };
    const audit = { epoch: 0, controller: null, busy: false, result: null, tested: 0, total: 0 };
    const lab = { epoch: 0, busy: false, result: null, feedback: '' };
    const alg = $('create-alg');
    for (const name of C.ALG_NAMES) {
      const option = document.createElement('option');
      option.value = name;
      option.textContent = name;
      alg.append(option);
    }

    const isHs = () => C.ALG_NAMES.includes(alg.value) && C.ALGORITHMS[alg.value].family === 'HS';
    const createSnapshot = () => JSON.stringify([alg.value, $('create-header').value, $('create-payload').value, $('create-secret').value]);
    const auditSnapshot = () => JSON.stringify([$('audit-token').value, $('audit-candidates').value]);

    function renderCreate() {
      const hs = isHs();
      const ready = hs ? Boolean($('create-secret').value) : Boolean(create.key);
      $('create-secret-group').hidden = !hs;
      $('create-public-group').hidden = hs || !create.key;
      $('create-public').value = !hs && create.key ? create.key.publicKey : '';
      $('create-key-status').textContent = t(create.busy === 'key' ? 'create.keyGenerating'
        : ready ? 'create.keyReady' : 'create.keyMissing', { alg: alg.value });
      $('btn-create-key').disabled = Boolean(create.busy);
      $('btn-create-run').disabled = Boolean(create.busy);
      const r = create.result;
      const success = Boolean(r && r.ok);
      $('create-output-group').hidden = !success;
      $('create-output').value = success ? r.token : '';
      for (const id of ['btn-create-decode', 'btn-create-verify', 'btn-create-copy']) $(id).disabled = !success;
      let text = create.busy === 'sign' ? t('create.running') : '';
      let level = '';
      if (r) {
        level = !r.ok ? 'danger' : r.warnings.length ? 'warn' : 'ok';
        text = r.ok ? [t('create.done'), ...r.warnings.map((w) => t(`verr.${w.code}`, w.vars))].join(' ') : errorText(r);
      }
      verdict('create-status', level, text);
      $('create-feedback').textContent = create.feedback ? t(`work.${create.feedback}`) : '';
    }

    function invalidateCreate(discardKey = false) {
      create.epoch++;
      create.busy = '';
      create.result = null;
      create.feedback = '';
      if (discardKey) {
        create.key = null;
        $('create-secret').value = '';
      }
      renderCreate();
    }

    function clearCreate() {
      alg.value = 'HS256';
      $('create-header').value = '';
      $('create-payload').value = '';
      invalidateCreate(true);
    }

    function exampleCreate() {
      invalidateCreate();
      const now = Math.floor(Date.now() / 1000);
      $('create-header').value = JSON.stringify({ alg: alg.value, typ: 'JWT' }, null, 2);
      $('create-payload').value = JSON.stringify({ sub: 'demo-user', iss: 'issuer.example', aud: 'jwt-inspector',
        role: 'user', iat: now, exp: now + 3600 }, null, 2);
    }

    for (const id of ['create-header', 'create-payload', 'create-secret']) {
      $(id).addEventListener('input', () => invalidateCreate());
    }
    alg.addEventListener('change', () => {
      // 壊れたJSONは勝手に上書きせず、作成APIから理由を知らせる
      const header = C.parseJsonObject(C.utf8($('create-header').value));
      if (header.ok && !header.duplicates.length) {
        $('create-header').value = JSON.stringify({ ...header.value, alg: alg.value }, null, 2);
      }
      invalidateCreate(true);
    });
    $('btn-create-example').addEventListener('click', exampleCreate);
    $('btn-create-clear').addEventListener('click', clearCreate);
    $('btn-create-key').addEventListener('click', async () => {
      invalidateCreate(true);
      const epoch = create.epoch;
      const name = alg.value;
      create.busy = 'key';
      renderCreate();
      let result;
      try { result = await G.generateKey(name); } catch { result = { ok: false, code: 'key.generate' }; }
      if (epoch !== create.epoch) return;
      if (alg.value !== name) { invalidateCreate(true); return; }
      create.busy = '';
      if (result.ok) {
        if (isHs()) $('create-secret').value = result.secret;
        else create.key = result;
      } else create.result = result;
      renderCreate();
    });
    $('btn-create-run').addEventListener('click', async () => {
      invalidateCreate();
      const epoch = create.epoch;
      const snapshot = createSnapshot();
      const name = alg.value;
      const key = isHs() ? $('create-secret').value : create.key && create.key.privateKey;
      const verificationKey = isHs() ? key : create.key && create.key.publicKey;
      create.busy = 'sign';
      renderCreate();
      let result;
      try {
        result = await G.create({ alg: name, key, headerText: $('create-header').value, payloadText: $('create-payload').value });
      } catch { result = { ok: false, code: 'sign.error' }; }
      if (epoch !== create.epoch) return;
      if (snapshot !== createSnapshot()) { invalidateCreate(); return; }
      create.busy = '';
      create.result = result.ok ? { ...result, alg: name, verificationKey } : result;
      renderCreate();
    });

    function transferCreate(tab) {
      const r = create.result;
      if (!r || !r.ok) return;
      sendToken({ token: r.token, alg: r.alg, key: r.verificationKey, tab });
      create.feedback = tab === 'verify' ? 'sentVerify' : 'sentDecode';
      renderCreate();
    }
    $('btn-create-decode').addEventListener('click', () => transferCreate('decode'));
    $('btn-create-verify').addEventListener('click', () => transferCreate('verify'));
    $('btn-create-copy').addEventListener('click', async () => {
      if (!create.result || !create.result.ok) return;
      const epoch = create.epoch;
      const snapshot = createSnapshot();
      let feedback;
      try {
        if (!navigator.clipboard) throw new Error('clipboard');
        await navigator.clipboard.writeText(create.result.token);
        feedback = 'copied';
      } catch { feedback = 'copyFailed'; }
      if (epoch !== create.epoch || snapshot !== createSnapshot()) return;
      create.feedback = feedback;
      renderCreate();
    });

    function renderAudit() {
      const r = audit.result;
      const found = Boolean(r && r.ok && r.status === 'found');
      $('btn-audit-run').disabled = audit.busy;
      $('btn-audit-stop').disabled = !audit.busy;
      $('audit-progress').max = Math.max(1, audit.total);
      $('audit-progress').value = audit.tested;
      $('audit-progress').setAttribute('aria-valuetext', t('audit.running', audit));
      $('audit-key-group').hidden = !found;
      $('audit-key').value = found ? r.key : '';
      let text = t(audit.busy ? 'audit.running' : 'audit.ready', audit);
      let level = '';
      if (r) {
        text = r.ok ? t(`audit.${r.status}`, r) : errorText(r);
        level = !r.ok || found ? 'danger' : 'warn';
      }
      verdict('audit-status', level, text);
    }

    function invalidateAudit() {
      if (audit.controller) audit.controller.abort();
      audit.epoch++;
      audit.controller = null;
      audit.busy = false;
      audit.result = null;
      audit.tested = 0;
      audit.total = 0;
      renderAudit();
    }

    function clearAudit() {
      $('audit-token').value = '';
      $('audit-candidates').value = '';
      invalidateAudit();
    }
    for (const id of ['audit-token', 'audit-candidates']) $(id).addEventListener('input', invalidateAudit);
    $('btn-audit-current').addEventListener('click', () => {
      $('audit-token').value = getToken();
      invalidateAudit();
    });
    $('btn-audit-example').addEventListener('click', () => {
      $('audit-token').value = globalThis.JwtSamples.verify.weak.token;
      $('audit-candidates').value = L.DEFAULT_CANDIDATES.join('\n');
      invalidateAudit();
    });
    $('btn-audit-defaults').addEventListener('click', () => {
      $('audit-candidates').value = L.DEFAULT_CANDIDATES.join('\n');
      invalidateAudit();
    });
    $('btn-audit-clear').addEventListener('click', clearAudit);
    $('btn-audit-stop').addEventListener('click', () => {
      if (audit.controller) audit.controller.abort();
    });
    $('btn-audit-run').addEventListener('click', async () => {
      invalidateAudit();
      const epoch = audit.epoch;
      const snapshot = auditSnapshot();
      const controller = new AbortController();
      audit.controller = controller;
      audit.busy = true;
      renderAudit();
      let result;
      try {
        result = await L.checkWeakKey($('audit-token').value, $('audit-candidates').value, {
          signal: controller.signal,
          onProgress: ({ tested, total }) => {
            if (epoch !== audit.epoch || snapshot !== auditSnapshot()) return;
            audit.tested = tested;
            audit.total = total;
            if (tested % 16 === 0 || tested === total) renderAudit();
          }
        });
      } catch { result = { ok: false, code: 'verify.error' }; }
      if (epoch !== audit.epoch) return;
      if (snapshot !== auditSnapshot()) { invalidateAudit(); return; }
      audit.controller = null;
      audit.busy = false;
      audit.result = result;
      if (result.ok) {
        audit.tested = result.tested;
        audit.total = result.total;
      }
      renderAudit();
    });

    function renderLab() {
      const r = lab.result;
      const success = Boolean(r && r.ok);
      $('btn-lab-run').disabled = lab.busy;
      $('lab-output-group').hidden = !success;
      $('lab-original').value = success ? r.originalToken : '';
      $('lab-token').value = success ? r.token : '';
      $('lab-public').value = success ? r.publicKey : '';
      for (const id of ['btn-lab-decode', 'btn-lab-verify']) $(id).disabled = !success;
      $('lab-detail').textContent = success ? t(`lab.detail.${r.mode}`) : '';
      const rows = [];
      if (success) {
        for (const [label, unsafe, fixed] of [['original', true, r.details.original.accepted], ['modified', r.unsafeAccepted, r.fixedAccepted]]) {
          const row = document.createElement('tr');
          const name = document.createElement('th');
          name.scope = 'row';
          name.textContent = t(`lab.${label}`);
          row.append(name);
          for (const accepted of [unsafe, fixed]) {
            const cell = document.createElement('td');
            cell.textContent = t(accepted ? 'lab.accepted' : 'lab.rejected');
            row.append(cell);
          }
          rows.push(row);
        }
      }
      $('lab-comparison').replaceChildren(...rows);
      verdict('lab-status', r && !r.ok ? 'danger' : '', r ? r.ok ? t('lab.done') : errorText(r)
        : t(lab.busy ? 'lab.running' : 'lab.ready'));
      $('lab-feedback').textContent = lab.feedback ? t(`work.${lab.feedback}`) : '';
    }

    function invalidateLab() {
      lab.epoch++;
      lab.busy = false;
      lab.result = null;
      lab.feedback = '';
      renderLab();
    }
    $('lab-mode').addEventListener('change', invalidateLab);
    $('btn-lab-clear').addEventListener('click', invalidateLab);
    $('btn-lab-run').addEventListener('click', async () => {
      invalidateLab();
      const epoch = lab.epoch;
      const mode = $('lab-mode').value;
      lab.busy = true;
      renderLab();
      let result;
      try { result = await L.runDemo(mode); } catch { result = { ok: false, code: 'demo.error' }; }
      if (epoch !== lab.epoch) return;
      if (mode !== $('lab-mode').value) { invalidateLab(); return; }
      lab.busy = false;
      lab.result = result;
      renderLab();
    });
    function transferLab(tab) {
      const r = lab.result;
      if (!r || !r.ok) return;
      sendToken({ token: r.token, alg: r.expectedAlg, key: r.publicKey, tab });
      lab.feedback = tab === 'verify' ? 'sentVerify' : 'sentDecode';
      renderLab();
    }
    $('btn-lab-decode').addEventListener('click', () => transferLab('decode'));
    $('btn-lab-verify').addEventListener('click', () => transferLab('verify'));

    exampleCreate();
    $('audit-candidates').value = L.DEFAULT_CANDIDATES.join('\n');
    return {
      render: () => { renderCreate(); renderAudit(); renderLab(); },
      clear: () => { clearCreate(); clearAudit(); invalidateLab(); }
    };
  }

  globalThis.JwtWorkbench = { init };
})();
