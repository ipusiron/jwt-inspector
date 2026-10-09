import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { read, load, core, verifier } from './load.js';

const C = core();
const V = verifier();
const G = load('js/jwt-create.js').JwtCreate;
const L = load('js/jwt-lab.js').JwtLab;
const ROOT = fileURLToPath(new URL('..', import.meta.url));

const DOCS = {
  ja: {
    file: 'README.md', switcher: '[English](README.en.md) · 日本語', day: '**Day053 - 生成AIで作るセキュリティツール100**',
    shots: /^assets\/screenshot\d*\.png$/,
    sec: { tech: '🔬 技術的な説明', limits: '⚠️ 注意と限界', refs: '🔗 参考', tree: '📁 ディレクトリー構造', about: '🛠️ このツールについて' },
    head: { lint: '| 項目 | 判定 |', alg: '| 族 | 名前 |' },
    levels: { 危険: 'danger', 注意: 'warn', 情報: 'info' },
    items: {
      'alg=none': ['alg.none', { alg: 'none' }, {}],
      'algがNone・NONEなど': ['alg.noneCase', { alg: 'None' }, {}],
      'jku・x5u': ['header.url', { jku: 'https://x.example' }, {}],
      jwk: ['header.jwk', { jwk: {} }, {}],
      kid: ['header.kid', { kid: 'k' }, {}],
      crit: ['header.crit', { crit: ['x'] }, {}],
      '同じ名前のメンバーの重複': ['json.duplicate', null, null],
      'expが現在時刻以前': ['exp.expired', {}, { exp: 1799999999 }],
      'nbfが未来': ['nbf.notYet', {}, { nbf: 1800009999 }],
      'iatが未来': ['iat.future', {}, { iat: 1800009999 }],
      'iss・audがない': ['iss.missing', {}, { iss: undefined, aud: undefined }],
      'typがない': ['typ.missing', { typ: undefined }, {}],
      '秘密らしい名前のクレーム': ['payload.sensitive', {}, { password: 'x' }]
    },
    families: { HS: 'HS', RS: 'RS', PS: 'PS', ES: 'ES' },
    sep: '・',
    hs: (bits) => `HS256なら${bits}ビット`,
    rsa: (bits) => `RSAは${bits}ビット以上`,
    maxChars: (n) => `トークンは${n}文字まで`,
    forbidden: /ディレクトリトラバーサル|暗号化アルゴリズム|絶対禁止|ブラウザ(?!ー)|📚　/
  },
  en: {
    file: 'README.en.md', switcher: 'English · [日本語](README.md)', day: '**Day053 - 100 Security Tools with Generative AI**',
    shots: /^assets\/en\/screenshot\d*\.png$/,
    sec: { tech: '🔬 Technical notes', limits: '⚠️ Notes and limitations', refs: '🔗 References',
      tree: '📁 Directory structure', about: '🛠️ About this tool' },
    head: { lint: '| Item | Verdict |', alg: '| Family | Names |' },
    levels: { Danger: 'danger', Warning: 'warn', Note: 'info' },
    items: {
      'alg=none': ['alg.none', { alg: 'none' }, {}],
      'alg as None, NONE and so on': ['alg.noneCase', { alg: 'None' }, {}],
      'jku, x5u': ['header.url', { jku: 'https://x.example' }, {}],
      jwk: ['header.jwk', { jwk: {} }, {}],
      kid: ['header.kid', { kid: 'k' }, {}],
      crit: ['header.crit', { crit: ['x'] }, {}],
      'Repeated member names': ['json.duplicate', null, null],
      'exp at or before now': ['exp.expired', {}, { exp: 1799999999 }],
      'nbf in the future': ['nbf.notYet', {}, { nbf: 1800009999 }],
      'iat in the future': ['iat.future', {}, { iat: 1800009999 }],
      'iss or aud missing': ['iss.missing', {}, { iss: undefined, aud: undefined }],
      'typ missing': ['typ.missing', { typ: undefined }, {}],
      'Claims whose names look like secrets': ['payload.sensitive', {}, { password: 'x' }]
    },
    families: { HS: 'HS', RS: 'RS', PS: 'PS', ES: 'ES' },
    sep: ', ',
    hs: (bits) => `${bits} bits for HS256`,
    rsa: (bits) => `RSA keys must be ${bits} bits or more`,
    maxChars: (n) => `up to ${n} characters`,
    forbidden: /directory traversal|encryption algorithm/i
  }
};
for (const d of Object.values(DOCS)) d.text = read(d.file);

function section(text, heading) {
  const i = text.indexOf(`\n## ${heading}`);
  assert.ok(i >= 0, heading);
  const rest = text.slice(i + 1);
  const end = rest.indexOf('\n## ', 3);
  return end < 0 ? rest : rest.slice(0, end);
}

function table(text, firstHeader) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.startsWith(firstHeader));
  assert.ok(start >= 0, firstHeader);
  const rows = [];
  for (let i = start + 2; i < lines.length && lines[i].startsWith('|'); i++) {
    rows.push(lines[i].replace(/^\| | \|$/g, '').split(/ (?<!\\)\| /).map((c) => c.trim()));
  }
  return rows;
}

const noCode = (md) => md.replace(/```[\s\S]*?```/g, '');
const h2 = (md) => noCode(md).split('\n').filter((l) => l.startsWith('## ')).map((l) => l.slice(3));
const headings = (md) => noCode(md).split('\n').filter((l) => /^#{1,4} /.test(l));

test('日英READMEのHS生成鍵の表は、実際に生成した乱数長とUTF-8鍵文字列長に一致する', async () => {
  const headers = {
    ja: '| アルゴリズム | 生成する乱数（バイト） | UTF-8の鍵文字列（文字＝バイト） |',
    en: '| Algorithm | Random bytes generated | UTF-8 key text (characters = bytes) |'
  };
  const expected = [];
  for (const alg of C.ALG_NAMES.filter((name) => name.startsWith('HS'))) {
    const result = await G.generateKey(alg);
    assert.ok(result.ok, alg);
    const random = C.decodeB64url(result.secret);
    assert.ok(random.ok, alg);
    assert.equal(random.bytes.length, C.ALGORITHMS[alg].bits / 8, alg);
    assert.equal(result.secret.length, C.utf8(result.secret).length, alg);
    expected.push([alg, String(random.bytes.length), String(C.utf8(result.secret).length)]);
  }
  for (const lang of ['ja', 'en']) assert.deepEqual(table(DOCS[lang].text, headers[lang]), expected, lang);
});

test('日英READMEの注意と限界は小辞書の全上限を示す', () => {
  for (const [lang, doc] of Object.entries(DOCS)) {
    const limits = section(doc.text, doc.sec.limits);
    for (const n of [L.MAX_CANDIDATES, L.MAX_CANDIDATE_BYTES, L.MAX_CANDIDATES_CHARS]) {
      assert.match(limits, new RegExp(`\\b${n}\\b`), `${lang}: ${n}`);
    }
  }
});

test('YAML メタデータの構造（キーの順、ブロック形式のリスト、固定の値）。YAML は README.md だけに置く', () => {
  const m = DOCS.ja.text.match(/^<!--\n---\n([\s\S]*?)\n---\n-->\n/);
  assert.ok(m, 'YAML block');
  const keys = [...m[1].matchAll(/^([a-z_]+):/gm)].map((x) => x[1]);
  assert.deepEqual(keys, ['id', 'slug', 'title', 'subtitle_ja', 'subtitle_en', 'description_ja', 'description_en', 'category_ja', 'category_en',
    'difficulty', 'tags', 'repo_url', 'demo_url', 'hub']);
  for (const k of ['category_ja', 'category_en', 'tags']) assert.match(m[1], new RegExp(`^${k}:\\n  - `, 'm'), k);
  assert.match(m[1], /^id: day053$/m);
  assert.match(m[1], /^slug: jwt-inspector$/m);
  assert.match(m[1], /^repo_url: "https:\/\/github.com\/ipusiron\/jwt-inspector"$/m);
  assert.match(m[1], /^demo_url: "https:\/\/ipusiron.github.io\/jwt-inspector\/"$/m);
  assert.match(m[1], /^hub: true$/m);
  assert.doesNotMatch(DOCS.en.text, /^<!--/);
});

test('日英の README は同じ見出しを同じ順に持つ（階層と絵文字がそろう）', () => {
  const ja = headings(DOCS.ja.text);
  const en = headings(DOCS.en.text);
  assert.equal(en.length, ja.length);
  assert.ok(ja.length >= 20, String(ja.length));
  ja.forEach((h, i) => {
    assert.equal(en[i].match(/^#+/)[0], h.match(/^#+/)[0], `${h} / ${en[i]}`);
    const first = [...h.replace(/^#+ /, '')][0];
    if (/\p{Extended_Pictographic}/u.test(first)) assert.equal([...en[i].replace(/^#+ /, '')][0], first, `${h} / ${en[i]}`);
  });
});

for (const [lang, d] of Object.entries(DOCS)) {
  test(`${d.file}: シリーズ標準の構成（前半と後半の見出しの順、Day の表記、言語の切り替え、プロジェクトのリンク）と、古い記述がないこと`, () => {
    const heads = h2(d.text);
    assert.ok(d.text.includes(d.switcher));
    assert.match(d.text, /\n# JWT Inspector - .+\n/);
    assert.ok(d.text.includes(d.day));
    assert.ok(heads[0].startsWith('🌐'));
    assert.ok(heads[1].startsWith('📸'));
    assert.deepEqual(heads.slice(-4).map((h) => [...h][0]), ['📁', '💻', '📄', '🛠']);
    for (const icon of ['✨', '📖', '🎯', '🔒', '⚠', '🧪', '🔬', '🔗']) assert.ok(heads.some((h) => h.startsWith(icon)), icon);
    assert.match(section(d.text, d.sec.about), /https:\/\/akademeia\.info\/\?page_id=42163/);
    for (const b of ['stars', 'forks', 'last-commit', 'license']) assert.ok(d.text.includes(`img.shields.io/github/${b}/ipusiron/jwt-inspector`), b);
    assert.doesNotMatch(d.text.replace(/<!--[\s\S]*?-->/, ''), d.forbidden);
  });

  test(`${d.file}: 強調は1節に2か所まで、箇条書きの項目名を太字にしない、文末にコロンを置かない`, () => {
    for (const h of h2(d.text)) {
      const n = (section(d.text, h).match(/\*\*[^*\n]+\*\*/g) || []).length;
      assert.ok(n <= 2, `${h}: ${n}`);
    }
    assert.doesNotMatch(d.text, /^\s*- \*\*/m);
    if (lang === 'ja') assert.doesNotMatch(noCode(d.text).replace(/<!--[\s\S]*?-->/, ''), /[：:]$/m);
  });

  test(`${d.file}: 検査の表の行は、計算部がその項目に付ける level と同じ`, () => {
    const rows = table(section(d.text, d.sec.tech), d.head.lint);
    assert.ok(rows.length >= 12, String(rows.length));
    const b64 = (obj) => C.encodeB64url(C.utf8(JSON.stringify(obj)));
    const BASE_HEADER = { alg: 'HS256', typ: 'JWT' };
    const BASE_PAYLOAD = { iss: 'i', aud: 'a', exp: 1800000100, iat: 1799990000 };
    // 同じ名前のメンバーの重複は、JSON を直接組み立てないと作れない
    const DUPLICATE = `${C.encodeB64url(C.utf8('{"alg":"HS256","alg":"HS256"}'))}.${b64(BASE_PAYLOAD)}.AAAA`;

    function levelOf(code, header, payload) {
      const text = header === null
        ? DUPLICATE
        : `${b64({ ...BASE_HEADER, ...header })}.${b64({ ...BASE_PAYLOAD, ...payload })}.AAAA`;
      const token = C.parseToken(text);
      assert.ok(token.ok, JSON.stringify(token));
      const f = C.lint(token, 1800000000).findings.find((x) => x.code === code);
      assert.ok(f, code);
      return f.level;
    }

    for (const [item, verdict] of rows) {
      const entry = d.items[item];
      assert.ok(entry, item);
      const [code, header, payload] = entry;
      assert.ok(d.levels[verdict] !== undefined, verdict);
      assert.equal(d.levels[verdict], levelOf(code, header, payload), item);
    }
    assert.equal(rows.length, Object.keys(d.items).length);
  });

  test(`${d.file}: アルゴリズムの表は、計算部が対応する12種類と同じ`, () => {
    const rows = table(section(d.text, d.sec.tech), d.head.alg);
    assert.equal(rows.length, 4);
    const listed = [];
    for (const [family, names] of rows) {
      assert.ok(d.families[family], family);
      const parts = names.split(d.sep).map((s) => s.trim());
      for (const name of parts) {
        assert.ok(C.ALGORITHMS[name], name);
        assert.equal(C.ALGORITHMS[name].family, d.families[family], name);
        listed.push(name);
      }
    }
    assert.deepEqual(listed.sort(), [...C.ALG_NAMES].sort());
  });

  test(`${d.file}: 鍵の長さと上限の数値は、計算部の値と同じ`, () => {
    const tech = section(d.text, d.sec.tech);
    assert.ok(tech.includes(d.hs(V.MIN_HS_BITS[256])), d.hs(V.MIN_HS_BITS[256]));
    assert.ok(tech.includes(d.rsa(V.MIN_RSA_BITS)), d.rsa(V.MIN_RSA_BITS));
    assert.ok(section(d.text, d.sec.limits).includes(d.maxChars(C.MAX_TOKEN_CHARS)), String(C.MAX_TOKEN_CHARS));
  });

  test(`${d.file}: ディレクトリー構造にすべてのファイルとディレクトリーが載り、全行に説明がある`, () => {
    const block = section(d.text, d.sec.tree).match(/```\n([\s\S]*?)```/)[1];
    const lines = block.split('\n').filter((l) => l.trim()).slice(1);
    const listed = new Set();
    for (const line of lines) {
      const m = line.match(/[├└]── ([^\s#]+)\s+# \S/);
      assert.ok(m, `説明のない行: ${line}`);
      listed.add(m[1].replace(/\/$/, ''));
    }
    const walk = (dir) => fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })
      .filter((x) => !['.git', 'node_modules', '.claude'].includes(x.name))
      .flatMap((x) => (x.isDirectory() ? [x.name, ...walk(path.join(dir, x.name))] : [x.name]));
    const all = walk('.');
    for (const name of all) assert.ok(listed.has(name), `ツリーにない: ${name}`);
    for (const name of listed) assert.ok(all.includes(name), `実在しない: ${name}`);
  });
}

test('参考文献の URL は日英で同じで、RFC 7515・7517・7518・7519・8725 を挙げる', () => {
  const urls = (d) => [...section(d.text, d.sec.refs).matchAll(/\]\((https:\/\/[^)\s]+)\)/g)].map((m) => m[1]);
  assert.deepEqual(urls(DOCS.en), urls(DOCS.ja));
  for (const rfc of [7515, 7517, 7518, 7519, 8725]) assert.ok(urls(DOCS.ja).some((u) => u.includes(String(rfc))), String(rfc));
  assert.equal(urls(DOCS.ja).length, 6);
});

test('画像: 参照はすべて実在する。スクリーンショットは日本語版が assets/、英語版が assets/en/ の7枚。どこからも参照しない画像は置かない', () => {
  const refs = {};
  for (const [lang, d] of Object.entries(DOCS)) {
    refs[lang] = [...d.text.matchAll(/!\[[^\]]*\]\((assets\/[^)]+)\)/g)].map((m) => m[1]);
    for (const r of refs[lang]) assert.ok(fs.existsSync(path.join(ROOT, r)), r);
    const shots = refs[lang].filter((r) => /screenshot/.test(r));
    assert.equal(shots.length, 7, lang);
    for (const r of shots) {
      assert.match(r, d.shots, r);
      assert.ok(fs.statSync(path.join(ROOT, r)).size <= 300 * 1024, r);
    }
  }
  const used = new Set([...refs.ja, ...refs.en]);
  const files = (dir) => fs.readdirSync(path.join(ROOT, dir)).filter((f) => /\.(png|jpg)$/.test(f)).map((f) => `${dir}/${f}`);
  for (const f of [...files('assets'), ...files('assets/en')]) assert.ok(used.has(f), `参照していない画像: ${f}`);
});

test('サンプルの説明（4つと5つ）は、samples.js の数と同じ', () => {
  const samples = load('js/samples.js').JwtSamples;
  assert.equal(Object.keys(samples.decode).length, 4);
  assert.equal(Object.keys(samples.verify).length, 5);
  assert.ok(DOCS.ja.text.includes('サンプル4つ'));
  assert.ok(DOCS.ja.text.includes('サンプル5つ'));
  assert.ok(DOCS.en.text.includes('Four samples'));
  assert.ok(DOCS.en.text.includes('Five samples'));
});

test('ユースケースの「このツールならではの使い方」の例は判定と表示に一致する（日英）', () => {
  const [ja, en] = [read('README.md'), read('README.en.md')];
  const now = 1767225600;
  const times = (payload) => C.timeStatus(payload, now);
  assert.equal(2 ** 31 - 1, 2147483647);
  const max = times({ exp: 2147483647 }).exp.iso;
  const two = times({ exp: 2000000000 }).exp.iso;
  assert.deepEqual([max, two], ['2038-01-19T03:14:07Z', '2033-05-18T03:33:20Z']);
  for (const text of [ja, en]) assert.ok(text.includes('2038-01-19T03:14:07') && text.includes('2033-05-18T03:33:20'));
  assert.equal(C.DEFAULT_LEEWAY, 60);
  assert.deepEqual([times({ nbf: now + 30 }).nbf.state, times({ nbf: now + 90 }).nbf.state], ['leeway', 'notYet']);
  const { MESSAGES } = load('js/messages.js').JwtMessages;
  assert.ok(ja.includes(`「${MESSAGES.ja['time.leeway']}」`) && ja.includes(`「${MESSAGES.ja['time.notYet']}」`));
  assert.ok(en.includes(`"${MESSAGES.en['time.leeway']}"`) && en.includes(`"${MESSAGES.en['time.notYet']}"`));
  const e = (o) => C.encodeB64url(C.utf8(JSON.stringify(o)));
  const algCode = (alg) => C.lint(C.parseToken(e({ alg, typ: 'JWT' }) + '.' + e({ sub: 'x' }) + '.'), now)
    .findings.find((f) => f.code.startsWith('alg.'));
  for (const alg of ['None', 'NONE']) assert.deepEqual([algCode(alg).level, algCode(alg).code], ['danger', 'alg.noneCase']);
  assert.ok(ja.includes('「None」や「NONE」') && en.includes('"None" or "NONE"'));
  assert.ok(ja.includes('「いま」の30秒後') && ja.includes('90秒後') && en.includes('30 seconds after "now"') && en.includes('at 90 seconds'));
});
