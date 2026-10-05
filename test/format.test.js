import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { read } from './load.js';

const list = (dir, ext) => fs.readdirSync(new URL(`../${dir}`, import.meta.url)).filter((f) => f.endsWith(ext)).map((f) => `${dir}/${f}`);
// js/samples.js はデータ（トークンと鍵の長い文字列）なので、行の長さの検査からは外す
const DATA = ['js/samples.js'];
const CODE = [...list('js', '.js'), ...list('test', '.js'), 'script.js', 'style.css'];

test('JS・CSS・テストの最長行は160文字以下、index.html は250文字以下', () => {
  for (const f of CODE.filter((x) => !DATA.includes(x))) {
    const lines = read(f).split('\n');
    const i = lines.findIndex((l) => l.length > 160);
    assert.equal(i, -1, `${f}:${i + 1}`);
  }
  const lines = read('index.html').split('\n');
  const i = lines.findIndex((l) => l.length > 250);
  assert.equal(i, -1, `index.html:${i + 1}`);
});

test('主要なファイルは1行に詰め込まれていない（行数の下限）', () => {
  const min = { 'js/jwt-core.js': 250, 'js/jwt-verify.js': 140, 'js/messages.js': 200, 'script.js': 200, 'style.css': 350, 'index.html': 180 };
  for (const [f, n] of Object.entries(min)) assert.ok(read(f).split('\n').length >= n, f);
});

test('改行は LF、制御文字なし、末尾に改行', () => {
  for (const f of [...CODE, 'index.html', 'README.md', 'README.en.md', 'CLAUDE.md']) {
    const s = read(f);
    assert.ok(!s.includes('\r'), `${f}: CR`);
    assert.ok(![...s].some((ch) => { const c = ch.codePointAt(0); return (c < 32 && c !== 10) || c === 127; }), f);
    assert.ok(s.endsWith('\n'), `${f}: no final newline`);
  }
});
