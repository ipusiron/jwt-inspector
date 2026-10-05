import test from 'node:test';
import assert from 'node:assert/strict';
import { read } from './load.js';

const css = read('style.css');

function tokens(selector) {
  const start = css.indexOf(`${selector} {`);
  assert.ok(start >= 0, selector);
  const block = css.slice(start, css.indexOf('}', start));
  return Object.fromEntries([...block.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})/g)].map((m) => [m[1], m[2]]));
}

const luminance = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a, b) => {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

// 文字の色と背景の色の組（画面で実際に重なるもの）。4.5:1 以上
const TEXT = [
  ['text', 'bg'], ['text', 'panel'], ['text', 'card'], ['text', 'surface'], ['text', 'accent-weak'],
  ['muted', 'bg'], ['muted', 'panel'], ['muted', 'card'], ['muted', 'surface'],
  ['accent-text', 'bg'], ['accent-text', 'panel'], ['accent-text', 'card'], ['accent-text', 'accent-weak'],
  ['on-accent', 'accent'],
  ['ok-text', 'ok-bg'], ['warn-text', 'warn-bg'], ['danger-text', 'danger-bg'], ['info-text', 'info-bg'],
  ['danger-text', 'card'], ['danger-bg', 'danger-text'], ['warn-bg', 'warn-text'], ['ok-bg', 'ok-text'], ['info-bg', 'info-text']
];
// 入力欄・ボタンの枠、方式の色（棒と帯）と、その下地の組。3:1 以上（WCAG 1.4.11）
const GRAPHICS = [
  ['field-border', 'card'], ['field-border', 'surface'], ['field-border', 'panel'], ['field-border', 'bg'],
  ['accent', 'card'], ['warn-text', 'card']
];

test('ライトとダークの配色は、文字と背景が4.5:1以上、入力欄の枠と色の帯が3:1以上', () => {
  for (const [name, set] of [['light', tokens(':root')], ['dark', tokens(':root[data-theme="dark"]')]]) {
    for (const [fg, bg] of TEXT) assert.ok(ratio(set[fg], set[bg]) >= 4.5, `${name} ${fg} on ${bg}: ${ratio(set[fg], set[bg]).toFixed(2)}`);
    for (const [fg, bg] of GRAPHICS) assert.ok(ratio(set[fg], set[bg]) >= 3, `${name} ${fg} on ${bg}: ${ratio(set[fg], set[bg]).toFixed(2)}`);
  }
});

test('OS の設定によるダークと、手動のダークは同じ値', () => {
  const start = css.indexOf(':root:not([data-theme="light"]) {');
  const block = css.slice(start, css.indexOf('}', start));
  const os = Object.fromEntries([...block.matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));
  const s2 = css.indexOf(':root[data-theme="dark"] {');
  const manual = Object.fromEntries([...css.slice(s2, css.indexOf('}', s2)).matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));
  assert.ok(Object.keys(os).length >= 20);
  assert.deepEqual(os, manual);
});

test('操作するボタン・リンク・入力欄は高さ44px以上、入力欄の文字は16px', () => {
  for (const sel of ['.icon-btn {', '.tab-btn {', '.btn {', '.text-area {', '.select {', '.site-footer a {', '.bullets a {']) {
    const start = css.indexOf(sel);
    assert.ok(start >= 0, sel);
    assert.match(css.slice(start, css.indexOf('}', start)), /min-height: 44px/, sel);
  }
  for (const sel of ['.text-area {', '.select {']) {
    const start = css.indexOf(sel);
    assert.match(css.slice(start, css.indexOf('}', start)), /font-size: 16px/, sel);
  }
});

test('本文の書体は欧文の書体を先に置く（日本語の書体のバックスラッシュが ¥ の形で描かれないように）', () => {
  assert.match(css, /body \{[^}]*font-family: "Segoe UI", system-ui,/);
});

test('動きを減らす設定では、切り替えのアニメーションを止める', () => {
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{\s*\* \{ transition: none !important; \}/);
});
