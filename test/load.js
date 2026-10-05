// 画面と同じ通常のスクリプト（js/*.js）を、テストの実行環境に読み込む。
// vm.runInThisContext で読むので、結果のオブジェクトはテスト側と同じ realm になる（deepStrictEqual で比べられる）
import fs from 'node:fs';
import vm from 'node:vm';

export const read = (f) => fs.readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

// ブラウザーにあって Node にないもの（PEM の読み取りで使う）
if (typeof globalThis.atob !== 'function') {
  globalThis.atob = (s) => Buffer.from(s, 'base64').toString('binary');
}

const loaded = new Set();
export function load(file) {
  if (!loaded.has(file)) {
    vm.runInThisContext(read(file), { filename: file });
    loaded.add(file);
  }
  return globalThis;
}

export const core = () => load('js/jwt-core.js').JwtCore;
export const verifier = () => {
  load('js/jwt-core.js');
  return load('js/jwt-verify.js').JwtVerify;
};

// サンプルと試験値（ipusiron-work 側の ref/day053 で、Node の crypto を使って作ったもの）
export const fixtures = JSON.parse(read('test/fixtures.json'));
