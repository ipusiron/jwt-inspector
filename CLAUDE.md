# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JWT Inspector decodes and lints JWTs in the browser, creates and verifies HS, RS, PS and ES signatures with Web Crypto, checks small HS256 key dictionaries, and demonstrates alg=none and RS256-to-HS256 confusion with built-in samples. Part of the "生成AIで作るセキュリティツール100" (100 Security Tools with Generative AI) project, Day053.

**Live demo**: https://ipusiron.github.io/jwt-inspector/

## Development Commands

Static site with no build process and no dependencies.

```bash
npm test                    # node --test (Node.js 22+), no dependencies
python -m http.server 8000  # serve locally
```

## Code Architecture

- `index.html` - 6 tab panels in order: decode / verify / create / audit / lab / learn. No `style` attributes, inline scripts or handlers. Static text has `data-i18n` keys whose Japanese text must equal the dictionary (tested). All textareas carry `spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off"`
- `script.js` - DOM layer for decoding, verification, shared token transfers and tab selection. A state object holds the parsed token and verification/copy state; render functions are re-run on language changes. Input revisions and job IDs invalidate stale verification and clipboard feedback. The global clear action also calls the workbench clear function
- `js/jwt-core.js` - parsing and linting (`globalThis.JwtCore`, no DOM):
  - `decodeB64url` / `encodeB64url` check every character and distinguish `b64.padding` (=), `b64.standard` (+ /), `b64.char` and `b64.length`; `loose` marks non-zero leftover bits
  - `parseJsonObject` requires a JSON object (RFC 7515 §4). `duplicateKeys` finds repeated names only at the top level, including equivalent Unicode escapes; nested objects are not scanned for duplicates
  - `parseToken` returns `{ raw, signingInput, header, payload, signature, duplicates }`, or a failure whose code is prefixed with `header.` / `payload.` / `signature.`
  - `timeStatus` applies RFC 7519 §4.1.4–§4.1.6 with `DEFAULT_LEEWAY` 60 s; **exp at the same second counts as expired**
  - `lint` returns `{ findings, times }`; findings are `{ level, code, vars }` with level `danger | warn | info | ok`. `duration` rounds seconds to the largest unit for display
  - `ALGORITHMS` holds the 12 supported algorithms; check own properties or the allowlist, not inherited property names. `KNOWN_UNSUPPORTED` holds recognised but unsupported names. `MAX_TOKEN_CHARS` is 16384
- `js/jwt-verify.js` - verification (`globalThis.JwtVerify`):
  - `verify(token, alg, key)` uses only the algorithm passed in, never `header.alg` (RFC 8725 §3.1), and returns `mismatch` separately when they differ. `valid` reports signature matching, not an authentication or authorization decision; it does not enforce the lab's fixed-header gate
  - keys: HS as raw UTF-8, others as PEM SPKI or JWK. `pem.private`, `pem.pkcs1`, `pem.certificate`, `jwk.private`, `jwk.set` are rejected with those codes
  - `keyWarnings` applies RFC 7518 §3.2 (`MIN_HS_BITS`) and §3.3/§3.5 (`MIN_RSA_BITS` 2048)
  - PS uses `saltLength = bits / 8`; ES uses the curve from the algorithm
- `js/jwt-create.js` - creation (`globalThis.JwtCreate`):
  - `generateKey(alg)` returns `{ ok, alg, secret?, privateKey?, publicKey? }`. HS gets 32/48/64 random bytes and encodes them as 43/64/86 Base64url characters for HS256/384/512; the resulting text is the raw UTF-8 key, not decoded key bytes
  - RS/PS generate 2048-bit RSA keys; ES uses the selected curve. Private CryptoKeys are generated with `extractable:false` and registered with their original algorithm. Only these generated private keys are accepted for signing; no private-key import/export. `publicKey` is PEM SPKI text
  - `create({ headerText, payloadText, alg, key })` returns `{ ok, token, warnings }` on success. `key` is HS text or a generated private CryptoKey. Require JSON objects, no top-level duplicate names and an exact header.alg match; reject header crit and b64=false. Enforce the final token limit
- `js/jwt-lab.js` - local exercises (`globalThis.JwtLab`):
  - `checkWeakKey(tokenText, candidatesText, { signal, onProgress })` accepts HS256 only and returns `{ ok, status, tested, total, key? }`, with status `found`, `notFound` or `cancelled`. It uses Web Crypto verification, checks cancellation around awaits and yields to the UI between groups of candidates
  - `DEFAULT_CANDIDATES` has 20 entries; `MAX_CANDIDATES` is 1000, `MAX_CANDIDATE_BYTES` is 1024 UTF-8 bytes, and `MAX_CANDIDATES_CHARS` is 1048576 UTF-16 code units. Ignore empty lines, preserve leading/trailing spaces, and never interpret no match as proof of security
  - `runDemo('none' | 'confusion')` uses only `JwtSamples.verify.RS256` and changes role to admin. Return the original and modified tokens, `publicKey`, `expectedAlg: 'RS256'`, `unsafeAccepted`, `fixedAccepted` and `details`. The intentionally vulnerable path is lab-only; the fixed path checks header.alg === RS256 before verifying. Never add external target inputs to this path
- `js/workbench-ui.js` - `JwtWorkbench.init({ getToken, sendToken })` returns `{ render, clear }`. Separate create/audit/lab epochs and input snapshots discard results that finish after relevant changes. Audit uses an AbortController; cancellation cannot stop a Web Crypto operation already running
  - Every input, example, algorithm, clear and transfer path must invalidate or redraw the relevant state, not just a checkbox/change event. Re-render current results on `languagechange`, including hidden panels
  - A JSON example replaces only JSON and keeps the selected algorithm and key. Algorithm changes discard generated keys. Clear empties inputs, results and key references without restoring examples. Initial examples have no generated key
  - Sending a created token to verification also transfers its algorithm and shared/public key, but does not run verification automatically. Lab transfer always uses expected RS256 and the sample public key
  - Error-message lookup is `werr.<code>` → `err.<code>` → `verr.<code>`; rendering uses message codes and variables, not cached translated strings
- `js/samples.js` - sample tokens and keys. **Public keys and the demo shared secret only**; the private keys live outside this repository (ipusiron-work `ref/day053/`), and a test asserts no private material is present
- `js/messages.js` - Japanese and English dictionaries with the same keys (`JwtMessages.t(key, vars, lang)`)
- `js/i18n.js`, `js/theme-init.js`, `js/theme.js` - language and theme; localStorage access is always in `try`
- `style.css` - color tokens on `:root`, dark via `prefers-color-scheme` and `[data-theme="dark"]` (same values). `.btn.primary:hover` must also set `background`, because `.btn:hover:not(:disabled)` has the same specificity

Keep `theme-init.js` in the head. The remaining external scripts load in order: core, verify, samples, jwt-create, jwt-lab, messages, i18n, theme, workbench-ui, script. Keep the classic-script globals usable by the Node test loader; do not add dependencies or inline code.

## Samples and test vectors

`test/fixtures.json` and `js/samples.js` are generated by `business/research/try100_audit/ref/day053/make_samples.mjs` in the ipusiron-work repository, which signs with real keys via Node `crypto`. Regenerate there and copy; do not hand-edit the tokens. The demo shared secret is 64 bytes so that even HS512 meets RFC 7518 §3.2.

## Security Considerations

- CSP in `<meta>`: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'` (no `unsafe-inline`)
- No network requests at all: JWK Sets and `jku` URLs are deliberately not fetched
- All output is built with DOM APIs and `textContent` (no `innerHTML`; tested)
- Tokens and keys are not written to application storage; only language and theme choices are persisted
- Generated asymmetric private keys stay in memory as non-extractable CryptoKeys. Creation-tab clear, global clear, algorithm changes and reload lose them; this is not a guarantee of browser-memory zeroization
- Global clear removes all tabs' input, output and key references. Individual clear buttons may leave transferred data or verification keys in place. Decode clear invalidates the shared token and verification result but retains the verification key. Neither action erases the clipboard. Late asynchronous results must not repopulate cleared fields
- The dictionary check is for one's own tokens or explicitly permitted tests. A short key is not necessarily present in a dictionary, and no match is not a security verdict
- Signature matching and the lab's algorithm acceptance are distinct from authentication and authorization. Applications still need issuer, audience, time and permission checks

## Tests

- `test/core.test.js` - Base64url round trips and errors, top-level duplicate names including Unicode escapes, token parsing with prefixed error codes, time verdicts incl. leeway and Date limits, every lint item
- `test/verify.test.js` - all 12 algorithms from PEM and JWK, flipped signature bits, a rewritten payload, the RS256→HS256 public-key swap, key length warnings, malformed keys
- `test/create.test.js` - twelve-algorithm round trips and independent Node crypto verification, non-extractable generated keys, Unicode JSON, duplicate members, header gates and size limits
- `test/lab.test.js` - candidate parsing, limits, Unicode, progress, cancellation, no-match results, and both built-in demonstrations
- `test/ui-state.test.js` - delayed verification, key generation, signing and dictionary results; input/example/algorithm/clear/transfer invalidation; JSON-example key retention and language changes
- `test/html.test.js` - CSP, tab ARIA, labels, `aria-live`, spellcheck attributes, dictionary agreement, ids used by script.js, no innerHTML/style writes, no private keys in samples
- `test/contrast.test.js` - text 4.5:1 and borders 3:1 in light and dark, 44px controls, 16px inputs
- `test/messages.test.js`, `test/i18n.test.js` - every code the core can return has a message, no Japanese in the English dictionary, language selection
- `test/readme.test.js` - both READMEs (same headings), YAML structure, lint/algorithm/HS-generated-key tables and dictionary limits checked against the calculation modules, directory tree, images (7 screenshots each)
- `test/format.test.js` - line length (js/samples.js is data and exempt), LF, final newline

README numbers are checked by tests — derive them from the implementation. README describes current behavior, without release-history comparisons. Keep Japanese and English sections, examples and caveats aligned.

Each README uses seven screenshots: `screenshot.png` = decode, `screenshot2.png` = alg=none lint, `screenshot3.png` = ES256 creation, `screenshot4.png` = weak HS256 dictionary match, `screenshot5.png` = the ES256 verification sample with JWK, `screenshot6.png` = algorithm mismatch in dark mode, and `screenshot7.png` = RS256-to-HS256 lab in dark mode. Japanese images are in `assets/`, English in `assets/en/`. The creation transfer uses SPKI; do not relabel screenshot5 as that transfer.

## Deployment

GitHub Pages from the `main` branch root: https://ipusiron.github.io/jwt-inspector/ (`.nojekyll` disables Jekyll).
