English · [日本語](README.md)

# JWT Inspector - JWT Decoder, Signer and Security Lab

![GitHub Repo stars](https://img.shields.io/github/stars/ipusiron/jwt-inspector?style=social)
![GitHub forks](https://img.shields.io/github/forks/ipusiron/jwt-inspector?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/ipusiron/jwt-inspector)
![GitHub license](https://img.shields.io/github/license/ipusiron/jwt-inspector)
[![GitHub Pages](https://img.shields.io/badge/demo-GitHub%20Pages-blue?logo=github)](https://ipusiron.github.io/jwt-inspector/)

**Day053 - 100 Security Tools with Generative AI**

JWT Inspector is a browser-local learning tool for decoding, linting, creating and verifying JWTs. It supports twelve algorithms in the HS, RS, PS and ES families, a small HS256 dictionary check, and algorithm-confusion demonstrations with built-in samples. Each lint result includes its RFC section, and neither tokens nor keys are sent anywhere.

---

## 🌐 Demo

👉 **[https://ipusiron.github.io/jwt-inspector/](https://ipusiron.github.io/jwt-inspector/)**

You can try it directly in your browser.

---

## 📸 Screenshots

>![A valid token decoded](assets/en/screenshot.png)
>
>*The header and payload decoded, with the size of the signature*

>![Lint results for an alg=none token](assets/en/screenshot2.png)
>
>*alg=none is flagged as dangerous, with the reason and the RFC section*

>![Creating a JWT with ES256](assets/en/screenshot3.png)
>
>*Sign JSON with ES256, view the created JWT, and send it to signature verification*

>![Finding a weak HS256 key with a small dictionary](assets/en/screenshot4.png)
>
>*Test candidate keys in order and view the matching key and number tested*

>![An ES256 signature verified with a JWK](assets/en/screenshot5.png)
>
>*An ES256 signature verified with a JWK public key, with the key size and how it was read*

>![Verification with an algorithm other than the one in the header (dark mode)](assets/en/screenshot6.png)
>
>*An HS256 signature does not match when checked with HS384; the header mismatch is also shown*

>![Demonstrating RS256-to-HS256 confusion](assets/en/screenshot7.png)
>
>*Compare a vulnerable implementation that uses a public key as an HMAC secret with one fixed to RS256 (dark mode)*

---

## 🔑 What this tool looks at

Even in a signed JWT, the payload is not encrypted. Anyone can read it by undoing Base64url. A correct signature can still lead to impersonation if the allowed algorithm, issuer or audience is not checked. RFC 8725 is the BCP that collects real attacks and their countermeasures.

From a single token, this tool checks:

- what the alg in the header is, and whether it is none or a case variant of it
- whether headers that point at a key (jku, x5u, jwk, kid) are present
- how the time claims (exp, nbf, iat) stand against the current time
- whether the issuer and the audience (iss, aud) are present and of the right type
- whether the payload carries claims whose names look like secrets
- whether the signature verifies with the key you have, and whether that key meets the length the RFCs require
- whether the HS256 signature matches any of the candidate keys you supply

The Create and sign tab lets you make your own JWTs. The Attack lab tab modifies a built-in sample so you can compare verification decisions.

---

## ✨ Features

### Decode and lint

- Decodes Base64url one character at a time, reporting = padding, mixed-in + and /, and lengths that cannot work, each with its position
- Checks that the header and the payload are JSON objects, and reports repeated member names at the top level of each object (RFC 7515 §4)
- Groups the lint results into danger, warning, note and good, each with the RFC section it comes from
- Shows the time claims in a table of Unix time, UTC, the time of this device and the verdict, with a clock skew leeway of 60 seconds
- Lists the meaning of the registered claims (iss, sub, aud, exp, nbf, iat, jti)
- Four samples (valid, expired, alg=none, risky header)

### Verify the signature

- Twelve algorithms: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
- The algorithm used for verification is chosen on the page, not taken from the header (RFC 8725 §3.1). A mismatch is reported
- Keys are a shared secret for HS, and a PEM (SPKI) or a JWK otherwise. Private keys, PKCS#1, certificates and JWK Sets are rejected with the reason
- Key lengths are checked against RFC 7518 (HMAC at least as long as the hash output, RSA at least 2048 bits)
- Five samples (HS256, RS256 as PEM, PS256 as JWK, ES256 as JWK, weak key)

### Create and sign

- Creates JWTs with the same twelve algorithms. Edit the header and payload as JSON, with alg matching the selected algorithm
- For HS, enter a UTF-8 shared secret or generate a text key from cryptographically random bytes
- For RS, PS and ES, generate keys on the page. The private key stays in a non-extractable CryptoKey; only the public key is displayed as PEM SPKI
- Rejects top-level duplicate member names in the header or payload, and crit or b64=false in the header
- Copy the created JWT or send it to decoding or signature verification. Verification also receives the shared secret or public key

### Weak-key check

- Checks an HS256 token against the twenty default candidates or newline-separated candidate keys
- Limits: 1000 candidates, 1024 UTF-8 bytes per candidate, and 1048576 characters (UTF-16 code units) for the entire candidates field
- Ignores empty lines and preserves leading and trailing spaces in keys. Shows progress and supports cancellation
- Displays a matching candidate key and the number tested. Finding no match does not establish key security

### Attack lab

- Uses the built-in RS256 sample to demonstrate skipping the signature with alg=none and confusing RS256 with HS256
- Changes role to admin and compares acceptance or rejection by a vulnerable implementation and one fixed to RS256
- Displays the original JWT, modified JWT and public key. There is no facility to specify an external token or URL as an attack target

### Learn

- The structure, the fact that the payload is readable, alg=none and fixing the algorithm, key strength, headers that point at keys, and checking times and recipients, each with its RFC section

### Common

- Japanese and English (`?lang=ja`, `?lang=en`; the chosen language is saved)
- Light and dark themes (follows the OS setting unless a choice has been saved)
- Keyboard operation (tabs move with the arrow keys, Home and End)
- "Clear all input and keys" discards inputs, results and held keys across all tabs. It does not clear the clipboard
- Changes to inputs, examples or algorithms, and clearing, discard stale asynchronous results. Language changes also translate the current results

---

## 📖 How to use

### Decode and verify signatures

1. Paste a JWT into the "Decode and lint" tab. The sample buttons also work.
2. Read the lint results from the top. Each danger and warning says which RFC section it is measured against.
3. To check the signature, go to the "Verify" tab, choose the algorithm and paste the key. The token comes from the same field as the decode tab.
4. "Match the alg in the header" switches to the header's algorithm. Choose a different one on purpose to see that it does not verify.

### Create a JWT

1. In the "Create and sign" tab, press "Insert JSON example" and select ES256.
2. Press "Generate a key" and wait for the public key to appear. The private key is neither displayed nor saved.
3. Edit the payload if needed, then press "Create a JWT".
4. "Send to verify" transfers the JWT, the ES256 selection and the public key to the verification tab. Press "Verify the signature" to check the result.

For HS, enter or generate a shared secret. "Insert JSON example" replaces only the JSON, keeping the current algorithm and key. Changing the algorithm discards the key, so generate one for the new algorithm.

### Check with a small dictionary

1. In the "Weak key check" tab, press "Insert weak key example".
2. Press "Start check" to find the matching key among the twenty default candidates.
3. To check your own token, or one you have permission to test, replace the JWT and candidates. "Use the decode input" also transfers the JWT.
4. Press "Stop" to cancel. Finding no matching candidate does not prove security.

### Demonstrate algorithm confusion

1. In the "Attack lab" tab, choose the alg=none or RS256→HS256 scenario.
2. Press "Run the demo" and use the comparison table to confirm that only the vulnerable implementation accepts the modified JWT.
3. Read the original and modified JWTs and the explanation. "Send to verify" transfers RS256 and the public key, so you can verify without changing the selection.

When finished, press "Clear all input and keys". Clearing does not automatically restore examples or keys.

---

## 🔬 Technical notes

### The structure of a JWT

The JWS Compact Serialization (RFC 7515 §7.1) is the header, the payload and the signature, each in Base64url and joined with dots. Base64url here omits the trailing = (§2). The signature covers the whole string "header.payload", so changing one character makes it no longer match.

### What is linted

| Item | Verdict | Basis |
|---|---|---|
| alg=none | Danger | RFC 8725 §2.1. Without a signature, anyone can change the content |
| alg as None, NONE and so on | Danger | RFC 7515 §4.1.1 defines alg as case-sensitive; an implementation that ignores case reads it as none |
| jku, x5u | Danger | RFC 8725 §3.10. A verifier that fetches them can be sent to a server of the attacker's choosing |
| jwk | Danger | The token carries its own public key; verifying with it lets anyone sign |
| kid | Warning | RFC 8725 §3.10. Used as-is for key lookup, it opens the door to injection |
| crit | Warning | RFC 7515 §4.1.11. A token must be rejected when the listed extensions are not understood |
| Repeated member names | Danger | RFC 7515 §4. Implementations may read different ones |
| exp at or before now | Danger | RFC 7519 §4.1.4. The same second as exp also counts as expired |
| nbf in the future | Danger | RFC 7519 §4.1.5 |
| iat in the future | Warning | RFC 7519 §4.1.6 |
| iss or aud missing | Warning | RFC 8725 §3.8 and §3.9 |
| typ missing | Note | RFC 8725 §3.11 recommends stating the type |
| Claims whose names look like secrets | Danger | The payload is only signed, not encrypted |

### Supported algorithms

| Family | Names | Web Crypto name | Verification key |
|---|---|---|---|
| HS | HS256, HS384, HS512 | HMAC | Shared secret (UTF-8 text) |
| RS | RS256, RS384, RS512 | RSASSA-PKCS1-v1_5 | Public key (PEM SPKI or JWK) |
| PS | PS256, PS384, PS512 | RSA-PSS | Public key (same) |
| ES | ES256, ES384, ES512 | ECDSA (P-256, P-384, P-521) | Public key (same) |

The PS salt length equals the hash output (RFC 7518 §3.5). The ES curve follows from the algorithm (§3.4).

For creation, HS uses a shared secret, while RS, PS and ES use a private key generated on the page. Generated RSA keys are 2048 bits. Private keys are generated with `extractable:false`; only keys generated on the same page and used with their original algorithm are accepted. The public key is exported as PEM SPKI and can be sent to verification.

### HS key generation and text

HS key generation uses Web Crypto's `getRandomValues` to obtain as many random bits as the hash output, then converts them into Base64url text. That text is used directly as the UTF-8 shared secret, without decoding it.

| Algorithm | Random bytes generated | UTF-8 key text (characters = bytes) |
|---|---|---|
| HS256 | 32 | 43 |
| HS384 | 48 | 64 |
| HS512 | 64 | 86 |

The HS key size shown during verification is the UTF-8 byte count multiplied by eight, in bits. Increasing the character count through Base64url encoding does not add entropy to the original random bytes.

### Key length

RFC 7518 §3.2 requires an HMAC key at least as long as the hash output (256 bits for HS256). RSA keys must be 2048 bits or more (§3.3 and §3.5). RFC 8725 §3.5 states that a human-memorable password must not be used directly as an HS256 key. Predictable keys may be found by testing candidates in a local dictionary attack. Length alone does not determine how difficult a key is to guess.

This tool flags a short key as dangerous even when the signature verifies.

### Fixing the algorithm

RFC 8725 §3.1 requires the caller to specify the supported algorithms and the library to use no others. An implementation that follows the header's alg without restricting allowed algorithms or key types may be vulnerable to these attacks:

- a token whose alg was rewritten to none
- a token whose RS256 was rewritten to HS256 and re-signed using the public key as the HMAC shared secret (CVE-2015-9235)

The verification tab's `JwtVerify.verify` checks the signature with the algorithm selected on the page and reports a header mismatch separately. Its `valid` result means that the signature matches; it is not an authentication or authorization decision.

The Attack lab uses only the built-in RS256 sample. The none example omits the signature; the confusion example uses the public PEM text as the HMAC shared secret. The safer comparison fixes the algorithm to RS256 and rejects the token before signature verification unless the header's alg is exactly RS256. Both examples change role to admin and compare the original and modified tokens. Authentication and authorization also require checks of the issuer, audience, expiry and application permissions.

---

## 🎯 Use cases

- Checking your own service: inspect exp, iss, aud and key length in issued tokens, and test HS256 candidate keys within the scope of your permission
- Reviewing an implementation: show alg=none and algorithm pinning on a working page when discussing them with your team
- CTFs and exercises: decode a provided token, check candidate keys and compare it with a token you sign yourself
- Teaching: let people read the payload to see that a JWT is not encrypted and what the signature actually protects
- Design decisions: compare HS, RS, PS and ES side by side, including how the keys have to be distributed
- Research and implementation comparison: examine signature matching separately from algorithm acceptance, and use the built-in sample results in explanations
- Debugging: when authentication fails, separate an expired token from a wrong key or a wrong algorithm
- Writing documents: attach the lint screen to an internal guideline or a review checklist
- Classes and training: generate keys, sign and verify tokens, and explore alg=none and public-key confusion with the built-in samples

---

## 🔒 Security

- Content Security Policy (meta tag): `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`. No inline scripts or styles, and no external communication
- Tokens and keys are processed only in the browser, never sent anywhere, and never written to application storage
- The token and key fields turn off spell checking and autocorrect, so that a pasted key is not sent to an external spell checker
- The page is built with the DOM (`textContent`), never `innerHTML`
- `<meta name="referrer" content="no-referrer">`; external links use `rel="noopener noreferrer"`
- Only the language and theme choices are stored in the browser
- Key generation, signing and signature verification use Web Crypto, without external libraries
- Asymmetric private keys are held as non-extractable CryptoKeys in memory. Private-key input, file saving and export are not provided
- Dictionary checks limit the count and input size, and yield between operations so the page remains interactive. Stale results completed after input changes or clearing are not displayed

---

## ⚠️ Notes and limitations

- The sample keys were made for this tool's demos. They are not production keys
- When handling real keys or tokens, open the page on your own device and clear the fields afterwards
- Use the small dictionary check only on your own tokens or tokens you have permission to test. It supports HS256 only, with limits of 1000 candidates, 1024 UTF-8 bytes per candidate and 1048576 UTF-16 code units in the entire candidates field
- No match means only that none of the supplied candidates matched the signature. It does not prove key security or resistance to guessing
- Generated asymmetric private keys exist only in memory and are lost on clearing, an algorithm change or a page reload. Private-key import and export are not provided
- Clearing all inputs and keys removes displayed data, results and held references; it does not guarantee that browser memory is overwritten with zeroes. An in-progress Web Crypto operation may finish, but its stale result is discarded
- Clearing does not erase data already copied to the clipboard. A tab's clear button affects only that tab; use the global clear button to remove data transferred to other tabs
- EdDSA and JWE (encrypted JWTs) are not supported
- JWK Sets are not read, and keys are not fetched from a jku URL (the tool makes no external requests)
- Linting is limited to what a single token shows. A matching signature is not authentication or authorization; the application must check the issuer, audience, expiry and permissions
- Duplicate member detection covers only the top level of the header and payload, not every nested object. Creation rejects those duplicates, and crit or b64=false in the header
- Tokens are read up to 16384 characters

---

## 🧪 Tests

```bash
npm test
```

- Runs with `node --test` on Node.js 22 or later, with no dependencies (no `npm install` needed)
- Runs on GitHub Actions for every push and pull request
- `test/core.test.js`: Base64url round trips and errors, detection of repeated member names, token parsing, time verdicts, every lint item
- `test/verify.test.js`: verification of the twelve algorithms (PEM and JWK), a single flipped bit in the signature, a rewritten payload, the public-key-as-HMAC-key swap, key lengths, malformed keys
- `test/create.test.js`: key generation and signing with twelve algorithms, independent verification with Node.js crypto, private-key export rejection, Unicode, top-level duplicate members and input limits
- `test/lab.test.js`: dictionary matches, no-match results, progress, cancellation and limits, plus the alg=none and RS256-to-HS256 demonstrations
- `test/ui-state.test.js`: input changes, examples, clearing, transfers, language switching and discarding late key-generation, signing and checking results
- `test/html.test.js`, `test/contrast.test.js`, `test/messages.test.js`, `test/i18n.test.js`, `test/format.test.js`: CSP, tab ARIA, dictionary and page text, color contrast (4.5:1 and 3:1), formatting
- `test/readme.test.js`: checks the README tables (lint items, algorithms, generated HS keys) and dictionary limits against the calculation modules, and the headings, images and directory structure of both READMEs
- The samples and test vectors were produced with Node.js `crypto` using real keys. No private key is kept in this repository

---

## 🔗 References

- [RFC 7515 JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7517 JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7518 JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518)
- [RFC 7519 JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 8725 JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)

---

## 📁 Directory structure

```
jwt-inspector/
├── index.html                # The page (six tabs)
├── script.js                 # Page logic (building the DOM, events)
├── style.css                 # Color tokens (light and dark) and layout
├── js/                       # Scripts shared by the page and the tests
│   ├── jwt-core.js           # Base64url, JSON, token parsing, times, linting (no DOM)
│   ├── jwt-verify.js         # Signature verification (Web Crypto), PEM and JWK, key lengths
│   ├── jwt-create.js         # In-memory key generation and JWT signing
│   ├── jwt-lab.js            # Small HS256 dictionary checks and built-in sample demonstrations
│   ├── workbench-ui.js       # Creation, dictionary and demonstration UI with asynchronous state
│   ├── samples.js            # Sample tokens and keys (public keys and a demo secret only)
│   ├── messages.js           # Japanese and English text
│   ├── i18n.js               # Language selection and static text replacement
│   ├── theme-init.js         # Applies the saved theme before rendering
│   └── theme.js              # Light and dark switching
├── test/                     # Tests with node:test
│   ├── load.js               # Helper that loads js/*.js into the tests
│   ├── fixtures.json         # Test vectors (tokens and keys for twelve algorithms)
│   ├── core.test.js          # Decoding, linting, times
│   ├── verify.test.js        # Signature verification and key formats
│   ├── create.test.js        # Key generation, signing and input limits
│   ├── lab.test.js           # Dictionary checks, cancellation and algorithm confusion
│   ├── ui-state.test.js      # Input changes, language switching and discarding stale asynchronous results
│   ├── readme.test.js        # README tables, headings, images, structure
│   ├── html.test.js          # CSP, ARIA, text, ids
│   ├── contrast.test.js      # Color contrast, 44px and 16px
│   ├── messages.test.js      # Dictionary keys, notation, numbers
│   ├── i18n.test.js          # How the language is chosen
│   └── format.test.js        # Line length, line endings, final newline
├── assets/                   # README screenshots
│   ├── screenshot.png        # Decode (Japanese)
│   ├── screenshot2.png       # alg=none lint (Japanese)
│   ├── screenshot3.png       # ES256 creation (Japanese)
│   ├── screenshot4.png       # HS256 dictionary check (Japanese)
│   ├── screenshot5.png       # ES256 verification (Japanese)
│   ├── screenshot6.png       # Algorithm mismatch (Japanese, dark)
│   ├── screenshot7.png       # RS256-to-HS256 confusion (Japanese, dark)
│   └── en/                   # Screenshots of the English page (the same seven)
├── .github/                  # GitHub settings
│   └── workflows/            # GitHub Actions workflows
│       └── test.yml          # Runs npm test on push and pull request
├── package.json              # Defines npm test (no dependencies)
├── .gitignore                # Files kept out of Git
├── .nojekyll                 # Disables Jekyll on GitHub Pages
├── CLAUDE.md                 # Development notes for Claude Code
├── FUTURE_IDEAS.md           # Future enhancement ideas
├── LICENSE                   # MIT License
├── README.md                 # Japanese README
└── README.en.md              # This file
```

---

## 💻 Requirements

- A recent browser (checked on Chromium, Edge and Firefox; Safari not checked)
- Key generation, signing and signature verification use Web Crypto. An error is shown when it is unavailable

```bash
python -m http.server 8000
# open http://localhost:8000/
```

---

## 📄 License

- See the `LICENSE` file (MIT) for the source code license.
- No external libraries are used. Key generation, signing and signature verification use the browser's Web Crypto.

---

## 🛠️ About this tool

This tool was developed as part of the "100 Security Tools with Generative AI" project.
The project builds and publishes a variety of security-related tools over 100 days with the help of AI.

For details about the project and other tools, see the page below.

🔗 [https://akademeia.info/?page_id=42163](https://akademeia.info/?page_id=42163)
