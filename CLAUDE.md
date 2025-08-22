# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JWT Inspector is a client-side web application for decoding and verifying JSON Web Tokens (JWTs). The tool provides security linting and educational features for JWT analysis without sending tokens to external servers.

## Architecture

- **Pure HTML/CSS/JS**: No build process or dependencies required
- **Client-side only**: All JWT processing happens in the browser using Web Crypto API
- **Three main tabs**: Decode, Verify, Learn
- **Web Crypto API usage**: 
  - HS256: HMAC-SHA-256
  - RS256: RSA-PKCS1-v1_5 + SHA-256 (not RSA-PSS)

## File Structure

- `index.html`: Main application interface with tabbed UI
- `script.js`: Core JWT processing logic, Web Crypto operations, and UI handlers
- `style.css`: Dark theme styling with CSS custom properties
- `README.md`: Japanese documentation with project details

## Key Functions

### JWT Processing (`script.js`)
- `parseJwtParts()`: Splits JWT into header.payload.signature
- `b64urlToUint8Array()` / `uint8ArrayToB64url()`: Base64URL encoding/decoding
- `lintJwt()`: Security analysis (alg=none, expiration, weak patterns)
- `verifyHS256()` / `verifyRS256()`: Signature verification using Web Crypto API

### Security Linting Rules
- Rejects `alg=none` tokens
- Validates expiration (`exp`) and not-before (`nbf`) claims
- Warns about future-dated `iat` claims
- Checks for `kid` header (directory traversal risks)
- Validates PEM format for RS256 public keys

## Development Commands

This is a static web application with no build process:
- Open `index.html` directly in browser for local testing
- Deploy by hosting static files (currently on GitHub Pages)

## Security Focus

This tool is designed for **defensive security analysis only**:
- Educational JWT security demonstrations
- Client-side token analysis (no external transmission)
- Security vulnerability identification and teaching
- Best practices guidance for JWT implementation