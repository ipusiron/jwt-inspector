<!--
---
title: JWT Inspector
category: web-security
difficulty: 2
description: Decode and verify JWTs (HS256/RS256) in-browser, with security lint hints.
tags: [jwt, websecurity, crypto, education]
demo: https://ipusiron.github.io/jwt-inspector/
---
-->

# JWT Inspector - JWT（JSON Web Token）可視化・検証ツール

![GitHub Repo stars](https://img.shields.io/github/stars/ipusiron/jwt-inspector?style=social)
![GitHub forks](https://img.shields.io/github/forks/ipusiron/jwt-inspector?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/ipusiron/jwt-inspector)
![GitHub license](https://img.shields.io/github/license/ipusiron/jwt-inspector)
[![GitHub Pages](https://img.shields.io/badge/demo-GitHub%20Pages-blue?logo=github)](https://ipusiron.github.io/jwt-inspector/)

**Day053 - 生成AIで作るセキュリティツール100**

**JWT Inspector**は、ブラウザー上でJWTを**デコード／検証**し、典型的なリスク（`alg=none`、弱いHS鍵、期限切れなど）を**Lint表示**する軽量ツールです。

外部にトークンを送信しないため、学習・検証用途に安全に利用できます。

---

## 特長

- **デコード**: Base64URLデコードしてHeader/Payloadを整形表示
- **署名検証**: HS256（シェアードキー）、RS256（公開鍵PEM）をWebCryptoで検証
- **Lint**: 期限（`exp`/`nbf`）チェック、`alg=none`、`iat`の将来時刻、`kid`ヘッダなどを警告
- **学習タブ**: よくある誤用とベストプラクティスを簡潔に解説

---

## 使い方

1. トークンを貼り付けて「デコード」  
2. 検証タブでアルゴリズムを選択し、HS鍵またはRS公開鍵PEMを入力して「検証」  
3. 右側の**Lint結果**で注意点を確認

---

## セキュリティ注意

- 貼り付けたトークンや鍵は**ブラウザ内だけ**で処理します（送信なし）。
- 学習目的での使用を想定。実運用の鍵・トークンを取り扱う場合は十分に注意してください。

---

## 開発メモ

- 純HTML/CSS/JSのみ。依存パッケージなし。
- Web Crypto API（SubtleCrypto）を使用（HS256: HMAC-SHA-256、RS256: RSA-PSSではなくRSA-PKCS1-v1_5 + SHA-256）。

---

## 📁 ディレクトリー構成

```
```

---

## 📄 ライセンス

MIT License - 詳細は [LICENSE](LICENSE) をご覧ください。

---

## 🛠 このツールについて

本ツールは、「生成AIで作るセキュリティツール100」プロジェクトの一環として開発されました。  
このプロジェクトでは、AIの支援を活用しながら、セキュリティに関連するさまざまなツールを100日間にわたり制作・公開していく取り組みを行っています。

プロジェクトの詳細や他のツールについては、以下のページをご覧ください。  

🔗 [https://akademeia.info/?page_id=42163](https://akademeia.info/?page_id=42163)