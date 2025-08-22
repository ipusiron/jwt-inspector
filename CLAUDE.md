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

## Future Enhancement Ideas (Not TODO - implement when time permits)

以下は将来的な改善アイデアです。余裕があるときに実装を検討してください。

### UI/UX改善
- **ダークモード切り替え**: ユーザー設定でライト/ダークモード選択
- **フォントサイズ調整**: アクセシビリティ向上のための文字サイズ変更機能
- **コードブロックのシンタックスハイライト**: JSON表示の色分け
- **コピーボタン**: Header、Payload、署名の各セクションにワンクリックコピー機能
- **キーボードショートカット**: Ctrl+Enter でデコード実行など
- **ドラッグ&ドロップ**: JWTファイルの直接ドロップ対応
- **履歴機能**: 過去に入力したJWTの履歴保存

### 機能強化
- **より多くのアルゴリズム対応**: ES256、PS256、EdDSA等
- **JWE (JSON Web Encryption)対応**: 暗号化されたJWTの解析
- **JWK (JSON Web Key)対応**: 公開鍵セットからの自動キー選択
- **クレーム詳細解説**: 各クレームの意味と用途の説明表示
- **時刻表示改善**: Unix時間を人間が読める形式で併記
- **JWKS URL対応**: エンドポイントから公開鍵を自動取得
- **複数鍵での一括検証**: 複数の候補鍵で順次検証試行
- **鍵生成機能**: HS256用の安全な鍵生成ツール

### セキュリティ機能
- **より詳細なLint機能**: 弱いHS256鍵の強度チェック、推奨されないクレーム値の検出
- **脆弱性データベース連携**: 既知の脆弱なJWT実装との照合
- **セキュリティスコア**: JWT全体のセキュリティレベル評価

### 分析・レポート機能
- **JWT使用統計**: デコードしたJWTの統計情報
- **レポート出力**: PDF、HTML形式でのセキュリティレポート
- **JSON/CSV出力**: 解析結果のデータ形式での出力

### 開発者向け機能
- **REST API提供**: 他ツールからのJWT解析API
- **CLI版**: コマンドライン版ツールの提供
- **ブラウザー拡張**: Chrome/Firefox拡張としての提供
- **VS Code拡張**: 開発環境での統合
- **CI/CD統合**: パイプラインでのJWTセキュリティチェック
- **バッチ処理**: 複数JWTファイルの一括解析

### 教育・学習機能
- **インタラクティブチュートリアル**: ステップバイステップの学習機能
- **攻撃シナリオ実習**: 安全な環境での攻撃手法学習
- **チャレンジ問題**: JWT関連の練習問題
- **レベル別学習**: 初級〜上級者向けコンテンツ

### セキュリティ・プライバシー
- **完全オフライン化**: ネットワーク通信の完全排除オプション
- **データ暗号化**: ローカルストレージの暗号化
- **自動データ削除**: 設定時間後の自動クリア
- **プライベートモード**: 履歴・キャッシュを残さないモード

### 多言語・アクセシビリティ
- **多言語対応**: 英語、中国語、韓国語等の多言語化
- **スクリーンリーダー対応**: 視覚障害者向けの改善
- **高コントラスト表示**: 視認性向上のための表示オプション

### パフォーマンス
- **大容量JWT対応**: メガバイト級JWTの処理最適化
- **Web Workers活用**: UIブロックしない非同期処理
- **メモリ使用量最適化**: 大量データ処理時のメモリ効率化