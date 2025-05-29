# TLS Analyzer for MITMproxy

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/yourusername/tls-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/tls-analyzer/actions)

**TLS Analyzer**は、MITMproxy用のアドオンとして、TLSハンドシェイクを処理し、ログと証明書を効率的に記録します。JSONまたはCSV形式のログ、証明書（`.pem`）、SQLiteデータベース（証明書管理）、メトリクスログを生成し、高耐障害性とクロスプラットフォーム対応を実現します。

## 特徴

- **TLSハンドシェイクの記録**：TLSバージョン、サイファースイート、SNI、サーバー/発行者の共通名などを記録。
- **証明書管理**：証明書チェーンをPEM形式で保存、SQLiteで重複管理（最大10,000件、30日保持）。
- **バッファリングとリトライ**：メモリ使用量に応じた動的バッファ調整とリトライ機構。
- **ログ圧縮**：Gzip圧縮と失敗時のリカバリ（`failed_compression`ディレクトリ）。
- **メトリクス**：ログフラッシュ、リトライ、圧縮失敗などを`metrics.log`に記録。
- **クロスプラットフォーム**：Linux/Windows対応（Windowsでは非同期I/O無効）。
- **スレッドセーフ**：非同期I/O（Linux）とロック機構で高並行性。

## 要件

- Python 3.8+
- MITMproxy 11.0.0+
- 依存パッケージ（`requirements.txt`参照）：
  - `psutil`
  - `aiofiles`
  - `cryptography`

## インストール

1. リポジトリをクローン：
   ```bash
   git clone https://github.com/yourusername/tls-analyzer.git
   cd tls-analyzer
