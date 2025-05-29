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
```

##　環境を作成（推奨）：
  ```bash
  python -m venv venv
  source venv/bin/activate  # Linux/Mac
  venv\Scripts\activate     # Windows
```
##　依存パッケージをインストール：
  ```bash
  pip install -r requirements.txt
```

使用方法
MITMproxyでアドオンを実行：
  ```bash
  mitmproxy -s tls_analyzer.py
```

または、Webインターフェースを使用：
  ```bash
  mitmweb -s tls_analyzer.py
```

出力ディレクトリ（tls_logs/）：
ログ：tls_log_YYYYMMDD_HHMMSS_NNN.json(.gz)

証明書：cert_[common_name]_chainNN_[hash]_[counter].pem

データベース：saved_certs.db

失敗ファイル：failed_compression/

メトリクス：metrics.log

サンプル出力
JSONログ：

```json
{
  "timestamp": 1745678901.234,
  "log_time_utc": "2025-05-30T12:15:01.234Z",
  "client_ip": "192.168.1.100",
  "client_port": 54321,
  "server_ip": "93.184.216.34",
  "server_port": 443,
  "tls_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "server_common_name": "example.com",
  "issuer_common_name": "DigiCert Global CA",
  "handshake_time_ms": 25.0,
  "sni": "example.com",
  "tls_extensions": ["server_name", "supported_versions"]
}
```

メトリクスログ：
```
2025-05-30 12:15:01 - Metric: buffer_size = 2000
2025-05-30 12:15:01 - Metric: saved_certs = 1
2025-05-30 12:15:01 - Debug: Set permissions 0o600 for tls_logs/cert_example_com_chain00_abc123_001.pem
2025-05-30 12:15:05 - Metric: cert_successful_retries = 1
```
テスト
テストはtls_analyzer.pyに統合されています。実行方法：
```bash
python -m unittest tls_analyzer.py
```

テストケース：
ファイル名サニタイズ（sanitize_filename）
ログと証明書のフラッシュ
リトライキュー処理
CSVヘッダー重複防止
圧縮リトライと失敗処理
証明書メモリ制限
ファイルパーミッション
ロールオーバー間隔の型チェック
TLS発行者名抽出
リトライカウント

注意点
ディスクとメモリ
failed_compression/：容量を定期的に監視。

バッファサイズ：高トラフィックではDEFAULT_BUFFER_MAX_SIZE（2000）を増やす（例：5000）。

証明書上限：MAX_SAVED_CERTS（10,000）を調整。

データベース
SQLiteはWALモードで同時性向上。超高負荷ではPostgreSQLを検討：
```python
from sqlalchemy import create_engine
engine = create_engine('postgresql://user:pass@localhost/db')
```


セキュリティ
パーミッション：ディレクトリ（0o700）、証明書（0o600）。Windowsでは0o666にフォールバック。

ACL：WindowsでACLが必要な場合、以下を検討：
```python
import win32security
# ACL設定（実装例はドキュメント参照）
```
暗号化：ログとDBはgpgなどで暗号化推奨。

パフォーマンス
非同期I/O：Windowsでは無効（use_async_io=False）。
ログ形式：CSVは高負荷で遅延。JSONを推奨。
ローテーション：DEFAULT_ROLLOVER_INTERVAL_SEC（300秒）をトラフィックに応じて調整。

カスタマイズ
ログ形式：log_format="csv"でCSV出力。
証明書パーミッション：cert_file_permissions=0o640で読み取り権限を追加。
バッファサイズ：buffer_max_size=5000で大規模トラフィック対応。
データベース無効化：persist_certs_db=FalseでSQLiteを無効。

ロードマップ
PostgreSQLサポート
ログ暗号化（GPG統合）
リアルタイムメトリクスダッシュボード
Windows ACL対応
テストをtests/ディレクトリに分割


