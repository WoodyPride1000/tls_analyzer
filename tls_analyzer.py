
import json
import os
import re
import hashlib
import threading
import time
import gzip
import shutil
import queue
import sqlite3
import psutil
import logging
import csv
from collections import OrderedDict
from datetime import datetime
import stat
from contextlib import contextmanager
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from mitmproxy import ctx
from mitmproxy.net import tls
import aiofiles
import asyncio
import platform
import unittest
from unittest.mock import Mock, patch

# --- 定数 ---
DEFAULT_ROLLOVER_INTERVAL_SEC = 300
DEFAULT_BUFFER_MAX_SIZE = 2000
DEFAULT_MAX_RETRIES = 3
DEFAULT_CERT_BUFFER_MAX_SIZE = 500

# --- ヘルパー関数 ---

def sanitize_filename(name: str, max_length: int = 150) -> str:
    """ファイル名を安全に変換し、命名規則を保持。

    Args:
        name: サニタイズするファイル名。
        max_length: 最大長（拡張子を含む）。

    Returns:
         サニタイズ済みのファイル名。
    """
    if not name or name.isspace():
        return "unknown"

    base_name, ext = os.path.splitext(name)
    ext = ext[:10]  # 拡張子の長さ制限
    sanitized = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', base_name)
    sanitized = re.sub(r'_+', '_', sanitized)

    if sanitized in {'.', '..'}:
        sanitized = f"invalid_{sanitized}"

    max_base_length = max_length - len(ext)
    sanitized = sanitized[:max_base_length]
    result = sanitized + ext
    return result or "unknown"

def get_available_memory_mb() -> int:
    """利用可能なメモリ（MB）を返す。"""
    return psutil.virtual_memory().available // (1024 * 1024)

def is_windows() -> bool:
    """Windows環境か判定。"""
    return platform.system() == "Windows"

def escape_csv_field(value) -> str:
    """CSVフィールドをエスケープ。"""
    if value is None:
        return ''
    value = str(value)
    if any(c in value for c in ',\n"'):
        return f'"{value.replace('"', '""')}"'
    return value

# --- モニタリングロガー ---

class MetricsLogger:
    def __init__(self, log_dir: str, metrics_file: str = "metrics.log"):
        """メトリクスロガーを初期化。

        Args:
            log_dir: メトリクスログの保存ディレクトリ。
            metrics_file: メトリクスログファイル名。
        """
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True, mode=0o700)
        self.metrics_file = os.path.join(log_dir, metrics_file)
        self.logger = logging.getLogger("MetricsLogger")
        handler = logging.FileHandler(self.metrics_file)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.retry_counts = {}
        self.successful_retries = 0
        self.compression_failures = 0

    def log_metric(self, metric_name: str, value: float) -> None:
        """メトリクスを記録。

        Args:
            metric_name: メトリクス名。
            value: メトリクス値。
        """
        self.logger.info(f"Metric: {metric_name} = {value}")

    def log_retry_attempt(self, retries_attempted: int, success: bool = False, is_cert: bool = False) -> None:
        """リトライ試行を記録。

        Args:
            retries_attempted: 試行されたリトライ回数。
            success: 成功したかどうか。
            is_cert: 証明書関連のリトライかどうか。
        """
        prefix = "cert_" if is_cert else ""
        if success:
            self.successful_retries += 1
            self.logger.info(f"Metric: {prefix}successful_retries = {self.successful_retries}")
        else:
            self.retry_counts[retries_attempted] = self.retry_counts.get(retries_attempted, 0) + 1
            self.logger.info(
                f"Metric: {prefix}retry_attempt_count retries={retries_attempted} count={self.retry_counts[retries_attempted]}"
            )

    def log_compression_failure(self, filename: str) -> None:
        """圧縮失敗を記録。

        Args:
            filename: 失敗したファイル名。
        """
        self.compression_failures += 1
        self.logger.info(f"Metric: compression_failure file={filename} count={self.compression_failures}")

    def stop(self):
        """ロガーを停止。"""
        for handler in self.logger.handlers:
            handler.close()
        self.logger.handlers = []
        self.logger.info("MetricsLogger stopped.")

# --- バッファリングロガー ベースクラス ---

class BufferedLogWriter:
    MIN_BUFFER_SIZE = 100
    MAX_BUFFER_SIZE = 5000
    MEMORY_THRESHOLD_MB = 50
    BACKOFF_INITIAL_MS = 100
    FIELD_ORDER = [
        "timestamp", "log_time_utc", "client_ip", "client_port",
        "server_ip", "server_port", "tls_version", "cipher_suite",
        "server_common_name", "issuer_common_name", "handshake_time_ms",
        "sni", "tls_extensions"
    ]

    def __init__(
        self,
        log_dir: str = "tls_logs",
        rollover_interval_sec: int = DEFAULT_ROLLOVER_INTERVAL_SEC,
        buffer_max_size: int = DEFAULT_BUFFER_MAX_SIZE,
        max_retries: int = DEFAULT_MAX_RETRIES,
        compress_on_rollover: bool = True,
        use_async_io: bool = True,
        log_format: str = "json",
        metrics_logger: MetricsLogger = None
    ):
        """バッファリングロガーを初期化。

        Args:
            log_dir: ログ保存ディレクトリ。
            rollover_interval_sec: ログローテーション間隔（秒)。
            buffer_max_size: バッファの最大サイズ。
            max_retries: 最大リトライ回数。
            compress_on_rollover: ロールオーバー時に圧縮を行うか。
            use_async_io: 非同期I/Oを使用するか。
            log_format: ログ形式（json または csv）。
            metrics_logger: メトリクスロガー。
        """
        self.log_dir = log_dir
        self.failed_dir = os.path.join(log_dir, "failed_compression")
        os.makedirs(self.log_dir, exist_ok=True, mode=0o700)
        os.makedirs(self.failed_dir, exist_ok=True, mode=0o700)
        self.buffer = []
        self.retry_queue = []
        self.compression_queue = queue.PriorityQueue()
        self.lock = threading.Lock()
        self.db_lock = threading.Lock()
        self.rollover_interval_sec = rollover_interval
        self.buffer_max_size = buffer_max_size
        self.max_retries = max_retries
        self.compress_on_rollover = compress_on_rollover
        self.use_async_io = use_async_io and not is_windows()
        self.log_format = log_format
        self.metrics_logger = metrics_logger or MetricsLogger(log_dir)
        self.current_log_filename = self._get_log_filename()
        self.file_counter = 0
        self.header_written = {}
        self.stop_event = threading.Event()
        self.log_async_queue = None
        self.cert_async_queue = None
        self.async_loop = None
        if self.use_async_io:
            self._start_async_loop()
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.compression_thread = threading.Thread(target=self._compression_worker, daemon=True)
        self.worker_thread.start()
        self.compression_thread.start()

    def _get_log_filename(self) -> str:
        """一意なログファイル名を生成。"""
        now = datetime.now()
        ext = ".json" if self.log_format == "json" else ".csv"
        base_name = f"tls_log_{now.strftime('%Y%m%d_%H%M%S')}_{self.file_counter:03d}{ext}}"
        self.file_counter += 1
        return os.path.join(self.log_dir, base_name)

    def _start_async_loop(self):
        """非同期I/O用のイベントループを開始。"""
        self.log_async_queue = asyncio.Queue()
        self.cert_async_queue = asyncio.Queue()

        async def handle_tasks(self):
            while not self.stop_event.is_set():
                try:
                    if not self.log_async_queue.empty():
                        filename, logs = await self.log_async_queue.get()
                        await self._async_write_logs(filename, logs)
                    elif not self.cert_async_queue.empty():
                        filename, pem_bytes = await self.cert_async_queue.get()
                        await self._async_write_cert(filename, pem_bytes)
                    else:
                        await asyncio.sleep(0.1)
                except Exception as e:
                    ctx.log.error(f"Async loop error: {e}")
                if self.stop_event.is_set():
                    break

        def run_loop(self):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.async_loop = loop
            try:
                loop.run_until_complete(handle_tasks(self))
            finally:
                loop.close()

        self.async_thread = threading.Thread(target=lambda: run_loop(self), daemon=True)
        self.async_thread.start()

    async def _async_write_logs(self, filename: str, logs: list) -> None:
        """非同期でログを書き込み。"""
        async with aiofiles.open(filename, "a") as f:
            if self.log_format == "json":
                for entry in logs:
                    await f.write(json.dumps(entry, indent=None, sort_keys=True) + '\n')
            else:  # csv
                if filename not in self.header_written:
                    await f.write(','.join(self.FIELD_ORDER) + '\n')
                    self.header_written[filename] = True
                for entry in logs:
                    row = ','.join(escape_csv_field(entry.get(k, '')) for k in self.FIELD_ORDER)
                    await f.write(row + '\n')

    async def _async_write_cert(self, filename: str, pem_bytes: bytes) -> None:
        """非同期で証明書を書き込み。"""
        fd = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            self.cert_file_permissions if hasattr(self, 'cert_file_permissions') else (0o600 if not is_windows() else 0o666)
        )
        async with aiofiles.open(fd, "wb") as f:
            await f.write(pem_bytes)

    def _adjust_buffer_size(self):
        """メモリ使用量に基づいてバッファサイズを調整。"""
        with self.lock:
            available_mem = get_available_memory_mb()
            if available_mem < self.MEMORY_THRESHOLD_MB:
                self.buffer_max_size = max(self.MIN_BUFFER_SIZE, self.buffer_max_size // 2)
            elif available_mem > 2 * self.MEMORY_THRESHOLD_MB:
                self.buffer_max_size = min(self.MAX_BUFFER_SIZE, self.buffer_max_size * 2)
            self.metrics_logger.log_metric("buffer_size", self.buffer_max_size)

    def log(self, log_entry: dict) -> None:
        """ログエントリをバッファに追加。

        Args:
            log_entry: ログエントリ（辞書形式）。
        """
        with self.lock:
            self.buffer.append(log_entry)
            self._adjust_buffer_size()
            if len(self.buffer) >= self.buffer_max_size:
                ctx.log.debug(f"Buffer reached max size ({self.buffer_max_size}). Flushing...")
                self._force_flush_all()

    def _worker(self):
        """ログフラッシュとローテーションを処理。"""
        last_rollover_time = time.time()
        last_flush_time = time.time()

        while not self.stop_event.is_set():
            self.stop_event.wait(timeout=1)
            now = time.time()
            self._adjust_buffer_size()

            if (now - last_rollover_time >= self.rollover_interval_sec and (self.buffer or self.retry_queue)) or self.retry_queue:
                ctx.log.debug("Initiating flush due to rollover or retry queue.")
                old_filename = self.current_log_filename
                self._force_flush_all()
                self.current_log_filename = self._get_log_filename()
                self.header_written.pop(old_filename, None)
                last_rollover_time = now
                if self.compress_on_rollover and os.path.exists(old_filename):
                    self.compression_queue.put((os.path.getmtime(old_filename), old_filename, 0))  # retry_count=0

            if now - last_flush_time >= 10:
                self.metrics_logger.log_metric("buffer_length", len(self.buffer))
                self.metrics_logger.log_metric("retry_queue_length", len(self.retry_queue))
                last_flush_time = now

            self._process_retry_queue()

        ctx.log.info("Flushing remaining logs...")
        self._force_flush_all()
        self._process_retry_queue(final_attempt=True)
        ctx.log.info("BufferedLogWriter worker stopped.")

    def _compression_worker(self):
        """圧縮を処理（リトライ制限付き）。"""
        MAX_COMPRESSION_RETRIES = 3
        while not self.stop_event.is_set():
            try:
                mtime, filename, retry_count = self.compression_queue.get(timeout=1)
                if os.path.exists(filename) and os.path.getmtime(filename) != mtime:
                    ctx.log.warn(f"Skipping compression for modified file: {filename}")
                    continue
                try:
                    with open(filename, 'rb') as f_in:
                        with gzip.open(filename + '.gz', 'wb') as f_out:
                            f_out.writelines(f_in)
                    os.remove(filename)
                    ctx.log.info(f"Compressed {filename}")
                    self.metrics_logger.log_metric("compressed_files", 1)
                except Exception as e:
                    ctx.log.error(f"Error compressing {filename}: {e}")
                    if retry_count < MAX_COMPRESSION_RETRIES:
                        self.compression_queue.put((mtime, filename, retry_count + 1))
                    else:
                        failed_path = os.path.join(self.failed_dir, os.path.basename(filename))
                        shutil.move(filename, failed_path)
                        ctx.log.error(f"Moved {filename} to {failed_path} after max retries")
                        self.metrics_logger.log_compression_failure(filename)
            except queue.Empty:
                continue

    def _force_flush_logs(self):
        """ログバッファをフラッシュ。"""
        with self.lock:
            if not self.buffer:
                return
            logs_to_write = list(self.buffer)
            self.buffer.clear()

            try:
                os.makedirs(os.path.dirname(self.current_log_filename), exist_ok=True, mode=0o700)
                if self.use_async_io:
                    self.async_loop.call_soon_threadsafe(self.log_async_queue.put_nowait, (self.current_log_filename, logs_to_write))
                else:
                    with open(self.current_log_filename, "a") as f:
                        if self.log_format == "json":
                            for entry in logs_to_write:
                                json.dump(entry, f, indent=None, sort_keys=True)
                                f.write("\n")
                        else:  # csv
                            if self.current_log_filename not in self.header_written:
                                f.write(','.join(self.FIELD_ORDER) + '\n')
                                self.header_written[self.current_log_filename] = True
                            for entry in logs_to_write:
                                row = ','.join(escape_csv_field(entry.get(k, '')) for k in self.FIELD_ORDER)
                                f.write(row + '\n')
                ctx.log.info(f"Flushed {len(logs_to_write)} logs to {self.current_log_filename}")
                self.metrics_logger.log_metric("flushed_logs", len(logs_to_write))
                for entry in logs_to_write:
                    if entry.get('retries', 0) > 0:
                        self.metrics_logger.log_retry_attempt(entry['retries'], success=True)
            except (OSError, IOError) as e:
                ctx.log.error(f"Error writing logs: {e}")
                self.metrics_logger.log_metric("log_write_errors", 1)
                for entry in logs_to_write:
                    entry['retries'] = entry.get('retries', 0) + 1
                    self.retry_queue.append(entry)

    def _force_flush_all(self):
        """ログと証明書をすべてフラッシュ（子クラスでオーバーライド）。"""
        self._force_flush_logs()

    def _process_retry_queue(self, final_attempt: bool = False):
        """リトライキューを処理。

        Args:
            final_attempt: 最後の試行かどうか。
        """
        with self.lock:
            if not self.retry_queue:
                return
            logs_to_reprocess = self.retry_queue
            self.retry_queue = []

            for log_entry in logs_to_reprocess:
                current_retries = log_entry.get('retries', 0)
                if final_attempt or current_retries < self.max_retries:
                    time.sleep(self.BACKOFF_INITIAL_MS / 1000 * (2 ** current_retries))
                    log_entry['retries'] = current_retries + 1
                    self.buffer.append(log_entry)
                    self.metrics_logger.log_retry_attempt(current_retries)
                else:
                    ctx.log.error(f"Max retries ({self.max_retries}) exceeded for log: {log_entry}")
                    self.metrics_logger.log_metric("discarded_logs", 1)

    def stop(self):
        """ワーカーと非同期ループを停止。"""
        ctx.log.info("Stopping BufferedLogWriter...")
        self.stop_event.set()
        self.worker_thread.join(timeout=5)
        self.compression_thread.join(timeout=5)
        if self.use_async_io and self.async_loop:
            self.async_loop.call_soon_threadsafe(self.async_loop.stop)
            self.async_thread.join(timeout=5)
        if self.worker_thread.is_alive() or self.compression_thread.is_alive():
            ctx.log.warn("Workers did not terminate gracefully.")
        self.metrics_logger.stop()

# --- 証明書保存機能付きのバッファリングロガー ---

class BufferedLogWriterWithCerts(BufferedLogWriter):
    DB_NAME = "saved_certs.db"
    DB_CLEANUP_INTERVAL = 3600
    MAX_SAVED_CERTS = 10000

    def __init__(
        self,
        *args,
        cert_file_permissions: int = 0o600,
        cert_buffer_max_size: int = DEFAULT_CERT_BUFFER_MAX_SIZE,
        persist_certs_db: bool = True,
        cert_expiry_check: bool = True,
        **kwargs
    ):
        """証明書付きバッファリングロガーを初期化。

        Args:
            cert_file_permissions: 証明書ファイルのパーミッション。
            cert_buffer_max_size: 証明書バッファの最大サイズ。
            persist_certs_db: 証明書をDBに永続化するか。
            cert_expiry_check: 証明書の有効期限をチェックするか。
            *args, **kwargs: 親クラスの引数。
        """
        super().__init__(*args, **kwargs)
        self.cert_queue = []
        self.cert_retry_queue = []
        self.cert_buffer_max_size = cert_buffer_max_size
        self.cert_file_permissions = cert_file_permissions
        self.persist_certs_db = persist_certs_db
        self.cert_expiry_check = cert_expiry_check
        self.saved_cert_files = set()
        self.conn = None
        self.last_db_cleanup = time.time()
        if self.persist_certs_db:
            self._init_db()

    def _init_db(self):
        """SQLiteデータベースを初期化。"""
        db_path = os.path.join(self.log_dir, self.DB_NAME)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute("PRAGMA journal_mode=WAL")
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS saved_certs (
                filename TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                saved_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
        self._reload_saved_certs()

    def _reload_saved_certs(self):
        """DBから証明書セットを再ロード。"""
        with self.db_lock:
            self.saved_cert_files.clear()
            try:
                for row in self.cursor.execute("SELECT filename FROM saved_certs"):
                    self.saved_cert_files.add(row[0])
                if len(self.saved_cert_files) > self.MAX_SAVED_CERTS:
                    self.saved_cert_files = set(list(self.saved_cert_files)[:self.MAX_SAVED_CERTS])
                ctx.log.info(f"Reloaded {len(self.saved_cert_files)} certificates from DB.")
            except sqlite3.Error as e:
                ctx.log.error(f"Error reloading saved certs: {e}")
                self.metrics_logger.log_metric("db_reload_errors", 1)

    def _cleanup_db(self):
        """古い証明書レコードを削除。"""
        if not self.persist_certs_db:
            return
        with self.db_lock:
            try:
                self.cursor.execute("DELETE FROM saved_certs WHERE saved_at < datetime('now', '-30 days')")
                deleted = self.cursor.rowcount
                self.conn.commit()
                if deleted > 0:
                    ctx.log.info(f"Cleaned up {deleted} certificate records from DB.")
                    self.metrics_logger.log_metric("db_cleanup_records", deleted)
                self._reload_saved_certs()
            except sqlite3.Error as e:
                ctx.log.error(f"Error cleaning up DB: {e}")
                self.metrics_logger.log_metric("db_cleanup_errors", 1)

    def log_cert(self, cert_info: dict) -> None:
        """証明書情報をキューに追加。

        Args:
            cert_info: 証明書情報（辞書形式）。
        """
        with self.lock:
            if self.cert_expiry_check:
                try:
                    cert = x509.load_pem_x509_certificate(cert_info['pem_bytes'], default_backend())
                    if cert.not_valid_after < datetime.utcnow():
                        ctx.log.warn(f"Skipping expired certificate: {cert_info['filename']}")
                        self.metrics_logger.log_metric("expired_certs", 1)
                        return
                except Exception as e:
                    ctx.log.error(f"Error validating certificate: {e}")
                    self.metrics_logger.log_metric("cert_validation_errors", 1)
            self.cert_queue.append(cert_info)
            self._adjust_buffer_size()
            if len(self.cert_queue) >= self.cert_buffer_max_size:
                ctx.log.debug(f"Cert buffer reached max size ({self.cert_buffer_max_size}). Flushing...")
                self._force_flush_all()

    def _flush_cert_queue(self):
        """証明書キューをフラッシュ。"""
        with self.lock:
            if not self.cert_queue:
                return
            certs_to_write = list(self.cert_queue)
            self.cert_queue.clear()

            with self.db_lock:
                for cert_info in certs_to_write:
                    cert_filename = cert_info['filename']
                    cert_pem_bytes = cert_info['pem_bytes']
                    cert_hash = cert_info['hash']
                    current_retries = cert_info.get('retries', 0)

                    if cert_filename not in self.saved_cert_files:
                        try:
                            os.makedirs(os.path.dirname(cert_filename), exist_ok=True, mode=0o700)
                            if not os.path.exists(cert_filename):
                                if self.use_async_io:
                                    self.async_loop.call_soon_threadsafe(
                                        self.cert_async_queue.put_nowait, (cert_filename, cert_pem_bytes)
                                    )
                                else:
                                    fd = os.open(
                                        cert_filename,
                                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                        self.cert_file_permissions if not is_windows() else 0o666
                                    )
                                    with os.fdopen(fd, "wb") as fcert:
                                        fcert.write(cert_pem_bytes)
                                if not is_windows():
                                    os.chmod(cert_filename, self.cert_file_permissions)
                                    ctx.log.debug(f"Set permissions {oct(self.cert_file_permissions)} for {cert_filename}")
                                if self.persist_certs_db:
                                    try:
                                        self.cursor.execute(
                                            "INSERT INTO saved_certs (filename, hash) VALUES (?, ?)",
                                            (cert_filename, cert_hash)
                                        )
                                        self.conn.commit()
                                    except sqlite3.IntegrityError:
                                        ctx.log.debug(f"Certificate {cert_filename} already in DB.")
                                self.saved_cert_files.add(cert_filename)
                                ctx.log.info(f"Saved certificate: {cert_filename}")
                                self.metrics_logger.log_metric("saved_certs", 1)
                                if current_retries > 0:
                                    self.metrics_logger.log_retry_attempt(current_retries, success=True, is_cert=True)
                            else:
                                if self.persist_certs_db:
                                    try:
                                        self.cursor.execute(
                                            "INSERT INTO saved_certs (filename, hash) VALUES (?, ?)",
                                            (cert_filename, cert_hash)
                                        )
                                        self.conn.commit()
                                    except sqlite3.IntegrityError:
                                        ctx.log.debug(f"Certificate {cert_filename} already in DB.")
                                self.saved_cert_files.add(cert_filename)
                        except (OSError, IOError) as e:
                            ctx.log.error(f"Error saving certificate {cert_filename}: {e}")
                            self.metrics_logger.log_metric("cert_write_errors", 1)
                            cert_info['retries'] = current_retries + 1
                            self.cert_retry_queue.append(cert_info)
                            self.metrics_logger.log_retry_attempt(current_retries, is_cert=True)

    def _process_cert_retry_queue(self, final_attempt: bool = False):
        """証明書リトライキューを処理。

        Args:
            final_attempt: 最後の試行かどうか。
        """
        with self.lock:
            if not self.cert_retry_queue:
                return
            certs_to_reprocess = self.cert_retry_queue
            self.cert_retry_queue = []

            with self.db_lock:
                for cert_info in certs_to_reprocess:
                    current_retries = cert_info.get('retries', 0)
                    if final_attempt or current_retries < self.max_retries:
                        time.sleep(self.BACKOFF_INITIAL_MS / 1000 * (2 ** current_retries))
                        cert_info['retries'] = current_retries + 1
                        self.cert_queue.append(cert_info)
                        self.metrics_logger.log_retry_attempt(current_retries, is_cert=True)
                    else:
                        ctx.log.error(f"Max retries ({self.max_retries}) exceeded for cert: {cert_info}")
                        self.metrics_logger.log_metric("discarded_certs", 1)

    def _force_flush_all(self):
        """ログと証明書をすべてフラッシュ。"""
        self._force_flush_logs()
        self._flush_cert_queue()
        self._process_cert_retry_queue()

        if self.persist_certs_db and time.time() - self.last_db_cleanup >= self.DB_CLEANUP_INTERVAL:
            self._cleanup_db()
            self.last_db_cleanup = time.time()

    def stop(self):
        """ワーカーとDB接続を停止。"""
        ctx.log.info("Stopping BufferedLogWriterWithCerts...")
        self._force_flush_all()
        self._process_cert_retry_queue(final_attempt=True)
        super().stop()
        if self.persist_certs_db and self.conn:
            try:
                self.conn.close()
                ctx.log.info("SQLite DB closed.")
            except sqlite3.Error as e:
                ctx.log.error(f"Error closing DB: {e}")
                self.metrics_logger.log_metric("db_close_errors", 1)

# --- mitmproxy アドオン本体 ---

class MyTLSAnalyzer:
    def __init__(self):
        """TLSアナライザーを初期化。"""
        self.metrics_logger = MetricsLogger("tls_logs")
        self.file_counter = 0
        self.lock = threading.Lock()
        self.log_writer = BufferedLogWriterWithCerts(
            log_dir="tls_logs",
            rollover_interval_sec=DEFAULT_ROLLOVER_INTERVAL_SEC,
            buffer_max_size=DEFAULT_BUFFER_MAX_SIZE,
            max_retries=DEFAULT_MAX_RETRIES,
            compress_on_rollover=True,
            use_async_io=not is_windows(),
            log_format="json",
            cert_file_permissions=0o600,
            cert_buffer_max_size=DEFAULT_CERT_BUFFER_MAX_SIZE,
            persist_certs_db=True,
            cert_expiry_check=True,
            metrics_logger=self.metrics_logger
        )
        ctx.log.info(f"TLS logs in {self.log_writer.log_dir}/tls_log_*.json(.gz)")
        ctx.log.info(f"Certificates in {self.log_writer.log_dir}/cert_*.pem")
        ctx.log.info(f"Metrics in {self.log_writer.log_dir}/metrics.log")

    def done(self):
        """アドオンを終了。"""
        ctx.log.info("Shutting down MyTLSAnalyzer...")
        self.log_writer.stop()
        self.metrics_logger.stop()
        ctx.log.info("MyTLSAnalyzer done.")

    def tls_established(self, flow: tls.TlsFlow):
        """TLSハンドシェイクを処理。

        Args:
            flow: TLSフローデータ。
        """
        common_name = "N/A"
        issuer_common_name = "N/A"
        certs_to_save_data = []

        if flow.server_conn.peer_certs:
            cert = flow.server_conn.peer_certs[0]
            try:
                subject_cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                common_name = subject_cn_attributes[0].value if subject_cn_attributes else "N/A"
                issuer_cn_attributes = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                issuer_common_name = issuer_cn_attributes[0].value if issuer_cn_attributes else "N/A"
            except Exception as e:
                ctx.log.error(f"Error parsing certificate: {e}")
                self.metrics_logger.log_metric("cert_parse_errors", 1)

            if common_name == "N/A":
                common_name = (
                    flow.client_hello.sni
                    if hasattr(flow, 'client_hello') and flow.client_hello.sni
                    else flow.server_conn.peername[0]
                )

            if common_name != "N/A":
                leaf_cert_hash = hashlib.sha256(cert.public_bytes(tls.x509.Encoding.DER)).hexdigest()
                safe_common_name_prefix = sanitize_filename(common_name, max_length=100)
                with self.lock:
                    file_counter = self.file_counter
                    self.file_counter += 1
                for i, current_cert in enumerate(flow.server_conn.peer_certs):
                    current_cert_hash = hashlib.sha256(current_cert.public_bytes(tls.x509.Encoding.DER)).hexdigest()
                    cert_filepath = os.path.join(
                        self.log_writer.log_dir,
                        f"cert_{safe_common_name_prefix}_chain{i:02d}_{current_cert_hash[:16]}_{file_counter:03d}.pem"
                    )
                    certs_to_save_data.append({
                        'filename': cert_filepath,
                        'pem_bytes': current_cert.public_bytes(tls.x509.Encoding.PEM),
                        'hash': current_cert_hash
                    })

        if flow.tls_version in ["TLSv1.2", "TLSv1.3"]:
            log_entry = {
                "timestamp": flow.timestamp_start,
                "log_time_utc": datetime.utcfromtimestamp(flow.timestamp_start).isoformat() + "Z",
                "client_ip": flow.client_conn.peername[0],
                "client_port": flow.client_conn.peername[1],
                "server_ip": flow.server_conn.peername[0],
                "server_port": flow.server_conn.peername[1],
                "tls_version": flow.tls_version,
                "cipher_suite": flow.cipher,
                "server_common_name": common_name,
                "issuer_common_name": issuer_common_name,
                "handshake_time_ms": float(flow.tls_handshake_end - flow.tls_handshake_start) * 1000,
                "sni": flow.client_hello.sni if hasattr(flow, 'client_hello') and flow.client_hello else None,
                "tls_extensions": (
                    [str(ext) for ext in flow.client_hello.extensions]
                    if hasattr(flow, 'client_hello') and hasattr(flow.client_hello, 'extensions')
                    else None
                )
            }
            self.log_writer.log(log_entry)
            ctx.log.debug(f"Queued {flow.tls_version} session for {flow.server_conn.peername}")
            for cert_data in certs_to_save_data:
                self.log_writer.log_cert(cert_data)
        else:
            ctx.log.debug(f"Non-TLSv1.2/1.3 session: {flow.tls_version}")

# --- テストコード ---

class TestBufferedLogWriterWithCerts(unittest.TestCase):
    def setUp(self):
        self.log_dir = "test_tls_logs"
        self.metrics_logger = MetricsLogger(self.log_dir)
        self.writer = BufferedLogWriterWithCerts(
            log_dir=self.log_dir,
            rollover_interval_sec=300,
            buffer_max_size=10,
            max_retries=2,
            compress_on_rollover=False,
            use_async_io=False,
            log_format="json",
            cert_buffer_max_size=10,
            persist_certs_db=True,
            cert_file_permissions=0o600,
            metrics_logger=self.metrics_logger
        )

    def test_sanitize_filename(self):
        """sanitize_filenameのエッジケースをテスト。"""
        test_cases = [
            ("__test__.pem", "_test_.pem"),
            ("test..pem", "test_.pem"),
            (".", "invalid_.pem"),
            ("", "unknown"),
            ("test<>\\/.pem", "test_.pem"),
            ("a" * 200 + ".pem", "a" * 146 + ".pem"),
        ]
        for input_name, expected in test_cases:
            with self.subTest(input_name=input_name):
                self.assertEqual(sanitize_filename(input_name, max_length=150), expected)

    @patch('os.open')
    @patch('os.fdopen')
    @patch('sqlite3.connect')
    def test_log_and_cert_flush(self, mock_connect, mock_fdopen, mock_open):
        """ログと証明書のフラッシュをテスト。"""
        entry = {"timestamp": 123, "log_time_utc": "test"}
        cert_info = {
            "filename": f"{self.log_dir}/cert_test.pem",
            "pem_bytes": b"test_pem",
            "hash": "test_hash"
        }
        self.writer.log(entry)
        self.writer.log_cert(cert_info)
        self.writer._force_flush_all()
        self.assertFalse(self.writer.buffer)
        self.assertFalse(self.writer.cert_queue)
        self.assertTrue(os.path.exists(self.writer.current_log_filename))

    @patch('os.path.exists', return_value=False)
    @patch('os.open')
    @patch('os.fdopen')
    def test_retry_cert_queue(self, mock_fdopen, mock_open, mock_exists):
        """証明書リトライキューの処理をテスト。"""
        cert_info = {
            "filename": f"{self.log_dir}/cert_test.pem",
            "pem_bytes": b"test_pem",
            "hash": "test_hash",
            "retries": 0
        }
        self.writer.cert_retry_queue.append(cert_info)
        with patch('os.fdopen', side_effect=IOError("Test error")):
            self.writer._flush_cert_queue()
        self.assertTrue(cert_info in self.writer.cert_retry_queue)
        self.assertEqual(self.writer.cert_retry_queue[0]['retries'], 1)
        self.writer._process_cert_retry_queue()
        self.assertTrue(cert_info in self.writer.cert_queue)
        self.assertEqual(self.writer.cert_queue[0]['retries'], 2)

    def test_csv_no_header_duplication(self):
        """CSVヘッダーの重複防止をテスト。"""
        self.writer.log_format = "csv"
        entry = {k: "test" for k in self.writer.FIELD_ORDER}
        self.writer.log(entry)
        self.writer._force_flush_all()
        self.writer.log(entry)
        self.writer._force_flush_all()
        with open(self.writer.current_log_filename) as f:
            lines = f.readlines()
        self.assertEqual(len([l for l in lines if l.strip() == ','.join(self.writer.FIELD_ORDER)]), 1)

    @patch('os.path.exists', return_value=True)
    @patch('os.remove')
    @patch('gzip.open')
    def test_compression_retry(self, mock_gzip, mock_remove, mock_exists):
        """圧縮リトライと失敗処理をテスト。"""
        filename = f"{self.log_dir}/test.json"
        with open(filename, "w") as f:
            f.write("test")
        self.writer.compression_queue.put((os.path.getmtime(filename), filename, 0))
        with patch('gzip.open', side_effect=IOError("Test error")):
            self.writer._compression_worker()
        self.assertFalse(self.writer.compression_queue.empty())

    @patch('sqlite3.connect')
    def test_saved_certs_memory(self, mock_connect):
        """証明書セットのメモリ制限をテスト。"""
        mock_connect.return_value.cursor.return_value.execute.return_value.fetchall.return_value = [("cert1.pem",), ("cert2.pem",)]
        self.writer._reload_saved_certs()
        self.assertEqual(len(self.writer.saved_cert_files), 2)
        for i in range(self.writer.MAX_SAVED_CERTS + 10):
            self.writer.saved_cert_files.add(f"cert_{i}.pem")
        self.writer._reload_saved_certs()
        self.assertLessEqual(len(self.writer.saved_cert_files), self.writer.MAX_SAVED_CERTS)

    @patch('os.open')
    @patch('os.fdopen')
    @patch('sqlite3.connect')
    def test_cert_file_permissions(self, mock_connect, mock_fdopen, mock_open):
        """証明書ファイルのパーミッション一貫性をテスト。"""
        cert_info = {
            "filename": f"{self.log_dir}/cert_test.pem",
            "pem_bytes": b"test_pem",
            "hash": "test_hash"
        }
        self.writer.cert_file_permissions = 0o640
        self.writer.log_cert(cert_info)
        self.writer._flush_cert_queue()
        mock_open.assert_called_with(
            cert_info['filename'],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o640 if not is_windows() else 0o666
        )

    def test_rollover_interval_sec_type(self):
        """rollover_interval_secの型をテスト。"""
        with self.assertRaises(TypeError):
            BufferedLogWriterWithCerts(log_dir=self.log_dir, rollover_interval_sec="300")

    @patch('cryptography.x509.load_pem_x509_certificate')
    def test_tls_established_issuer_common_name(self, mock_load_cert):
        """issuer_common_nameの取得をテスト。"""
        mock_cert = Mock()
        mock_cert.subject.get_attributes_for_oid.return_value = [Mock(value="test_subject")]
        mock_cert.issuer.get_attributes_for_oid.return_value = [Mock(value="test_issuer")]
        mock_load_cert.return_value = mock_cert
        flow = Mock()
        flow.server_conn.peer_certs = [mock_cert]
        flow.tls_version = "TLSv1.3"
        flow.timestamp_start = 1234567890
        flow.client_conn.peername = ("192.168.1.1", 12345)
        flow.server_conn.peername = ("93.184.216.34", 443)
        flow.cipher = "TLS_AES_256_GCM_SHA384"
        flow.tls_handshake_end = 1234567890.025
        flow.tls_handshake_start = 1234567890.0
        analyzer = MyTLSAnalyzer()
        analyzer.tls_established(flow)
        analyzer.log_writer.stop()

    def test_retry_attempt_counting(self):
        """log_retry_attemptのカウントをテスト。"""
        self.metrics_logger.log_retry_attempt(1)
        self.metrics_logger.log_retry_attempt(1)
        self.metrics_logger.log_retry_attempt(2, success=True)
        self.assertEqual(self.metrics_logger.retry_counts.get(1), 2)
        self.assertEqual(self.metrics_logger.successful_retries, 1)

    def tearDown(self):
        self.writer.stop()
        if os.path.exists(self.log_dir):
            shutil.rmtree(self.log_dir)

if __name__ == "__main__":
    unittest.main(argv=[''], exit=False)

# --- mitmproxyアドオンとして登録 ---
addons = [MyTLSAnalyzer()]
