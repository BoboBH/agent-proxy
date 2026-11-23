"""三层滚动日志（全局规范）：按天 + 单文件 50MB 立即滚动 + 保留 7 天 + 后缀精确到秒。

同一日志文件全局仅一个滚动 handler（模块级注册表保证）。
trace logger 经 QueueHandler+QueueListener 异步落盘（不阻塞事件循环）。
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import queue
import re
import threading
from datetime import datetime, timedelta

MAX_BYTES = 50 * 1024 * 1024
KEEP_DAYS = 7

_registry: dict[str, "DailySizeRotatingHandler"] = {}
_trace_queue: queue.Queue | None = None
_trace_listener: logging.handlers.QueueListener | None = None
_lock = threading.Lock()


class DailySizeRotatingHandler(logging.Handler):
    """按天 + 大小双触发滚动；文件名 <base>.YYYYmmdd_HHMMSS（同秒重复滚动追加 .N 序号）；按 mtime 清理过期。"""

    def __init__(self, base_path: str, max_bytes: int = MAX_BYTES, keep_days: int = KEEP_DAYS):
        super().__init__()
        self.base_path = base_path
        self.max_bytes = max_bytes
        self.keep_days = keep_days
        self._current_day = self._today()
        self._stream = None
        self._last_suffix: str | None = None
        self._seq = 0
        os.makedirs(os.path.dirname(base_path) or ".", exist_ok=True)
        self._open_new()

    def _today(self) -> str:
        return datetime.now().strftime("%Y%m%d")

    def _open_new(self) -> None:
        self._close_stream()
        suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
        if suffix == self._last_suffix:
            # 同一秒内再次滚动（如大小触发）时追加序号，避免同名 append 不分文件
            self._seq += 1
            path = f"{self.base_path}.{suffix}.{self._seq}"
        else:
            self._seq = 0
            path = f"{self.base_path}.{suffix}"
        self._last_suffix = suffix
        self._stream = open(path, "a", encoding="utf-8")
        self._current_day = self._today()
        self._cleanup()

    def _close_stream(self) -> None:
        if self._stream:
            try:
                self._stream.flush()
                self._stream.close()
            finally:
                self._stream = None

    def _should_rotate(self) -> bool:
        if self._stream is None or self._today() != self._current_day:
            return True
        try:
            return self._stream.tell() >= self.max_bytes
        except (OSError, ValueError):
            return True

    def _cleanup(self) -> None:
        cutoff = datetime.now() - timedelta(days=self.keep_days)
        base = os.path.basename(self.base_path)
        directory = os.path.dirname(self.base_path) or "."
        pattern = re.compile(rf"^{re.escape(base)}\.\d{{8}}_\d{{6}}(?:\.\d+)?$")
        try:
            for name in os.listdir(directory):
                if not pattern.match(name):
                    continue
                full = os.path.join(directory, name)
                try:
                    if datetime.fromtimestamp(os.path.getmtime(full)) < cutoff:
                        os.remove(full)
                except OSError:
                    pass
        except OSError:
            pass

    def emit(self, record: logging.LogRecord) -> None:
        if self._should_rotate():
            self._open_new()
        self._stream.write(self.format(record) + "\n")
        self._stream.flush()

    def close(self) -> None:
        self._close_stream()
        super().close()


def _get_file_handler(path: str) -> DailySizeRotatingHandler:
    with _lock:
        handler = _registry.get(path)
        if handler is None:
            handler = DailySizeRotatingHandler(path)
            _registry[path] = handler
        return handler


def _get_trace_queue_handler(path: str) -> logging.handlers.QueueHandler:
    """trace 日志走内存队列 + 后台线程落盘（异步不阻塞）。"""
    global _trace_queue, _trace_listener
    file_handler = _get_file_handler(path)
    if _trace_queue is None:
        _trace_queue = queue.Queue(-1)
        _trace_listener = logging.handlers.QueueListener(
            _trace_queue, file_handler, respect_handler_level=False
        )
        _trace_listener.start()
    return logging.handlers.QueueHandler(_trace_queue)


def flush_trace() -> None:
    """同步排空 trace 队列（测试与停机前调用）。"""
    if _trace_queue is None or _trace_listener is None:
        return
    while True:
        try:
            _trace_listener.handle(_trace_queue.get_nowait())
        except queue.Empty:
            break


def shutdown_logging() -> None:
    flush_trace()
    if _trace_listener is not None:
        _trace_listener.stop()


def setup_logging(log_dir: str, level: str = "INFO") -> None:
    """装配运行 / 审计 / 追踪三个文件的滚动 handler（幂等）。"""
    os.makedirs(log_dir, exist_ok=True)
    root = logging.getLogger("agent_proxy")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    if not root.handlers:
        handler = _get_file_handler(os.path.join(log_dir, "agent-proxy.log"))
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        root.addHandler(handler)

    audit = logging.getLogger("agent_proxy.audit")
    audit.setLevel(logging.INFO)
    audit.propagate = False
    if not audit.handlers:
        audit.addHandler(_get_file_handler(os.path.join(log_dir, "audit.log")))

    trace = logging.getLogger("agent_proxy.trace")
    trace.setLevel(logging.INFO)
    trace.propagate = False
    if not trace.handlers:
        trace.addHandler(_get_trace_queue_handler(os.path.join(log_dir, "trace.log")))
