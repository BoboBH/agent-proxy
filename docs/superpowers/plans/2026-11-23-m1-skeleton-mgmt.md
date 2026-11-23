# M1 实施计划：骨架 + 配置/日志/追踪 + 身份 stub + 管理接口 + MySQL/Redis + /metrics

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 agent-proxy M1：可注册/查询/更新/删除映射（返回代理地址+占位符 header）的服务骨架，含三层滚动日志、追踪日志框架、TokenVerifier stub、Prometheus 基础埋点与健康检查。

**Architecture:** 分层 `api(接口) → services(应用服务: CRUD/cache-aside/归属校验) → forward(M2+) → db/cache/auth(基础设施)`。FastAPI + SQLAlchemy(async) + aiomysql + redis-py(<5)。测试走真实 MySQL 测试库 `agent_proxy_test` + Redis db9，httpx ASGITransport 全链路。

**Tech Stack:** Python 3.12（venv `.venv`）、FastAPI、SQLAlchemy 2 async、aiomysql、redis 4.6、prometheus-client、pytest + pytest-asyncio（asyncio_mode=auto）。

**对应设计文档:** §5 数据模型、§6.1/6.2/6.3/6.4 API、§7 鉴权、§9 安全、§10 错误、§11 日志、§12 结构、§16 M1 验收。

**范围说明:** 本计划只覆盖 M1；M2–M7 在各里程碑启动时单独出计划（各自产出可运行可验收的软件）。

**约定:** 测试令牌 `stub.<base64url(payload)>.sig`（StubVerifier 只解码中间段），payload 含 `user_id`(必须)/`user_name`/`role`。测试库 `agent_proxy_test`、Redis db9、`SSRF_ALLOW_PRIVATE=true`、`EXTERNAL_BASE=http://testserver`。

---

### Task 1: 项目脚手架与冒烟测试

**Files:**
- Create: `pyproject.toml`
- Create: `src/agent_proxy/__init__.py`
- Create: `tests/unit/test_smoke.py`
- Modify: `.gitignore`

- [ ] **Step 1: 写 pyproject.toml**

```toml
[project]
name = "agent-proxy"
version = "0.1.0"
description = "MCP / HTTP egress proxy for the Agent platform"
requires-python = ">=3.12"
dependencies = [
  "fastapi>=0.165",
  "uvicorn[standard]>=0.54",
  "httpx>=0.28",
  "sqlalchemy[asyncio]>=2.1",
  "aiomysql>=0.3",
  "redis>=4.2,<5",
  "pyjwt>=2.15",
  "cryptography>=50",
  "prometheus-client>=0.26",
  "jinja2>=3.1",
  "pymysql>=1.2",
]

[project.optional-dependencies]
dev = ["pytest>=9", "pytest-asyncio>=1.5"]

[build-system]
requires = ["setuptools>=75"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
addopts = "-q"
pythonpath = ["src", "."]
```

- [ ] **Step 2: 建包与冒烟测试**

`src/agent_proxy/__init__.py`:

```python
"""agent-proxy：Agent 平台对外 MCP / HTTP 出站代理。"""

__version__ = "0.1.0"
```

`tests/__init__.py` / `tests/unit/__init__.py` / `tests/integration/__init__.py`: 均为空文件（使 tests 成为可导入包，支撑 `from tests.utils import ...`）。

`tests/unit/test_smoke.py`:

```python
def test_package_importable():
    import agent_proxy
    assert agent_proxy.__version__ == "0.1.0"
```

- [ ] **Step 3: .gitignore 覆盖测试日志目录**

确认 `.gitignore` 含 `logs*/`（开发与测试日志目录都不入库）。

- [ ] **Step 4: 运行冒烟测试**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_smoke.py -v`
Expected: PASS（pythonpath=["src"] 使 tests 直接 import）

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/agent_proxy/__init__.py tests/
git commit -m "chore(M1): 项目脚手架与冒烟测试"
```

---

### Task 2: 配置模块 config.py

**Files:**
- Create: `src/agent_proxy/config.py`
- Create: `tests/unit/test_config.py`

- [ ] **Step 1: 写失败测试**

`tests/unit/test_config.py`:

```python
import pytest

from agent_proxy.config import ConfigError, Settings

BASE = {
    "MYSQL_DSN": "mysql+aiomysql://root:123456@127.0.0.1:3306/agent_proxy",
    "REDIS_URL": "redis://127.0.0.1:6379/1",
}


def test_defaults():
    s = Settings.from_env(BASE)
    assert s.env == "dev" and s.token_verify_impl == "stub" and s.cache_ttl == 300
    assert s.max_body_size == 10 * 1024 * 1024 and s.trace_body_max_size == 64 * 1024
    assert s.trace_mode == "metadata" and s.upstream_max_redirects == 3


def test_parse_size_and_external_base_strip():
    s = Settings.from_env({**BASE, "MAX_BODY_SIZE": "5MB", "EXTERNAL_BASE": "http://x.com/"})
    assert s.max_body_size == 5 * 1024 * 1024
    assert s.external_base == "http://x.com"


def test_prod_rejects_stub():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "ENV": "prod"})


def test_missing_dsn_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"REDIS_URL": "redis://127.0.0.1:6379/1"})


def test_bad_trace_mode_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "TRACE_MODE": "loud"})


def test_encrypt_requires_master_key():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "ENCRYPT_AT_REST": "true"})
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_config.py -v`
Expected: FAIL（ModuleNotFoundError: agent_proxy.config）

- [ ] **Step 3: 实现 config.py**

```python
"""环境配置：Settings.from_env 纯函数读取；prod 禁止 stub 实现；.env 轻量加载。"""
from __future__ import annotations

import functools
import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _parse_size(text: str) -> int:
    t = text.strip().upper()
    for suffix, mult in {"KB": 1024, "MB": 1024**2, "GB": 1024**3}.items():
        if t.endswith(suffix):
            return int(float(t[: -len(suffix)]) * mult)
    return int(t)


@dataclass(frozen=True)
class Settings:
    listen: str = "0.0.0.0:8800"
    external_base: str = "http://127.0.0.1:8800"
    env: str = "dev"
    token_verify_impl: str = "stub"
    login_impl: str = "stub"
    admin_role: str = "admin"
    mysql_dsn: str = ""
    redis_url: str = ""
    cache_ttl: int = 300
    upstream_connect_timeout: float = 10.0
    upstream_read_timeout: float = 60.0
    upstream_max_redirects: int = 3
    upstream_max_connections: int = 200
    shutdown_drain_seconds: int = 10
    max_body_size: int = 10 * 1024 * 1024
    ssrf_allow_private: bool = False
    cors_allowed_origins: tuple[str, ...] = ()
    oauth_state_ttl: int = 600
    admin_session_ttl: int = 28800
    encrypt_at_rest: bool = False
    master_key: str = ""
    log_dir: str = "logs"
    log_level: str = "INFO"
    trace_mode: str = "metadata"
    trace_body_max_size: int = 64 * 1024

    @staticmethod
    def from_env(env: dict[str, str] | None = None) -> "Settings":
        e = dict(os.environ if env is None else env)
        s = Settings(
            listen=e.get("AGENT_PROXY_LISTEN", "0.0.0.0:8800"),
            external_base=e.get("EXTERNAL_BASE", "http://127.0.0.1:8800").rstrip("/"),
            env=e.get("ENV", "dev"),
            token_verify_impl=e.get("TOKEN_VERIFY_IMPL", "stub"),
            login_impl=e.get("LOGIN_IMPL", "stub"),
            admin_role=e.get("ADMIN_ROLE", "admin"),
            mysql_dsn=e.get("MYSQL_DSN", ""),
            redis_url=e.get("REDIS_URL", ""),
            cache_ttl=int(e.get("CACHE_TTL", "300")),
            upstream_connect_timeout=float(e.get("UPSTREAM_CONNECT_TIMEOUT", "10")),
            upstream_read_timeout=float(e.get("UPSTREAM_READ_TIMEOUT", "60")),
            upstream_max_redirects=int(e.get("UPSTREAM_MAX_REDIRECTS", "3")),
            upstream_max_connections=int(e.get("UPSTREAM_MAX_CONNECTIONS", "200")),
            shutdown_drain_seconds=int(e.get("SHUTDOWN_DRAIN_SECONDS", "10")),
            max_body_size=_parse_size(e.get("MAX_BODY_SIZE", "10MB")),
            ssrf_allow_private=e.get("SSRF_ALLOW_PRIVATE", "false").lower() == "true",
            cors_allowed_origins=tuple(
                x.strip() for x in e.get("CORS_ALLOWED_ORIGINS", "").split(",") if x.strip()
            ),
            oauth_state_ttl=int(e.get("OAUTH_STATE_TTL", "600")),
            admin_session_ttl=int(e.get("ADMIN_SESSION_TTL", "28800")),
            encrypt_at_rest=e.get("ENCRYPT_AT_REST", "false").lower() == "true",
            master_key=e.get("MASTER_KEY", ""),
            log_dir=e.get("LOG_DIR", "logs"),
            log_level=e.get("LOG_LEVEL", "INFO"),
            trace_mode=e.get("TRACE_MODE", "metadata"),
            trace_body_max_size=_parse_size(e.get("TRACE_BODY_MAX_SIZE", "64KB")),
        )
        s.validate()
        return s

    def validate(self) -> None:
        if self.env == "prod" and (self.token_verify_impl == "stub" or self.login_impl == "stub"):
            raise ConfigError("prod 环境禁止 stub 校验/登录实现启动")
        if self.trace_mode not in ("off", "metadata", "body"):
            raise ConfigError(f"非法 TRACE_MODE: {self.trace_mode}")
        if not self.mysql_dsn or not self.redis_url:
            raise ConfigError("缺少必需配置: MYSQL_DSN / REDIS_URL")
        if self.encrypt_at_rest and not self.master_key:
            raise ConfigError("ENCRYPT_AT_REST 开启时必须配置 MASTER_KEY")


def load_dotenv_file(path: str = ".env") -> None:
    """极简 .env 加载（KEY=VALUE，# 注释），不覆盖已有环境变量。"""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_config.py -v`
Expected: 6 PASS

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/config.py tests/unit/test_config.py
git commit -m "feat(M1): 配置模块 Settings.from_env（prod 禁 stub、大小解析、.env 加载）"
```

---

### Task 3: 三层滚动日志 logging_setup.py

**Files:**
- Create: `src/agent_proxy/logging_setup.py`
- Create: `tests/unit/test_logging_setup.py`

- [ ] **Step 1: 写失败测试**

`tests/unit/test_logging_setup.py`:

```python
import logging
import os
import time


def test_rotate_on_size(tmp_path):
    from agent_proxy.logging_setup import DailySizeRotatingHandler

    base = str(tmp_path / "t.log")
    handler = DailySizeRotatingHandler(base, max_bytes=100, keep_days=7)
    logger = logging.getLogger("rotate-test")
    logger.handlers = [handler]
    logger.propagate = False
    for _ in range(50):
        logger.info("x" * 20)
    files = list(tmp_path.glob("t.log.*"))
    assert len(files) >= 2, "超过 max_bytes 应已滚动出多个文件"
    handler.close()


def test_cleanup_expired_by_mtime(tmp_path):
    from agent_proxy.logging_setup import DailySizeRotatingHandler

    base = str(tmp_path / "t.log")
    handler = DailySizeRotatingHandler(base, max_bytes=10 * 1024 * 1024, keep_days=7)
    old = tmp_path / "t.log.20200101_000000"
    old.write_text("old", encoding="utf-8")
    past = time.time() - 8 * 86400
    os.utime(old, (past, past))
    handler._open_new()  # 触发一次清理
    assert not old.exists(), "超过保留期(7天)的旧文件应被删除"
    handler.close()


def test_setup_logging_creates_three_files(tmp_path):
    from agent_proxy.logging_setup import setup_logging

    setup_logging(str(tmp_path), "INFO")
    import agent_proxy.logging_setup as ls

    assert any("agent-proxy.log" in p for p in ls._registry)
    assert any("audit.log" in p for p in ls._registry)
    assert any("trace.log" in p for p in ls._registry)
    assert logging.getLogger("agent_proxy.audit").handlers
    assert logging.getLogger("agent_proxy.trace").handlers
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_logging_setup.py -v`
Expected: FAIL（ModuleNotFoundError: agent_proxy.logging_setup）

- [ ] **Step 3: 实现 logging_setup.py**

```python
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
    """按天 + 大小双触发滚动；文件名 <base>.YYYYmmdd_HHMMSS；按 mtime 清理过期。"""

    def __init__(self, base_path: str, max_bytes: int = MAX_BYTES, keep_days: int = KEEP_DAYS):
        super().__init__()
        self.base_path = base_path
        self.max_bytes = max_bytes
        self.keep_days = keep_days
        self._current_day = self._today()
        self._stream = None
        os.makedirs(os.path.dirname(base_path) or ".", exist_ok=True)
        self._open_new()

    def _today(self) -> str:
        return datetime.now().strftime("%Y%m%d")

    def _open_new(self) -> None:
        self._close_stream()
        path = f"{self.base_path}.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
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
        pattern = re.compile(rf"^{re.escape(base)}\.\d{{8}}_\d{{6}}$")
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
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_logging_setup.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/logging_setup.py tests/unit/test_logging_setup.py
git commit -m "feat(M1): 三层滚动日志（按天+50MB+7天保留+秒级后缀，trace 异步队列）"
```

---

### Task 4: 追踪日志 trace.py

**Files:**
- Create: `src/agent_proxy/trace.py`
- Create: `tests/unit/test_trace.py`

- [ ] **Step 1: 写失败测试**

`tests/unit/test_trace.py`:

```python
import json
import logging

from agent_proxy import trace
from agent_proxy.logging_setup import flush_trace


def _capture(tmp_path, mode, limit=100):
    handler = logging.FileHandler(tmp_path / "trace.log", encoding="utf-8")
    logger = logging.getLogger("agent_proxy.trace")
    logger.handlers = [handler]
    trace.configure(mode, limit)
    return tmp_path / "trace.log"


def _read(path):
    flush_trace()
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_off_mode_no_records(tmp_path):
    path = _capture(tmp_path, "off")
    trace.log_request("r1", "u1", "m1", "GET", "http://x", {"Authorization": "Bearer abc"})
    assert _read(path) == []


def test_metadata_mode_fingerprint_no_body(tmp_path):
    path = _capture(tmp_path, "metadata")
    trace.log_request("r1", "u1", "m1", "POST", "http://x/api",
                      {"X-API-Key": "sk-very-secret-key", "Content-Type": "application/json"},
                      body=b"{\"a\":1}", content_type="application/json")
    trace.log_response("r1", 200, 123)
    recs = _read(path)
    assert recs[0]["phase"] == "request"
    assert recs[0]["headers"]["X-API-Key"].startswith("sk-v****") and "(len=" in recs[0]["headers"]["X-API-Key"]
    assert "body" not in recs[0] and "body" not in recs[1]
    assert recs[1] == {"request_id": "r1", "phase": "response", "status": 200, "duration_ms": 123}


def test_body_mode_masks_sensitive_but_keeps_normal(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_request("r1", "u1", "m1", "POST", "http://x",
                      {"Authorization": "Bearer sk-abc12345", "Accept": "application/json"},
                      body=b"{\"q\":1}", content_type="application/json")
    recs = _read(path)
    assert recs[0]["body"] == '{"q":1}'
    assert recs[0]["headers"]["Authorization"].startswith("Bea****2345")
    assert recs[0]["headers"]["Accept"] == "application/json"
    assert "sk-abc12345" not in json.dumps(recs[0])


def test_body_truncation(tmp_path):
    path = _capture(tmp_path, "body", limit=10)
    trace.log_request("r1", "u1", "m1", "POST", "http://x", {}, body=b"0123456789ABCDEF")
    recs = _read(path)
    assert recs[0]["body_truncated"] is True and len(recs[0]["body"]) == 10


def test_binary_body_skipped(tmp_path):
    path = _capture(tmp_path, "body")
    trace.log_request("r1", "u1", "m1", "POST", "http://x", {}, body=b"\x00\x01", content_type="application/octet-stream")
    recs = _read(path)
    assert recs[0]["body_bytes"] == 2 and "body" not in recs[0]


def test_sse_event_only_in_body_mode(tmp_path):
    path = _capture(tmp_path, "metadata")
    trace.log_sse_event("r1", "message", b"data")
    assert _read(path) == []
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_trace.py -v`
Expected: FAIL（ModuleNotFoundError: agent_proxy.trace）

- [ ] **Step 3: 实现 trace.py**

```python
"""追踪日志（trace.log）：三档粒度 + header 指纹脱敏 + body 截断（安全底线：敏感值永不落盘）。"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-auth-token"}
_TEXT_TYPES = ("text/", "application/json", "application/xml", "application/x-www-form-urlencoded")

_trace = logging.getLogger("agent_proxy.trace")
_mode = "metadata"
_max_body = 64 * 1024


def configure(mode: str, max_body: int) -> None:
    global _mode, _max_body
    _mode = mode
    _max_body = max_body


def enabled() -> bool:
    return _mode != "off"


def fingerprint(value: str) -> str:
    if len(value) >= 8:
        return f"{value[:4]}****{value[-4:]}(len={len(value)})"
    return "****"


def _headers_for_log(headers: dict[str, str], body_mode: bool) -> dict[str, str]:
    out = {}
    for key, value in headers.items():
        sensitive = key.lower() in SENSITIVE_HEADERS
        out[key] = fingerprint(value) if (sensitive or not body_mode) else value
    return out


def _truncate(body: bytes | str, content_type: str = "") -> dict:
    if content_type and not content_type.lower().startswith(_TEXT_TYPES):
        size = len(body) if isinstance(body, bytes) else len(body.encode("utf-8"))
        return {"body_bytes": size, "body_skipped": "binary"}
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    raw = text.encode("utf-8")
    truncated = len(raw) > _max_body
    if truncated:
        text = raw[:_max_body].decode("utf-8", "replace")
    return {"body": text, "body_truncated": truncated}


def _write(record: dict) -> None:
    record["ts"] = datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")
    _trace.info(json.dumps(record, ensure_ascii=False))


def log_request(request_id: str, uid: str, mapping_id: str, method: str, url: str,
                headers: dict[str, str], body: bytes = b"", content_type: str = "") -> None:
    if _mode == "off":
        return
    record: dict = {
        "request_id": request_id, "uid": uid, "mapping_id": mapping_id,
        "phase": "request", "method": method, "url": url,
        "headers": _headers_for_log(headers, body_mode=(_mode == "body")),
        "body_bytes": len(body),
    }
    if _mode == "body":
        record.update(_truncate(body, content_type))
    _write(record)


def log_response(request_id: str, status: int, duration_ms: int,
                 headers: dict[str, str] | None = None, body: bytes = b"",
                 content_type: str = "") -> None:
    if _mode == "off":
        return
    record: dict = {"request_id": request_id, "phase": "response",
                    "status": status, "duration_ms": duration_ms}
    if headers is not None:
        record["headers"] = _headers_for_log(headers, body_mode=(_mode == "body"))
    if _mode == "body":
        record.update(_truncate(body, content_type))
    _write(record)


def log_sse_event(request_id: str, event: str, data: bytes) -> None:
    """SSE 事件仅 body 模式记录（心跳/retry 行由调用方过滤后再传入）。"""
    if _mode != "body":
        return
    record: dict = {"request_id": request_id, "phase": "sse_event", "event": event}
    record.update(_truncate(data))
    _write(record)
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_trace.py -v`
Expected: 6 PASS

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/trace.py tests/unit/test_trace.py
git commit -m "feat(M1): 追踪日志 trace.py（三档粒度/指纹脱敏/body截断/SSE事件）"
```
---

### Task 5: 错误体系 + 中间件 + 指标 + main 最小组装 + 集成测试夹具

**Files:**
- Create: `src/agent_proxy/errors.py`
- Create: `src/agent_proxy/metrics.py`
- Create: `src/agent_proxy/middleware.py`
- Create: `src/agent_proxy/main.py`
- Create: `src/agent_proxy/api/__init__.py`（空文件）
- Create: `src/agent_proxy/api/mgmt.py`（空 router 占位，Task 10 填充）
- Create: `src/agent_proxy/api/deps.py`（本 Task 建 get_db，身份依赖 Task 6）
- Create: `src/agent_proxy/cache.py`（本 Task 先建 build_redis，Task 9 填充读写）
- Create: `tests/conftest.py`
- Create: `tests/integration/test_health.py`

- [ ] **Step 1: 写 errors.py**

```python
"""统一错误：AppError(code,status,message) → JSON {"code","message","request_id"}。"""
from __future__ import annotations

import logging

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

log = logging.getLogger("agent_proxy")


class AppError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message
        super().__init__(message)


def error_response(request: Request, status: int, code: str, message: str) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "")
    return JSONResponse(
        {"code": code, "message": message, "request_id": request_id},
        status_code=status,
        headers={"X-Request-ID": request_id},
    )


def install_error_handlers(app) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError):
        return error_response(request, exc.status, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        return error_response(request, 400, "INVALID_PARAM", f"参数非法: {first}")

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.exception("unhandled error")
        return error_response(request, 500, "INTERNAL_ERROR", "内部错误")
```

- [ ] **Step 2: 写 metrics.py**

```python
"""Prometheus 指标定义（标签仅低基数维度，不放 user_id/mapping_id）。"""
from prometheus_client import Counter, Gauge, Histogram

requests_total = Counter("ap_requests_total", "HTTP 请求总数", ["route", "type", "status"])
request_duration = Histogram("ap_request_duration_seconds", "端到端延迟", ["route", "type"])
upstream_duration = Histogram("ap_upstream_duration_seconds", "上游耗时（M2+ 使用）", ["type"])
upstream_errors_total = Counter("ap_upstream_errors_total", "上游失败计数（M2+ 使用）", ["type", "code"])
bytes_total = Counter("ap_bytes_total", "上下行字节数（M2+ 使用）", ["direction"])
sse_active = Gauge("ap_sse_active_connections", "SSE 活跃长连接数（M3+ 使用）")
inflight = Gauge("ap_inflight_requests", "在途请求数")
oauth_actions_total = Counter("ap_oauth_actions_total", "OAuth 凭证事件（M6 使用）", ["action"])
```

- [ ] **Step 3: 写 middleware.py（request_id + 埋点 + 审计）**

```python
"""中间件：request_id 生成与 X-Request-ID 回传、Prometheus 埋点、审计日志。"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone

from starlette.types import ASGIApp, Receive, Scope, Send

from . import metrics

audit = logging.getLogger("agent_proxy.audit")


def route_name(path: str) -> str:
    if path.startswith("/api/v1/mappings"):
        return "mgmt"
    if path.startswith("/api/v1/builtin"):
        return "builtin"
    if path.startswith("/p/"):
        return "proxy"
    if path.startswith("/admin"):
        return "admin"
    if path in ("/metrics", "/healthz", "/readyz"):
        return "ops"
    return "other"


def _type_of(route: str) -> str:
    return "http" if route == "proxy" else "-"


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        scope.setdefault("state", {})
        request_id = uuid.uuid4().hex
        scope["state"]["request_id"] = request_id
        route = route_name(scope.get("path", ""))
        method = scope.get("method", "")
        start = time.monotonic()
        status_holder = {"status": 0}
        metrics.inflight.inc()

        async def send_wrapper(message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                message.setdefault("headers", []).append((b"x-request-id", request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            metrics.inflight.dec()
            status = status_holder["status"] or 500
            t = _type_of(route)
            metrics.requests_total.labels(route=route, type=t, status=str(status)).inc()
            metrics.request_duration.labels(route=route, type=t).observe(time.monotonic() - start)
            if method != "OPTIONS":
                state = scope["state"]
                audit.info(json.dumps({
                    "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
                    "request_id": request_id,
                    "user_id": state.get("uid", ""),
                    "user_name": state.get("user_name", ""),
                    "action": state.get("audit_action", route),
                    "mapping_id": state.get("mapping_id", ""),
                    "method": method,
                    "path": scope.get("path", ""),
                    "status": status,
                    "duration_ms": duration_ms,
                    "client_ip": (scope.get("client") or ("",))[0],
                }, ensure_ascii=False))
```

- [ ] **Step 4: 写 main.py 最小组装与 api 占位文件**

`src/agent_proxy/api/__init__.py`: 空文件。

`src/agent_proxy/api/deps.py`（本 Task 仅 get_db）:

```python
"""FastAPI 依赖。"""
from __future__ import annotations

from fastapi import Request


async def get_db(request: Request):
    async with request.app.state.sessionmaker() as session:
        yield session
```

`src/agent_proxy/api/mgmt.py`（占位，Task 10 填充路由）:

```python
"""管理接口 /api/v1/mappings。"""
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/mappings", tags=["mgmt"])
```

`src/agent_proxy/cache.py`（本 Task 仅 build_redis）:

```python
"""Redis cache-aside（Task 9 填充读写逻辑）。"""
from __future__ import annotations

import redis.asyncio as redis_async


def build_redis(redis_url: str):
    return redis_async.from_url(redis_url, socket_timeout=5)
```

`src/agent_proxy/main.py`:

```python
"""FastAPI 组装：lifespan（引擎/Redis/建表/自检/优雅停机）、中间件、路由、健康检查。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from . import errors, metrics, trace
from .cache import build_redis
from .config import Settings, get_settings
from .db import Base, build_engine, build_sessionmaker
from .logging_setup import setup_logging, shutdown_logging
from .middleware import RequestContextMiddleware
from .api.mgmt import router as mgmt_router

log = logging.getLogger("agent_proxy")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    setup_logging(settings.log_dir, settings.log_level)
    trace.configure(settings.trace_mode, settings.trace_body_max_size)
    engine = build_engine(settings.mysql_dsn)
    app.state.engine = engine
    app.state.sessionmaker = build_sessionmaker(engine)
    app.state.redis = build_redis(settings.redis_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await app.state.redis.ping()
    log.info("agent-proxy 启动: listen=%s external_base=%s", settings.listen, settings.external_base)
    yield
    shutdown_logging()
    await app.state.redis.aclose()
    await engine.dispose()
    log.info("agent-proxy 已停止")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="agent-proxy", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    if settings.cors_allowed_origins:
        from fastapi.middleware.cors import CORSMiddleware
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_allowed_origins),
                           allow_methods=["*"], allow_headers=["Authorization", "Content-Type"])
    app.add_middleware(RequestContextMiddleware)
    errors.install_error_handlers(app)
    app.include_router(mgmt_router)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz(request: Request):
        try:
            async with request.app.state.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            await request.app.state.redis.ping()
        except Exception as exc:
            return JSONResponse({"status": "unavailable", "error": str(exc)}, status_code=503)
        return {"status": "ready"}

    @app.get("/metrics")
    async def metrics_endpoint():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app
```

- [ ] **Step 5: 写集成测试夹具 tests/conftest.py**

```python
"""集成测试夹具：独立测试库 agent_proxy_test + Redis db9 + ASGITransport。"""
import base64
import json
import os

import pymysql
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ.update({
    "ENV": "dev",
    "TOKEN_VERIFY_IMPL": "stub",
    "LOGIN_IMPL": "stub",
    "EXTERNAL_BASE": "http://testserver",
    "MYSQL_DSN": "mysql+aiomysql://root:123456@127.0.0.1:3306/agent_proxy_test",
    "REDIS_URL": "redis://127.0.0.1:6379/9",
    "SSRF_ALLOW_PRIVATE": "true",
    "ENCRYPT_AT_REST": "false",
    "MASTER_KEY": "test-master-key",
    "TRACE_MODE": "metadata",
    "LOG_DIR": "logs-test",
    "LOG_LEVEL": "INFO",
})

from agent_proxy.config import Settings  # noqa: E402
from agent_proxy.main import create_app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _recreate_test_db():
    conn = pymysql.connect(host="127.0.0.1", user="root", password="123456", port=3306)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE DATABASE IF NOT EXISTS agent_proxy_test "
                "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            conn.commit()
    finally:
        conn.close()


@pytest.fixture
async def app():
    application = create_app(Settings.from_env(os.environ))
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


@pytest.fixture(autouse=True)
async def _clean(app):
    yield
    from sqlalchemy import text
    async with app.state.sessionmaker() as session:
        for table in ("proxy_oauth_credential", "proxy_oauth_client", "proxy_mapping"):
            await session.execute(text(f"DELETE FROM {table}"))
        await session.commit()
    await app.state.redis.flushdb()


def make_token(user_id: str = "u888", role: str | None = None, user_name: str = "张三") -> str:
    payload = {"user_id": user_id, "user_name": user_name}
    if role:
        payload["role"] = role
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"stub.{body}.sig"


def auth(user_id: str = "u888", role: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {make_token(user_id, role)}"}
```

- [ ] **Step 6: 写健康检查集成测试 tests/integration/test_health.py**

```python
async def test_healthz(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    assert resp.headers.get("x-request-id")


async def test_readyz(client):
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


async def test_metrics_exposes_counters(client):
    await client.get("/healthz")
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert "ap_requests_total" in resp.text
    assert "ap_inflight_requests" in resp.text


async def test_request_id_in_error_body(client):
    resp = await client.get("/api/v1/mappings")  # 未带 token → 401
    assert resp.status_code == 401
    body = resp.json()
    assert body["code"] == "INVALID_TOKEN" and body["request_id"]
```

注：`test_request_id_in_error_body` 依赖 Task 6 的身份依赖，本 Task 允许 FAIL。

- [ ] **Step 7: 运行**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_health.py -v`
Expected: healthz / readyz / metrics PASS；test_request_id_in_error_body FAIL（预期，Task 6 转绿）

- [ ] **Step 8: Commit**

```bash
git add src/ tests/
git commit -m "feat(M1): 错误体系/中间件(request_id+审计)/指标/main 组装/集成夹具"
```

---

### Task 6: 身份模块 auth.py + Bearer 依赖

**Files:**
- Create: `src/agent_proxy/auth.py`
- Create: `tests/utils.py`
- Modify: `src/agent_proxy/api/deps.py`
- Create: `tests/unit/test_auth.py`

- [ ] **Step 1: 写测试工具与失败测试**

`tests/utils.py`:

```python
import base64
import json


def make_token(user_id: str = "u888", role: str | None = None, user_name: str = "张三") -> str:
    payload = {"user_id": user_id, "user_name": user_name}
    if role:
        payload["role"] = role
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"stub.{body}.sig"
```

`tests/unit/test_auth.py`:

```python
import base64
import json

import pytest

from agent_proxy.auth import StubVerifier, TokenInvalidError, build_verifier
from tests.utils import make_token


async def test_stub_verify_ok():
    identity = await StubVerifier().verify(make_token("u999", role="admin", user_name="李四"))
    assert identity.user_id == "u999"
    assert identity.role == "admin"
    assert identity.user_name == "李四"


async def test_stub_verify_without_role():
    identity = await StubVerifier().verify(make_token("u888"))
    assert identity.role is None


async def test_stub_verify_missing_uid():
    payload = base64.urlsafe_b64encode(json.dumps({"foo": 1}).encode()).decode()
    with pytest.raises(TokenInvalidError):
        await StubVerifier().verify(f"stub.{payload}.sig")


async def test_stub_verify_garbage():
    with pytest.raises(TokenInvalidError):
        await StubVerifier().verify("not-a-jwt")


def test_build_verifier_unknown_impl():
    with pytest.raises(NotImplementedError):
        build_verifier("magic")
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_auth.py -v`
Expected: FAIL（ModuleNotFoundError: agent_proxy.auth）

- [ ] **Step 3: 实现 auth.py**

```python
"""身份：Identity / TokenVerifier 抽象 + stub 实现。第三方校验实现后续接入（协议实现时定）。"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Protocol

from .errors import AppError


class TokenInvalidError(AppError):
    def __init__(self, message: str = "token 缺失或无效"):
        super().__init__(401, "INVALID_TOKEN", message)


class TokenServiceError(AppError):
    def __init__(self, message: str = "身份校验服务不可用"):
        super().__init__(503, "AUTH_SERVICE_UNAVAILABLE", message)


@dataclass(frozen=True)
class Identity:
    user_id: str
    user_name: str | None = None
    role: str | None = None


class TokenVerifier(Protocol):
    async def verify(self, token: str) -> Identity: ...


class StubVerifier:
    """开发/测试：本地解码 JWT payload 中段，不验签。claims: user_id(必须)/user_name/role。"""

    async def verify(self, token: str) -> Identity:
        try:
            payload = json.loads(_b64url_decode(token.split(".")[1]))
        except Exception as exc:
            raise TokenInvalidError("token 格式非法") from exc
        user_id = payload.get("user_id")
        if not user_id:
            raise TokenInvalidError("缺少 user_id claim")
        return Identity(user_id=str(user_id),
                        user_name=payload.get("user_name"), role=payload.get("role"))


class ThirdPartyVerifier:
    """后续接入：对接第三方校验接口（协议确定后实现 verify，注册于 build_verifier）。"""

    async def verify(self, token: str) -> Identity:
        raise NotImplementedError("third_party 校验实现待接入，见设计文档第 7 章")


def build_verifier(impl: str) -> TokenVerifier:
    if impl == "stub":
        return StubVerifier()
    raise NotImplementedError(f"未知 TOKEN_VERIFY_IMPL: {impl}")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
```

- [ ] **Step 4: 扩展 api/deps.py（身份依赖 + admin 判定）**

在 `get_db` 之后追加：

```python
from ..auth import Identity, TokenInvalidError, build_verifier
from ..config import get_settings

_verifier = None


def _get_verifier():
    global _verifier
    if _verifier is None:
        _verifier = build_verifier(get_settings().token_verify_impl)
    return _verifier


async def get_current_identity(request: Request) -> Identity:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise TokenInvalidError("缺少 Authorization: Bearer token")
    identity = await _get_verifier().verify(header[7:].strip())
    request.state.uid = identity.user_id
    request.state.user_name = identity.user_name or ""
    return identity


def is_admin(identity: Identity, admin_role: str) -> bool:
    return identity.role == admin_role
```

- [ ] **Step 5: 运行全部相关测试**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_auth.py tests/integration/test_health.py -v`
Expected: 全部 PASS（test_request_id_in_error_body 转绿）

- [ ] **Step 6: Commit**

```bash
git add src/agent_proxy/auth.py src/agent_proxy/api/deps.py tests/
git commit -m "feat(M1): TokenVerifier 抽象 + stub + Bearer 依赖（uid/user_name 写入 state）"
```

---

### Task 7: ORM 模型与建表验证

**Files:**
- Create: `src/agent_proxy/db.py`
- Create: `src/agent_proxy/models.py`
- Modify: `src/agent_proxy/main.py`（import 区加 models 注册）
- Create: `tests/integration/test_tables.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_tables.py`:

```python
from sqlalchemy import text


async def test_tables_created(app):
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='agent_proxy_test'"
        ))
        names = {r[0] for r in rows}
    assert {"proxy_mapping", "proxy_oauth_client", "proxy_oauth_credential"} <= names


async def test_mapping_columns(app):
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='agent_proxy_test' AND table_name='proxy_mapping'"
        ))
        cols = {r[0] for r in rows}
    assert {"mapping_id", "owner_uid", "name", "type", "visibility", "auth_mode",
            "upstream_url", "upstream_headers", "test_request", "status"} <= cols
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_tables.py -v`
Expected: FAIL（ModuleNotFoundError: agent_proxy.db）

- [ ] **Step 3: 实现 db.py**

```python
"""MySQL 异步 engine / session。"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def build_engine(mysql_dsn: str, pool_size: int = 10):
    return create_async_engine(mysql_dsn, pool_size=pool_size, pool_recycle=1800, pool_pre_ping=True)


def build_sessionmaker(engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
```

- [ ] **Step 4: 实现 models.py**

```python
"""ORM：proxy_mapping / proxy_oauth_client / proxy_oauth_credential（M6 表 M1 一并建）。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, BigInteger, DateTime, Enum, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class ProxyMapping(Base):
    __tablename__ = "proxy_mapping"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    mapping_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    owner_uid: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str | None] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(Enum("http", "mcp", name="mapping_type"))
    visibility: Mapped[str] = mapped_column(
        Enum("private", "public", name="mapping_visibility"), default="private")
    auth_mode: Mapped[str] = mapped_column(
        Enum("static", "oauth", name="mapping_auth_mode"), default="static")
    upstream_url: Mapped[str] = mapped_column(String(2048))
    upstream_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    test_request: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(
        Enum("active", "disabled", name="mapping_status"), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now())


class OAuthClient(Base):
    __tablename__ = "proxy_oauth_client"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    mapping_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    client_id: Mapped[str] = mapped_column(String(256))
    client_secret: Mapped[str | None] = mapped_column(Text)
    token_auth: Mapped[str] = mapped_column(
        Enum("client_secret_basic", "client_secret_post", "none", name="oauth_token_auth"),
        default="client_secret_post")
    authorize_url: Mapped[str | None] = mapped_column(String(2048))
    token_url: Mapped[str | None] = mapped_column(String(2048))
    scopes: Mapped[str | None] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(Enum("dcr", "manual", name="oauth_client_source"))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now())


class OAuthCredential(Base):
    __tablename__ = "proxy_oauth_credential"
    __table_args__ = (UniqueConstraint("mapping_id", "uid", name="uk_mapping_uid"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    mapping_id: Mapped[str] = mapped_column(String(16), index=True)
    uid: Mapped[str] = mapped_column(String(64), index=True)
    access_token: Mapped[str] = mapped_column(Text)
    refresh_token: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    scope: Mapped[str | None] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(
        Enum("active", "invalid", name="oauth_cred_status"), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now())
```

- [ ] **Step 5: main.py 注册 ORM 元数据**

`src/agent_proxy/main.py` import 区追加一行：

```python
from . import models as _models  # noqa: F401  注册 ORM 元数据供 create_all
```

- [ ] **Step 6: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_tables.py -v`
Expected: 2 PASS

- [ ] **Step 7: Commit**

```bash
git add src/agent_proxy/db.py src/agent_proxy/models.py src/agent_proxy/main.py tests/integration/test_tables.py
git commit -m "feat(M1): ORM 三表（含 M6 OAuth 表预留字段）+ 建表验证"
```

---

### Task 8: 纯函数模块 mapping_id / placeholder / ssrf

**Files:**
- Create: `src/agent_proxy/mapping_id.py`
- Create: `src/agent_proxy/placeholder.py`
- Create: `src/agent_proxy/ssrf.py`
- Create: `tests/unit/test_mapping_id.py`
- Create: `tests/unit/test_placeholder.py`
- Create: `tests/unit/test_ssrf.py`

- [ ] **Step 1: 写三个失败测试**

`tests/unit/test_mapping_id.py`:

```python
import re

from agent_proxy.mapping_id import LENGTH, MAPPING_ID_RE, new_mapping_id


def test_shape():
    for _ in range(50):
        mid = new_mapping_id()
        assert len(mid) == LENGTH
        assert MAPPING_ID_RE.match(mid)


def test_random_enough():
    assert len({new_mapping_id() for _ in range(200)}) > 190
```

`tests/unit/test_placeholder.py`:

```python
import pytest

from agent_proxy.placeholder import mask_headers, validate_headers


def test_mask_same_key_different_value():
    masked = mask_headers({"Authorization": "Bearer sk-real-key", "X-User-Id": "u888"})
    assert masked == {"Authorization": "${PX:Authorization}", "X-User-Id": "${PX:X-User-Id}"}
    assert "sk-real-key" not in str(masked)


def test_validate_rejects_bad_name():
    with pytest.raises(ValueError):
        validate_headers({"bad header": "v"})


def test_validate_rejects_too_many():
    with pytest.raises(ValueError):
        validate_headers({f"h{i}": "v" for i in range(33)})


def test_validate_rejects_long_value():
    with pytest.raises(ValueError):
        validate_headers({"X-K": "x" * 4097})


def test_validate_empty_ok():
    validate_headers({})
```

`tests/unit/test_ssrf.py`:

```python
import pytest

from agent_proxy.ssrf import UpstreamNotAllowed, validate_upstream_url


def test_strip_trailing_slash():
    assert validate_upstream_url("http://10.0.0.5/api/v1/", allow_private=True) == "http://10.0.0.5/api/v1"


def test_reject_non_http_scheme():
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("ftp://10.0.0.5", allow_private=True)


def test_reject_private_when_not_allowed():
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("http://127.0.0.1:6379", allow_private=False)


def test_allow_private_when_enabled():
    assert validate_upstream_url("http://127.0.0.1:6379", allow_private=True).endswith("6379")


def test_reject_missing_host():
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("http:///path", allow_private=True)
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_mapping_id.py tests/unit/test_placeholder.py tests/unit/test_ssrf.py -v`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现三个模块**

`src/agent_proxy/mapping_id.py`:

```python
"""随机映射 ID：base62 12 位（约 71 bit 熵），不含任何真实地址信息。"""
from __future__ import annotations

import re
import secrets

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
LENGTH = 12
MAPPING_ID_RE = re.compile(rf"^[A-Za-z0-9]{{{LENGTH}}}$")


def new_mapping_id() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))
```

`src/agent_proxy/placeholder.py`:

```python
"""占位符：${PX:<header名>}。同 key 不同值，纯脱敏展示；还原按 key 查存储，不解析占位符。"""
from __future__ import annotations

import re

HEADER_TOKEN_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,128}$")
MAX_HEADERS = 32
MAX_VALUE_LEN = 4096


def validate_headers(headers: dict[str, str]) -> None:
    """校验 header 键名/数量/值长度，非法抛 ValueError。"""
    if len(headers) > MAX_HEADERS:
        raise ValueError(f"header 数量超过上限 {MAX_HEADERS}")
    for key, value in headers.items():
        if not HEADER_TOKEN_RE.match(key):
            raise ValueError(f"非法 header 名: {key!r}")
        if not isinstance(value, str):
            raise ValueError(f"header 值必须为字符串: {key!r}")
        if len(value) > MAX_VALUE_LEN:
            raise ValueError(f"header 值超长: {key!r}")


def mask_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: f"${{PX:{key}}}" for key in headers}


def normalize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    return dict(headers or {})
```

`src/agent_proxy/ssrf.py`:

```python
"""SSRF 防护：scheme 白名单 + DNS 解析拒绝私网/环回/链路本地/保留地址。"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UpstreamNotAllowed(ValueError):
    pass


def validate_upstream_url(url: str, allow_private: bool = False) -> str:
    """校验并返回规范化 URL（去尾斜杠）。非法抛 UpstreamNotAllowed。"""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UpstreamNotAllowed(f"不支持的 scheme: {parsed.scheme!r}（仅 http/https）")
    if not parsed.hostname:
        raise UpstreamNotAllowed("缺少 host")
    if not allow_private:
        for info in socket.getaddrinfo(parsed.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast):
                raise UpstreamNotAllowed(f"上游解析到受限地址: {ip}")
    return url.rstrip("/")
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_mapping_id.py tests/unit/test_placeholder.py tests/unit/test_ssrf.py -v`
Expected: 13 PASS

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/mapping_id.py src/agent_proxy/placeholder.py src/agent_proxy/ssrf.py tests/unit/
git commit -m "feat(M1): mapping_id/占位符/SSRF 校验三个纯函数模块"
```

---

### Task 9: 缓存 + Schema + 应用服务层 services

**Files:**
- Modify: `src/agent_proxy/cache.py`（填充读写逻辑）
- Create: `src/agent_proxy/schemas.py`
- Create: `src/agent_proxy/services.py`
- Create: `tests/integration/test_services.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_services.py`:

```python
from agent_proxy import cache
from agent_proxy.services import (build_proxy_url, create_mapping, delete_mapping,
                                  get_owned, list_mappings, load_mapping,
                                  row_to_dict, update_mapping)


def _mk_body(**overrides):
    body = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1",
            "headers": {"Authorization": "Bearer sk-real-key"}}
    body.update(overrides)
    return body


async def test_create_and_load_cache_roundtrip(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="http", name=None, visibility="private",
                               upstream_url="http://10.0.0.5/api/v1",
                               headers={"Authorization": "Bearer sk-real-key"}, test_request=None)
    # 命中缓存
    cached = await load_mapping(app.state.sessionmaker(), app.state.redis,
                                row.mapping_id, app.state.settings.cache_ttl)
    assert cached is not None and cached["owner_uid"] == "u888"
    assert cached["upstream_headers"] == {"Authorization": "Bearer sk-real-key"}
    # 走缓存 dict 一致
    assert (await cache.get_mapping(app.state.redis, row.mapping_id)) == cached


async def test_update_invalidates_cache(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="mcp", name=None, visibility="private",
                               upstream_url="http://10.0.0.5/sse", headers={}, test_request=None)
    await load_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, 300)
    updated = await update_mapping(app.state.sessionmaker(), app.state.redis,
                                   app.state.settings, row.mapping_id, "u888",
                                   upstream_url="http://10.0.0.5/mcp")
    assert updated["upstream_url"] == "http://10.0.0.5/mcp"
    again = await load_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, 300)
    assert again["upstream_url"] == "http://10.0.0.5/mcp"  # 缓存已失效，读到新值


async def test_get_owned_hides_others(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="http", name=None, visibility="private",
                               upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
    assert await get_owned(app.state.sessionmaker(), app.state.redis, row.mapping_id,
                           "u888", 300) is not None
    assert await get_owned(app.state.sessionmaker(), app.state.redis, row.mapping_id,
                           "u999", 300) is None


async def test_list_only_mine(app):
    await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                         "u888", type_="http", name=None, visibility="private",
                         upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
    rows = await list_mappings(app.state.sessionmaker(), "u888", limit=10, offset=0)
    assert len(rows) == 1
    assert await list_mappings(app.state.sessionmaker(), "u999", limit=10, offset=0) == []


async def test_delete(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="http", name=None, visibility="private",
                               upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
    assert await delete_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, "u888")
    assert not await delete_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, "u888")
    assert await load_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, 300) is None


def test_build_proxy_url():
    from agent_proxy.config import Settings
    settings = Settings.from_env({"MYSQL_DSN": "mysql+aiomysql://x", "REDIS_URL": "redis://x",
                                  "EXTERNAL_BASE": "http://testserver"})
    assert build_proxy_url(settings, "aB3xK9mQ2wR4", "http://bobo.com/api/v1", "http") \
        == "http://testserver/p/aB3xK9mQ2wR4"
    assert build_proxy_url(settings, "aB3xK9mQ2wR4", "https://mcp.ex.com/sse", "mcp") \
        == "http://testserver/p/aB3xK9mQ2wR4/sse"


async def test_row_to_dict_serializable(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="http", name="我的接口", visibility="private",
                               upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
    import json
    data = row_to_dict(row)
    json.dumps(data, ensure_ascii=False)  # 不抛异常即可
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_services.py -v`
Expected: FAIL（services 不存在）

- [ ] **Step 3: 填充 cache.py 读写逻辑**

在 `build_redis` 之后追加：

```python
import json  # 移至模块顶部 import 区
import logging

log = logging.getLogger("agent_proxy")


def _cache_key(mapping_id: str) -> str:
    return f"ap:mapping:{mapping_id}"


async def get_mapping(r, mapping_id: str) -> dict | None:
    try:
        raw = await r.get(_cache_key(mapping_id))
    except Exception as exc:
        log.warning("redis get 失败，回源 MySQL: %s", exc)
        return None
    return json.loads(raw) if raw is not None else None


async def set_mapping(r, mapping_id: str, data: dict, ttl: int) -> None:
    try:
        await r.set(_cache_key(mapping_id), json.dumps(data, ensure_ascii=False), ex=ttl)
    except Exception as exc:
        log.warning("redis set 失败: %s", exc)


async def invalidate(r, mapping_id: str) -> None:
    try:
        await r.delete(_cache_key(mapping_id))
    except Exception as exc:
        log.warning("redis del 失败: %s", exc)
```

- [ ] **Step 4: 写 schemas.py**

```python
"""请求/响应模型（Pydantic v2）。"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class MappingCreate(BaseModel):
    type: Literal["http", "mcp"]
    name: str | None = Field(default=None, max_length=128)
    visibility: Literal["private", "public"] = "private"
    upstream_url: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    test_request: dict | None = None

    @field_validator("test_request")
    @classmethod
    def _validate_test_request(cls, v: dict | None) -> dict | None:
        if v is not None and not {"method", "path"} <= set(v.keys()):
            raise ValueError("test_request 需包含 method/path")
        return v


class MappingUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    visibility: Literal["private", "public"] | None = None
    upstream_url: str | None = Field(default=None, min_length=1, max_length=2048)
    headers: dict[str, str] | None = None
    test_request: dict | None = None
    status: Literal["active", "disabled"] | None = None


class RegisteredOut(BaseModel):
    """POST/PUT 响应：代理地址 + 占位符 header（页面据此保存到 Agent）。"""
    mapping_id: str
    name: str | None = None
    type: str
    visibility: str
    proxy_url: str
    headers: dict[str, str]
    status: str


class MappingDetailOut(RegisteredOut):
    upstream_url: str
    test_request: dict | None = None
    created_at: str | None = None
    updated_at: str | None = None


class ListItemOut(BaseModel):
    """列表项：不含真实 headers。"""
    mapping_id: str
    name: str | None = None
    type: str
    upstream_url: str
    proxy_url: str
    status: str
    created_at: str | None = None
    updated_at: str | None = None
```

- [ ] **Step 5: 写 services.py**

```python
"""应用服务层：映射 CRUD、cache-aside 加载、归属校验。管理、回显、转发共用。"""
from __future__ import annotations

import logging

from sqlalchemy import IntegrityError, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import cache, mapping_id as mid_module, placeholder
from .config import Settings
from .errors import AppError
from .models import ProxyMapping
from .ssrf import validate_upstream_url
from urllib.parse import urlparse

log = logging.getLogger("agent_proxy")


def row_to_dict(row: ProxyMapping) -> dict:
    return {
        "id": row.id, "mapping_id": row.mapping_id, "owner_uid": row.owner_uid,
        "name": row.name, "type": row.type, "visibility": row.visibility,
        "auth_mode": row.auth_mode, "upstream_url": row.upstream_url,
        "upstream_headers": row.upstream_headers or {}, "test_request": row.test_request,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def build_proxy_url(settings: Settings, mapping_id: str, upstream_url: str, type_: str) -> str:
    """proxy_url = EXTERNAL_BASE/p/{id}[ + mcp 端点路径]。"""
    prefix = f"{settings.external_base.rstrip('/')}/p/{mapping_id}"
    if type_ == "mcp":
        prefix += urlparse(upstream_url).path.rstrip("/")
    return prefix


async def load_mapping(session: AsyncSession, r, mapping_id: str, ttl: int) -> dict | None:
    """cache-aside：Redis → MySQL 回填。返回记录 dict 或 None。"""
    cached = await cache.get_mapping(r, mapping_id)
    if cached is not None:
        return cached
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id)
    )).scalar_one_or_none()
    if row is None:
        return None
    data = row_to_dict(row)
    await cache.set_mapping(r, mapping_id, data, ttl)
    return data


async def get_owned(session: AsyncSession, r, mapping_id: str, uid: str, ttl: int) -> dict | None:
    """加载并校验归属；非注册者返回 None（404 隐藏存在性）。"""
    data = await load_mapping(session, r, mapping_id, ttl)
    if data is None or data["owner_uid"] != uid:
        return None
    return data


async def create_mapping(session: AsyncSession, r, settings: Settings, owner_uid: str, *,
                         type_: str, name: str | None, visibility: str,
                         upstream_url: str, headers: dict[str, str],
                         test_request: dict | None) -> ProxyMapping:
    placeholder.validate_headers(headers)
    url = validate_upstream_url(upstream_url, settings.ssrf_allow_private)
    for attempt in range(5):
        mapping_id = mid_module.new_mapping_id()
        row = ProxyMapping(mapping_id=mapping_id, owner_uid=owner_uid, name=name,
                           type=type_, visibility=visibility, auth_mode="static",
                           upstream_url=url, upstream_headers=headers,
                           test_request=test_request, status="active")
        session.add(row)
        try:
            await session.commit()
            break
        except IntegrityError:
            await session.rollback()
            if attempt == 4:
                raise AppError(500, "INTERNAL_ERROR", "mapping_id 生成冲突，请重试")
    await cache.invalidate(r, row.mapping_id)
    return row


async def list_mappings(session: AsyncSession, owner_uid: str, limit: int, offset: int) -> list[ProxyMapping]:
    result = await session.execute(
        select(ProxyMapping).where(ProxyMapping.owner_uid == owner_uid)
        .order_by(ProxyMapping.id.desc()).offset(offset).limit(limit))
    return list(result.scalars().all())


async def update_mapping(session: AsyncSession, r, settings: Settings, mapping_id: str,
                         owner_uid: str, patch: dict) -> dict | None:
    """按 owner 定位并更新；返回 row_to_dict 或 None（不存在/非本人）。"""
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id,
                                   ProxyMapping.owner_uid == owner_uid)
    )).scalar_one_or_none()
    if row is None:
        return None
    if "headers" in patch and patch["headers"] is not None:
        placeholder.validate_headers(patch["headers"])
        row.upstream_headers = patch["headers"]
    if patch.get("upstream_url"):
        row.upstream_url = validate_upstream_url(patch["upstream_url"], settings.ssrf_allow_private)
    for field in ("name", "visibility", "test_request", "status"):
        if patch.get(field) is not None:
            setattr(row, field, patch[field])
    await session.commit()
    await cache.invalidate(r, mapping_id)
    return row_to_dict(row)


async def delete_mapping(session: AsyncSession, r, mapping_id: str, owner_uid: str) -> bool:
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id,
                                   ProxyMapping.owner_uid == owner_uid)
    )).scalar_one_or_none()
    if row is None:
        return False
    await session.delete(row)
    await session.commit()
    await cache.invalidate(r, mapping_id)
    return True
```

- [ ] **Step 6: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_services.py -v`
Expected: 7 PASS

- [ ] **Step 7: Commit**

```bash
git add src/agent_proxy/cache.py src/agent_proxy/schemas.py src/agent_proxy/services.py tests/integration/test_services.py
git commit -m "feat(M1): cache-aside + schemas + 应用服务层（CRUD/归属校验/代理地址拼装）"
```

---

### Task 10: 管理接口路由（注册/列表/详情/resolve/更新/删除）

**Files:**
- Modify: `src/agent_proxy/api/mgmt.py`（填充全部路由）
- Create: `tests/integration/test_mgmt_api.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_mgmt_api.py`:

```python
import pytest

from tests.utils import make_token

BODY = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1",
        "headers": {"Authorization": "Bearer sk-real-key", "X-User-Id": "u888"}}


async def _create(client, token_user="u888", token_admin=False, **overrides):
    payload = {**BODY, **overrides}
    role = "admin" if token_admin else None
    return await client.post("/api/v1/mappings", json=payload,
                             headers={"Authorization": f"Bearer {make_token(token_user, role)}"})


async def test_create_returns_masked_headers_and_proxy_url(client):
    resp = await _create(client)
    assert resp.status_code == 201
    data = resp.json()
    assert len(data["mapping_id"]) == 12
    assert data["proxy_url"] == f"http://testserver/p/{data['mapping_id']}"
    assert data["headers"] == {"Authorization": "${PX:Authorization}", "X-User-Id": "${PX:X-User-Id}"}
    assert "sk-real-key" not in resp.text and "u888" not in data["headers"].values()
    assert data["visibility"] == "private" and data["status"] == "active"


async def test_create_mcp_proxy_url_includes_endpoint_path(client):
    resp = await _create(client, type="mcp", upstream_url="https://mcp.ex.com/sse")
    assert resp.json()["proxy_url"].endswith(f"/p/{resp.json()['mapping_id']}/sse")


async def test_create_public_requires_admin(client):
    resp = await _create(client, visibility="public")
    assert resp.status_code == 403 and resp.json()["code"] == "FORBIDDEN"
    resp = await _create(client, visibility="public", token_admin=True)
    assert resp.status_code == 201


async def test_create_invalid_header_name_400(client):
    resp = await _create(client, headers={"bad header": "v"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_create_invalid_scheme_400(client):
    resp = await _create(client, upstream_url="ftp://10.0.0.5")
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_list_only_mine_no_real_headers(client):
    await _create(client)  # u888
    resp = await client.get("/api/v1/mappings",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    items = resp.json()
    assert len(items) == 1
    assert items[0]["upstream_url"] == "http://10.0.0.5/api/v1"
    assert "headers" not in items[0]
    resp = await client.get("/api/v1/mappings",
                            headers={"Authorization": f"Bearer {make_token('u999')}"})
    assert resp.json() == []


async def test_detail_owner_only_real_headers(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    assert resp.json()["headers"]["Authorization"] == "Bearer sk-real-key"
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u999')}"})
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_resolve_by_proxy_url_and_by_id(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    from urllib.parse import quote
    proxy_url = quote(created["proxy_url"], safe="")
    for value in (f"proxy_url={proxy_url}", f"proxy_url={mid}"):
        resp = await client.get(f"/api/v1/mappings/resolve?{value}",
                                headers={"Authorization": f"Bearer {make_token('u888')}"})
        assert resp.status_code == 200
        assert resp.json()["upstream_url"] == "http://10.0.0.5/api/v1"
        assert resp.json()["headers"]["Authorization"] == "Bearer sk-real-key"
    resp = await client.get("/api/v1/mappings/resolve?proxy_url=garbage",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 400
    resp = await client.get(f"/api/v1/mappings/resolve?proxy_url={mid}",
                            headers={"Authorization": f"Bearer {make_token('u999')}"})
    assert resp.status_code == 404


async def test_put_updates_and_returns_masked(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{mid}",
                            json={"upstream_url": "http://10.0.0.5/api/v2",
                                  "headers": {"Authorization": "Bearer sk-new-key"}},
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["proxy_url"] == f"http://testserver/p/{mid}"
    assert data["headers"] == {"Authorization": "${PX:Authorization}"}
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.json()["upstream_url"] == "http://10.0.0.5/api/v2"
    assert resp.json()["headers"]["Authorization"] == "Bearer sk-new-key"


async def test_put_non_owner_404(client):
    created = (await _create(client)).json()
    resp = await client.put(f"/api/v1/mappings/{created['mapping_id']}",
                            json={"status": "disabled"},
                            headers={"Authorization": f"Bearer {make_token('u999')}"})
    assert resp.status_code == 404


async def test_delete_then_404(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.delete(f"/api/v1/mappings/{mid}",
                               headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 204
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 404
    resp = await client.delete(f"/api/v1/mappings/{mid}",
                               headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 404


async def test_disabled_mapping_detail_visible_but_flagged(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    await client.put(f"/api/v1/mappings/{mid}", json={"status": "disabled"},
                     headers={"Authorization": f"Bearer {make_token('u888')}"})
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200 and resp.json()["status"] == "disabled"


async def test_unauthorized_401(client):
    resp = await client.post("/api/v1/mappings", json=BODY)
    assert resp.status_code == 401 and resp.json()["code"] == "INVALID_TOKEN"
    bad = {"Authorization": "Bearer garbage"}
    resp = await client.get("/api/v1/mappings", headers=bad)
    assert resp.status_code == 401
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_mgmt_api.py -v`
Expected: 全部 FAIL（router 无路由，返回 404 而非预期）

- [ ] **Step 3: 填充 mgmt.py 全部路由**

```python
"""管理接口 /api/v1/mappings（全部要求系统 JWT）。"""
from __future__ import annotations

import logging
import re
from urllib.parse import unquote, urlparse

from fastapi import APIRouter, Depends, Query, Request, Response

from .. import placeholder
from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..schemas import (ListItemOut, MappingCreate, MappingDetailOut, MappingUpdate,
                       RegisteredOut)
from ..services import (build_proxy_url, create_mapping, delete_mapping, get_owned,
                        list_mappings, row_to_dict, update_mapping)
from ..ssrf import UpstreamNotAllowed
from .deps import get_current_identity, get_db, is_admin

log = logging.getLogger("agent_proxy")
router = APIRouter(prefix="/api/v1/mappings", tags=["mgmt"])

_PROXY_PATH_RE = re.compile(r"^/p/([A-Za-z0-9]{12})(/.*)?$")


def parse_proxy_url(raw: str) -> str:
    """proxy_url（URL 编码）或裸 12 位 mapping_id → mapping_id。无法解析 → 400。"""
    value = unquote(raw)
    if re.fullmatch(r"[A-Za-z0-9]{12}", value):
        return value
    path = urlparse(value).path
    matched = _PROXY_PATH_RE.match(path)
    if not matched:
        raise AppError(400, "INVALID_PARAM", "无法解析为本服务代理地址")
    return matched.group(1)


def _registered_out(settings: Settings, data: dict) -> RegisteredOut:
    return RegisteredOut(
        mapping_id=data["mapping_id"], name=data.get("name"), type=data["type"],
        visibility=data["visibility"],
        proxy_url=build_proxy_url(settings, data["mapping_id"], data["upstream_url"], data["type"]),
        headers=placeholder.mask_headers(data["upstream_headers"]), status=data["status"])


def _detail_out(settings: Settings, data: dict) -> MappingDetailOut:
    base = _registered_out(settings, data).model_dump()
    base.update(upstream_url=data["upstream_url"], test_request=data.get("test_request"),
                created_at=data.get("created_at"), updated_at=data.get("updated_at"))
    return MappingDetailOut(**base)


# 注意：静态路由 /resolve 必须先于动态路由 /{mapping_id} 注册（FastAPI 按注册顺序匹配）。
@router.get("/resolve", response_model=MappingDetailOut)
async def resolve_mapping(request: Request, proxy_url: str = Query(...),
                          identity: Identity = Depends(get_current_identity),
                          session=Depends(get_db), settings: Settings = Depends(get_settings)):
    mapping_id = parse_proxy_url(proxy_url)
    data = await get_owned(session, request.app.state.redis, mapping_id,
                           identity.user_id, settings.cache_ttl)
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.audit_action = "view_credentials"
    request.state.mapping_id = data["mapping_id"]
    return _detail_out(settings, data)


@router.post("", status_code=201, response_model=RegisteredOut)
async def create_mapping_route(request: Request, body: MappingCreate,
                               identity: Identity = Depends(get_current_identity),
                               session=Depends(get_db),
                               settings: Settings = Depends(get_settings)):
    if body.visibility == "public" and not is_admin(identity, settings.admin_role):
        raise AppError(403, "FORBIDDEN", "仅管理员可创建 public 映射")
    try:
        row = await create_mapping(
            session, request.app.state.redis, settings, identity.user_id,
            type_=body.type, name=body.name, visibility=body.visibility,
            upstream_url=body.upstream_url, headers=body.headers,
            test_request=body.test_request)
    except ValueError as exc:
        raise AppError(400, "INVALID_PARAM", str(exc))
    except UpstreamNotAllowed as exc:
        raise AppError(400, "INVALID_PARAM", str(exc))
    request.state.mapping_id = row.mapping_id
    return _registered_out(settings, row_to_dict(row))


@router.get("", response_model=list[ListItemOut])
async def list_my_mappings(request: Request,
                           identity: Identity = Depends(get_current_identity),
                           session=Depends(get_db), settings: Settings = Depends(get_settings),
                           page: int = Query(1, ge=1), page_size: int = Query(20, le=100)):
    rows = await list_mappings(session, identity.user_id,
                               limit=page_size, offset=(page - 1) * page_size)
    return [ListItemOut(mapping_id=r.mapping_id, name=r.name, type=r.type,
                        upstream_url=r.upstream_url,
                        proxy_url=build_proxy_url(settings, r.mapping_id, r.upstream_url, r.type),
                        status=r.status,
                        created_at=r.created_at.isoformat() if r.created_at else None,
                        updated_at=r.updated_at.isoformat() if r.updated_at else None)
            for r in rows]


@router.get("/{mapping_id}", response_model=MappingDetailOut)
async def get_detail(request: Request, mapping_id: str,
                     identity: Identity = Depends(get_current_identity),
                     session=Depends(get_db), settings: Settings = Depends(get_settings)):
    data = await get_owned(session, request.app.state.redis, mapping_id,
                           identity.user_id, settings.cache_ttl)
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.audit_action = "view_credentials"
    request.state.mapping_id = data["mapping_id"]
    return _detail_out(settings, data)


@router.put("/{mapping_id}", response_model=RegisteredOut)
async def update_mapping_route(request: Request, mapping_id: str, body: MappingUpdate,
                               identity: Identity = Depends(get_current_identity),
                               session=Depends(get_db),
                               settings: Settings = Depends(get_settings)):
    if body.visibility == "public" and not is_admin(identity, settings.admin_role):
        raise AppError(403, "FORBIDDEN", "仅管理员可设置 public 可见性")
    patch = body.model_dump(exclude_unset=False)
    try:
        data = await update_mapping(session, request.app.state.redis, settings,
                                    mapping_id, identity.user_id, patch)
    except ValueError as exc:
        raise AppError(400, "INVALID_PARAM", str(exc))
    except UpstreamNotAllowed as exc:
        raise AppError(400, "INVALID_PARAM", str(exc))
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.mapping_id = data["mapping_id"]
    return _registered_out(settings, data)


@router.delete("/{mapping_id}", status_code=204)
async def delete_mapping_route(request: Request, mapping_id: str,
                               identity: Identity = Depends(get_current_identity),
                               session=Depends(get_db)):
    ok = await delete_mapping(session, request.app.state.redis, mapping_id, identity.user_id)
    if not ok:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.mapping_id = mapping_id
    return Response(status_code=204)
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_mgmt_api.py -v`
Expected: 13 PASS

- [ ] **Step 5: 全量回归**

Run: `.venv/Scripts/python.exe -m pytest -v`
Expected: 全部 PASS（此前所有任务无回归）

- [ ] **Step 6: Commit**

```bash
git add src/agent_proxy/api/mgmt.py tests/integration/test_mgmt_api.py
git commit -m "feat(M1): 管理接口全量（注册/列表/详情/resolve/更新/删除，权限与404隐藏语义）"
```

---

### Task 11: 审计日志与追踪日志接入验证

**Files:**
- Create: `tests/integration/test_audit.py`

- [ ] **Step 1: 写失败测试**

`tests/integration/test_audit.py`:

```python
import json

from tests.conftest import make_token

BODY = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}


def _last_audit_line():
    from agent_proxy.logging_setup import flush_trace
    flush_trace()
    with open("logs-test/audit.log", encoding="utf-8") as fh:
        lines = [x for x in fh.read().splitlines() if x.strip()]
    return json.loads(lines[-1])


async def test_audit_has_identity_and_request_id(client):
    headers = {"Authorization": f"Bearer {make_token('u888')}"}
    resp = await client.post("/api/v1/mappings", json=BODY, headers=headers)
    assert resp.status_code == 201
    entry = _last_audit_line()
    assert entry["user_id"] == "u888" and entry["user_name"] == "张三"
    assert entry["request_id"] == resp.headers["x-request-id"]
    assert entry["action"] == "mgmt" and entry["status"] == 201


async def test_view_credentials_audited(client):
    created = (await client.post("/api/v1/mappings", json=BODY,
                                 headers={"Authorization": f"Bearer {make_token('u888')}"})).json()
    mid = created["mapping_id"]
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    entry = _last_audit_line()
    assert entry["action"] == "view_credentials" and entry["mapping_id"] == mid


async def test_audit_never_contains_header_values(client):
    body = {**BODY, "headers": {"Authorization": "Bearer sk-super-secret-value"}}
    await client.post("/api/v1/mappings", json=body,
                      headers={"Authorization": f"Bearer {make_token('u888')}"})
    with open("logs-test/audit.log", encoding="utf-8") as fh:
        content = fh.read()
    assert "sk-super-secret-value" not in content
```

- [ ] **Step 2: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_audit.py -v`
Expected: 3 PASS（审计在 Task 5 中间件已实现，此处为行为验证；若 FAIL 按失败信息修正 middleware）

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_audit.py
git commit -m "test(M1): 审计行为验证（身份/request_id/view_credentials/敏感值不落盘）"
```

---

### Task 12: 手动验收（真实进程）+ README 骨架

**Files:**
- Create: `src/agent_proxy/__main__.py`
- Create: `README.md`

- [ ] **Step 1: 写入口 __main__.py**

```python
"""入口：python -m agent_proxy（读取 .env 后启动 uvicorn）。"""
from __future__ import annotations

import uvicorn

from .config import Settings, load_dotenv_file
from .main import create_app


def main() -> None:
    load_dotenv_file(".env")
    settings = Settings.from_env()
    host, _, port = settings.listen.rpartition(":")
    app = create_app(settings)
    uvicorn.run(app, host=host or "0.0.0.0", port=int(port or 8800), log_config=None)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: 启动真实进程并 curl 验收**

```bash
cd d:/git/agent-proxy && ./.venv/Scripts/python.exe -m agent_proxy
```

另开终端（Git Bash）逐条验证（命令与预期）：

```bash
# 1) 健康与就绪
curl -s http://127.0.0.1:8800/healthz            # {"status":"ok"}
curl -s http://127.0.0.1:8800/readyz             # {"status":"ready"}

# 2) 注册（stub token：user_id=u888）
TOKEN=$(./.venv/Scripts/python.exe - <<'EOF'
import base64, json
print("stub." + base64.urlsafe_b64encode(json.dumps({"user_id":"u888","user_name":"张三"}).encode()).decode().rstrip("=") + ".sig")
EOF
)
curl -s -X POST http://127.0.0.1:8800/api/v1/mappings \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"type":"http","upstream_url":"http://10.0.0.5/api/v1","headers":{"Authorization":"Bearer sk-real-key"}}'
# 预期 201：headers 值为 ${PX:Authorization}，proxy_url=http://127.0.0.1:8800/p/{12位ID}

# 3) 列表（无 headers 字段）、详情（真实值）、resolve、PUT、DELETE 同计划 Task 10 用例
# 4) /metrics 包含 ap_requests_total；logs/ 下出现 agent-proxy.log / audit.log / trace.log
```

预期：全部与集成测试一致。验收完成后 `Ctrl+C` 停止，删除 logs/（不入库）。

- [ ] **Step 3: 写 README.md 骨架**

```markdown
# agent-proxy

Agent 平台对外 MCP / HTTP 出站代理：真实地址与凭据只存代理侧，Agent 仅持有代理地址与占位符 header。

- 设计文档：`docs/superpowers/specs/2026-11-21-agent-proxy-design.md`
- 实施计划：`docs/superpowers/plans/`

## 快速开始

```bash
D:/Python312/python.exe -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]" -i https://pypi.tuna.tsinghua.edu.cn/simple
cp .env.example .env   # 按环境修改
python -m agent_proxy  # 读取 .env 启动
```

## 测试

```bash
.venv/Scripts/python.exe -m pytest -v   # 需本地 MySQL(root/123456) 与 Redis(6379)
```

## 接口速览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST/GET/PUT/DELETE | /api/v1/mappings[/{id}] | 映射 CRUD（JWT） |
| GET | /api/v1/mappings/resolve?proxy_url= | 按代理地址回显真实配置 |
| ANY | /p/{mapping_id}/{path} | 代理转发（M2 起） |
| GET | /healthz /readyz /metrics | 运维端点 |
```

- [ ] **Step 4: 全量测试回归**

Run: `.venv/Scripts/python.exe -m pytest -v`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/__main__.py README.md
git commit -m "feat(M1): python -m agent_proxy 入口 + README 骨架（M1 完成）"
```

---

## M1 验收清单（对照设计文档 §16）

- [ ] 注册返回代理地址与占位符 header（test_create_returns_masked_headers_and_proxy_url）
- [ ] 缓存读写与失效正确（test_create_and_load_cache_roundtrip / test_update_invalidates_cache / Redis 停机降级为 cache.py try/except 设计）
- [ ] stub 解码 user_id/user_name/role 生效（test_stub_verify_ok + 全部 API 鉴权用例）
- [ ] /metrics 可抓取（test_metrics_exposes_counters）
- [ ] trace 三模式与指纹打码生效（test_trace.py 六用例）
- [ ] 审计不含敏感值（test_audit_never_contains_header_values）
- [ ] M1 不含：/p/* 转发、test 接口、OAuth、管理页面（M2–M7 交付）
