# M2 实施计划：HTTP 前缀流式转发 + test 接口 + 真实 echo 上游代理测试

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 agent-proxy M2：`ANY /p/{mapping_id}/{path}` HTTP 前缀流式转发（出站 header 重建、流式不驻留、同源重定向内部跟随、413/502/504/503 错误映射）、`POST /api/v1/mappings/{id}/test`（http 连通/严格验证），以及真实 echo 上游（uvicorn 真实监听）经真实 TCP 的端到端代理测试；同时关闭 M1 终审确认的四项债务（trace query 脱敏、审计/metrics bytes、直方图桶、resolve netloc 加固）。

**Architecture:** 延续 M1 分层 `api → services → forward → infra`。新增 `headers.py`（出站 header 重建/hop-by-hop 过滤）、`forward/http_forward.py`（路径分发 + 流式转发管线）、`api/proxy.py`（代理路由）。lifespan 创建全局共享 `httpx.AsyncClient`（连接池上限/超时配置，停机 aclose）。测试经 `uvicorn.Server` 在 127.0.0.1:9901 真实监听的 echo 上游走真实 TCP。

**Tech Stack:** Python 3.12（venv `.venv`）、FastAPI、httpx 0.28（异步流式）、SQLAlchemy 2 async、redis 4.x、prometheus-client、uvicorn（既作服务入口也作测试上游）、pytest + pytest-asyncio（asyncio_mode=auto）。无新增依赖。

**对应设计文档:** §6.2 代理端点、§6.6 test 接口、§8.1 通用规则（header 重建/流式/超时/重定向/路径安全/连接池/缓冲）、§8.2 HTTP 前缀映射、§8.5 与 http 的差异、§9 安全、§10 错误、§11.1 追踪日志、§13 测试策略、§16 M2 验收。

**范围说明:** 本计划只覆盖 M2；MCP SSE / Streamable（M3/M4）、OAuth 公共映射（M6）、管理页面（M7）不在本计划内。M2 阶段 `visibility=public` 的用户映射不存在，但鉴权语义按设计 §14.2 实现（private → uid=owner 否则 403；public → 任意有效身份放行），M6 直接复用。

**约定（延续 M1）:** 测试令牌 `stub.<base64url(payload)>.sig`；测试库 `agent_proxy_test` + Redis db9、`SSRF_ALLOW_PRIVATE=true`、`EXTERNAL_BASE=http://testserver`。基线 101 passed 全绿为出发点。

**关键决策（实现前先读）：**

1. **请求体流式 + Content-Length**：请求体经字节计数 async 生成器透传（超限抛 413）。httpx 对「iterator content + 显式 Content-Length」会保留 content-length 头且不加 chunked（已在本仓 venv 验证），因此入站 Content-Length 白名单透传后分帧正确；入站既无 Content-Length 也无 Transfer-Encoding（如无 body 的 GET）则 `content=None`，避免对 GET 发空 chunked body。
2. **httpx 异常映射**（已验证继承链 `PoolTimeout ⊂ TimeoutException ⊂ TransportError ⊂ HTTPError`）：`PoolTimeout → 503 PROXY_BUSY`（必须先于 TimeoutException 捕获）、其余 `TimeoutException → 504 UPSTREAM_TIMEOUT`、其余 `HTTPError → 502 UPSTREAM_ERROR`。请求体生成器抛出的 413 AppError 原样上抛（响应未开始，可回标准错误体）。
3. **重定向**：`follow_redirects=False`，转发层手动跟随。同源判定 = 与**注册 upstream_url 的 origin** 比较（非逐跳 target）。跳间存储 header 每跳重放；**已知限制：首跳 body 已流式消耗，重定向跳不重放 body**（303 转发方法已降为 GET，307/308 保方法但 body 为空——设计 §8.1 第 7 条未要求 body 重放，M2 接受并注释）。跟随跳不再带 content-length（长度已不可信）。
4. **trace 与流式的兼容**：metadata 模式在发起上游调用后即记 request 行（body_bytes 用事后计数值，`trace.log_request` 增加 `body_bytes` 可选参数）；body 模式经 `trace.capture_limit()` 在请求/响应生成器内 tee 捕获前缀（≤64KB，有界），流结束后记 request/response 行。
5. **测试上游端口**：echo 上游固定 127.0.0.1:9901（session 夹具启动一次）；9902 为「不存在的端口」，专用于跨源重定向透传与 test 接口「上游不可达」用例。

---

## 文件结构（M2 变更后）

```
agent-proxy/
├── docs/superpowers/plans/
│   └── 2026-11-24-m2-http-forward.md        # 本计划
├── src/agent_proxy/
│   ├── main.py                              # [改] lifespan 建 app.state.http_client；挂 proxy router
│   ├── config.py                            # （不变，M1 已有全部上游配置项）
│   ├── headers.py                           # [新] 出站 header 重建 / hop-by-hop 过滤
│   ├── trace.py                             # [改] redact_query（query 值脱敏）；log_request 加 body_bytes；capture_limit()
│   ├── metrics.py                           # [改] 直方图自定义 buckets（终审债务）
│   ├── middleware.py                        # [改] bytes_in/out 计数 → 审计字段 + ap_bytes_total
│   ├── api/
│   │   ├── mgmt.py                          # [改] parse_proxy_url netloc 加固；POST /{id}/test
│   │   └── proxy.py                         # [新] ANY /p/{mapping_id}[/{path}] 转发入口
│   ├── forward/
│   │   ├── __init__.py                      # [新] 转发领域包
│   │   └── http_forward.py                  # [新] 纯函数（拼接/路径安全）+ 流式转发 + http test 探测
│   └── schemas.py                           # [改] MappingTestOut
├── tests/
│   ├── conftest.py                          # [改] MAX_BODY_SIZE=1MB（413 用例）
│   ├── unit/
│   │   ├── test_headers.py                  # [新] header 重建/过滤
│   │   ├── test_http_forward.py             # [新] 纯函数：拼接/路径分发/dot-segment
│   │   └── test_trace.py                    # [改] redact_query 用例
│   └── integration/
│       ├── mock_upstream.py                 # [新] echo 上游应用（回显/大响应/慢/重定向/状态码）
│       ├── conftest.py                      # [改] real_upstream_server 夹具（uvicorn 9901，session 级）
│       ├── test_echo_upstream.py            # [新] 真实 TCP 冒烟
│       ├── test_proxy_http.py               # [新] 端到端代理全链路（真实 TCP）
│       ├── test_mgmt_test_endpoint.py       # [新] test 接口
│       ├── test_proxy_trace.py              # [新] body 模式 trace 集成（query 脱敏）
│       ├── test_health.py                   # [改] 自定义桶/bytes 指标
│       └── test_audit.py                    # [改] 审计 bytes_in/out
└── README.md                                # [改] /p/ 行更新（M2 已支持 http 转发）
```

---

### Task 1: headers.py——出站 header 重建与 hop-by-hop 过滤

**Files:**
- Create: `src/agent_proxy/headers.py`
- Create: `tests/unit/test_headers.py`

- [ ] **Step 1: 写失败测试**

`tests/unit/test_headers.py`:

```python
"""出站 header 重建（安全核心）单测：存储全量 + 协议白名单；调用方其余 header 一律不透传。"""
from agent_proxy.headers import build_outbound_headers, filter_response_headers, is_hop_by_hop


def test_stored_full_plus_whitelist_caller_jwt_not_forwarded():
    out = build_outbound_headers(
        {"Authorization": "Bearer sk-real-12345678", "X-User-Id": "u888"},
        {"Authorization": "Bearer caller-system-jwt", "Accept": "application/json",
         "X-Caller-Only": "should-not-leak", "User-Agent": "agent/1.0",
         "Cookie": "sid=abc"},
        content_type="application/json", content_length="11", content_encoding=None)
    assert out["Authorization"] == "Bearer sk-real-12345678"      # 存储还原（调用方 JWT 被丢弃）
    assert out["X-User-Id"] == "u888"
    assert out["Accept"] == "application/json"                    # 白名单透传
    assert out["Content-Type"] == "application/json"
    assert out["Content-Length"] == "11"
    assert "X-Caller-Only" not in out and "User-Agent" not in out and "Cookie" not in out


def test_explicit_body_params_override_caller_values():
    out = build_outbound_headers({}, {"Content-Type": "text/plain"},
                                 content_type="application/gzip",
                                 content_length="7", content_encoding="gzip")
    assert out["Content-Type"] == "application/gzip"
    assert out["Content-Length"] == "7"
    assert out["Content-Encoding"] == "gzip"


def test_mcp_protocol_headers_whitelisted():
    out = build_outbound_headers(
        {}, {"Mcp-Session-Id": "s-001", "Last-Event-ID": "42",
             "MCP-Protocol-Version": "2025-06-18", "X-Other": "no"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"Mcp-Session-Id": "s-001", "Last-Event-ID": "42",
                   "MCP-Protocol-Version": "2025-06-18"}


def test_hop_by_hop_stripped_from_both_sides():
    out = build_outbound_headers(
        {"Connection": "close", "Keep-Alive": "timeout=5", "X-Keep": "v"},
        {"Transfer-Encoding": "chunked", "Te": "trailers", "Upgrade": "websocket",
         "Proxy-Authorization": "Basic x", "Proxy-Note": "n"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"X-Keep": "v"}          # 两侧 hop-by-hop 全部剥离，仅剩普通头
    assert is_hop_by_hop("Proxy-Foo")       # Proxy-* 前缀兜底


def test_empty_inputs_minimal():
    assert build_outbound_headers({}, {}, None, None, None) == {}


def test_filter_response_headers_strips_hop_by_hop():
    out = filter_response_headers({
        "Content-Type": "application/json", "Content-Length": "3",
        "Set-Cookie": "a=1", "X-Custom": "v",
        "Connection": "close", "Keep-Alive": "x", "Transfer-Encoding": "chunked",
        "Trailer": "x", "Proxy-Foo": "bar",
    })
    assert out == {"Content-Type": "application/json", "Content-Length": "3",
                   "Set-Cookie": "a=1", "X-Custom": "v"}


def test_filter_response_headers_empty():
    assert filter_response_headers({}) == {}
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_headers.py -v`
Expected: FAIL（ModuleNotFoundError: agent_proxy.headers）

- [ ] **Step 3: 实现 headers.py**

`src/agent_proxy/headers.py`:

```python
"""出站 header 重建（安全核心）与响应 header 过滤（设计 §8.1 第 1/3 条）。

出站 = 存储 upstream_headers 全量 + 协议白名单（Accept / Content-* / Content-Encoding /
MCP 三头，从 caller 提取）；调用方其余 header（JWT / 占位 header / 浏览器指纹）一律不透传；
hop-by-hop 双向剥离。响应 header 剥离 hop-by-hop 后原样回传，绝不含存储的真实 header。
"""
from __future__ import annotations

import typing

# hop-by-hop（RFC 9110 §7.6.1 + 设计 §8.1：Connection/Keep-Alive/TE/Trailer/
# Transfer-Encoding/Upgrade；Proxy-* 前缀统一剥离）
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}

# 协议必要白名单：http body/Accept 透传必需 + MCP 会话/流/版本头（M3/M4 使用，白名单现在建全）
PROTOCOL_ALLOWED_HEADERS = {
    "accept", "content-type", "content-length", "content-encoding",
    "mcp-session-id", "last-event-id", "mcp-protocol-version",
}


def is_hop_by_hop(name: str) -> bool:
    lowered = name.lower()
    return lowered in HOP_BY_HOP_HEADERS or lowered.startswith("proxy-")


def build_outbound_headers(stored_headers: dict[str, str] | None,
                           caller_headers: typing.Mapping[str, str] | None,
                           content_type: str | None, content_length: str | None,
                           content_encoding: str | None) -> dict[str, str]:
    """出站 header：存储全量打底 + 协议白名单从 caller 提取（同名覆盖，白名单头描述本次载荷）。

    content_type / content_length / content_encoding 为入站请求三个 body 相关头的
    显式值（None = 入站未携带），优先级高于 caller_headers 中的同名白名单项。
    """
    outbound: dict[str, str] = {k: v for k, v in (stored_headers or {}).items()
                                if not is_hop_by_hop(k)}
    caller = {k: v for k, v in (caller_headers or {}).items()
              if k.lower() in PROTOCOL_ALLOWED_HEADERS and not is_hop_by_hop(k)}
    explicit = {"Content-Type": content_type, "Content-Length": content_length,
                "Content-Encoding": content_encoding}
    for name, value in explicit.items():
        if value is not None:
            caller[name] = value
    outbound.update(caller)
    return outbound


def filter_response_headers(resp_headers: typing.Mapping[str, str]) -> dict[str, str]:
    """响应 header 剥离 hop-by-hop 后原样回传（含 Content-Type 等；绝不注入存储真实 header）。"""
    return {k: v for k, v in resp_headers.items() if not is_hop_by_hop(k)}
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_headers.py -v`
Expected: 7 PASS

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/headers.py tests/unit/test_headers.py
git commit -m "feat(M2): 出站 header 重建 headers.py（存储全量+协议白名单，hop-by-hop 双向剥离）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 2: 终审债务（一）——metrics 直方图桶 + bytes 计数 + trace query 脱敏

**Files:**
- Modify: `src/agent_proxy/metrics.py`
- Modify: `src/agent_proxy/middleware.py`
- Modify: `src/agent_proxy/trace.py`
- Modify: `tests/unit/test_trace.py`
- Modify: `tests/integration/test_health.py`
- Modify: `tests/integration/test_audit.py`

- [ ] **Step 1: 写失败测试（单测：trace query 脱敏；集成：桶/bytes/审计字段）**

`tests/unit/test_trace.py` 末尾追加：

```python
def test_redact_query_masks_values_keeps_keys():
    out = trace.redact_query("http://x/api?session_id=abcdef12345678&status=paid")
    assert out == "http://x/api?session_id=abcd****5678(len=14)&status=****(len=4)"
    assert "abcdef12345678" not in out


def test_redact_query_no_query_unchanged():
    assert trace.redact_query("http://x/api/v1/orders") == "http://x/api/v1/orders"


def test_log_request_redacts_url_query(tmp_path):
    path = _capture(tmp_path, "metadata")
    trace.log_request("r1", "u1", "m1", "GET",
                      "http://x/api?access_token=secret-token-value", {})
    recs = _read(path)
    assert "secret-token-value" not in json.dumps(recs)
    assert "access_token=" in recs[0]["url"]  # 键名保留，值指纹化
```

`tests/integration/test_health.py` 末尾追加：

```python
async def test_metrics_custom_buckets_and_bytes(client):
    await client.get("/healthz")
    resp = await client.get("/metrics")
    text = resp.text
    assert 'le="0.005"' in text and 'le="300.0"' in text  # 自定义直方图桶（终审债务）
    assert "ap_bytes_total" in text                        # bytes 指标已注册
```

`tests/integration/test_audit.py` 末尾追加：

```python
async def test_audit_records_bytes_in_out(client):
    resp = await client.post("/api/v1/mappings", json=BODY,
                             headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 201
    entry = _find_audit_entry(resp.headers["x-request-id"])
    assert entry["bytes_in"] > 0   # 请求体（JSON）被应用实际读取
    assert entry["bytes_out"] > 0  # 响应体实际发送字节数
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_trace.py tests/integration/test_health.py tests/integration/test_audit.py -v`
Expected: 新增 5 条 FAIL（redact_query 不存在；le="0.005"/ap_bytes_total/bytes_in 缺失），其余原用例 PASS

- [ ] **Step 3: 实现 metrics.py / trace.py / middleware.py**

`src/agent_proxy/metrics.py` 整体替换为：

```python
"""Prometheus 指标定义（标签仅低基数维度，不放 user_id/mapping_id）。"""
from prometheus_client import Counter, Gauge, Histogram

# 直方图桶（终审债务）：prometheus 默认桶对亚毫秒与长耗时（SSE/慢上游）分辨率不足，
# 自定义桶覆盖 5ms ~ 5min（设计 §15.2 / §8.1 第 5 条超时上界 60s、SSE 长连接）
DURATION_BUCKETS = (0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300)

requests_total = Counter("ap_requests_total", "HTTP 请求总数", ["route", "type", "status"])
request_duration = Histogram("ap_request_duration_seconds", "端到端延迟", ["route", "type"],
                             buckets=DURATION_BUCKETS)
upstream_duration = Histogram("ap_upstream_duration_seconds", "上游耗时", ["type"],
                              buckets=DURATION_BUCKETS)
upstream_errors_total = Counter("ap_upstream_errors_total", "上游失败计数", ["type", "code"])
bytes_total = Counter("ap_bytes_total", "上下行字节数", ["direction"])
sse_active = Gauge("ap_sse_active_connections", "SSE 活跃长连接数（M3+ 使用）")
inflight = Gauge("ap_inflight_requests", "在途请求数")
oauth_actions_total = Counter("ap_oauth_actions_total", "OAuth 凭证事件（M6 使用）", ["action"])
```

`src/agent_proxy/trace.py` 两处修改——import 区追加 `urlparse` 相关并在 `fingerprint` 之后新增 `redact_query`，`log_request` 的 url 改为脱敏后写入：

```python
# import 区（文件头部现有 import 之后）追加：
from urllib.parse import parse_qsl, urlparse, urlunparse
```

```python
def redact_query(url: str) -> str:
    """URL query 值脱敏（终审债务 #3）：保留键名，值统一指纹化。

    query 常携带 token / session_id 等敏感参数，与 header 同等对待（安全底线）。
    """
    parsed = urlparse(url)
    if not parsed.query:
        return url
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    redacted = "&".join(f"{key}={fingerprint(value)}" for key, value in pairs)
    return urlunparse(parsed._replace(query=redacted))
```

`log_request` 内 record 一行修改（其余不变）：

```python
        "phase": "request", "method": method, "url": redact_query(url),
```

`src/agent_proxy/middleware.py` 整体替换为（新增 bytes_in/out 计数 → 审计字段 + ap_bytes_total）：

```python
"""中间件：request_id 生成与 X-Request-ID 回传、Prometheus 埋点（含 bytes）、审计日志。"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone

from starlette.types import ASGIApp, Message, Receive, Scope, Send

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
        bytes_in = 0   # 请求体字节数（应用实际读取到的；流式分片累计）
        bytes_out = 0  # 响应体字节数（实际发送的，StreamingResponse 分片累计）
        metrics.inflight.inc()

        async def receive_wrapper() -> Message:
            nonlocal bytes_in
            message = await receive()
            if message["type"] == "http.request":
                bytes_in += len(message.get("body", b""))
            return message

        async def send_wrapper(message: Message) -> None:
            nonlocal bytes_out
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = message.setdefault("headers", [])
                if not any(k.lower() == b"x-request-id" for k, _ in headers):
                    headers.append((b"x-request-id", request_id.encode()))
            elif message["type"] == "http.response.body":
                bytes_out += len(message.get("body", b""))
            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            metrics.inflight.dec()
            status = status_holder["status"] or 500
            t = _type_of(route)
            metrics.requests_total.labels(route=route, type=t, status=str(status)).inc()
            metrics.request_duration.labels(route=route, type=t).observe(duration_ms / 1000)
            if bytes_in:
                metrics.bytes_total.labels(direction="in").inc(bytes_in)
            if bytes_out:
                metrics.bytes_total.labels(direction="out").inc(bytes_out)
            if method != "OPTIONS" and route != "ops":  # 运维端点不记审计（设计 §6.2/§15.2）
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
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "client_ip": (scope.get("client") or ("",))[0],
                }, ensure_ascii=False))
```

- [ ] **Step 4: 运行确认通过 + 全量回归**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_trace.py tests/integration/test_health.py tests/integration/test_audit.py -v`
Expected: 新增 5 条 PASS，原用例无回归

Run: `.venv/Scripts/python.exe -m pytest`
Expected: 113 passed（基线 101 + Task 1 新增 7 + 本任务新增 5）

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/metrics.py src/agent_proxy/middleware.py src/agent_proxy/trace.py tests/unit/test_trace.py tests/integration/test_health.py tests/integration/test_audit.py
git commit -m "feat(M2): 终审债务——直方图自定义桶 + bytes_in/out 计数（审计/bytes_total）+ trace query 脱敏" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 3: forward 纯函数（URL 拼接 / dot-segment 拒绝）+ resolve netloc 加固

**Files:**
- Create: `src/agent_proxy/forward/__init__.py`
- Create: `src/agent_proxy/forward/http_forward.py`（本 Task 只含纯函数）
- Create: `tests/unit/test_http_forward.py`
- Modify: `src/agent_proxy/api/mgmt.py`（parse_proxy_url 加固）
- Modify: `tests/integration/test_mgmt_api.py`

- [ ] **Step 1: 写失败测试（纯函数单测 + resolve 越权 host 集成用例）**

`tests/unit/test_http_forward.py`:

```python
"""forward 纯函数单测：前缀拼接（§8.2）、子路径分发、dot-segment 拒绝（§8.1 第 8 条）。"""
import pytest

from agent_proxy.errors import AppError
from agent_proxy.forward.http_forward import (assert_safe_sub_path, build_forward_target,
                                              split_sub_path)


def test_build_target_prefix_join():
    assert build_forward_target("http://bobo.com/api/v1", "/orders", "status=paid") \
        == "http://bobo.com/api/v1/orders?status=paid"


def test_build_target_deep_path_and_trailing_slash_normalized():
    assert build_forward_target("http://bobo.com/api/v1/", "/a/b/c", "") \
        == "http://bobo.com/api/v1/a/b/c"


def test_build_target_empty_sub_path_direct_to_registered_url():
    assert build_forward_target("http://bobo.com/api/v1", "", "") == "http://bobo.com/api/v1"


@pytest.mark.parametrize("bad", ["/..", "/../etc", "/a/..", "/.", "/a/./b",
                                 "/%2e%2e", "/a/%2E%2E/b", "/%252e"])
def test_assert_safe_sub_path_rejects_dot_segments(bad):
    with pytest.raises(AppError) as ei:
        assert_safe_sub_path(bad)
    assert ei.value.status == 400 and ei.value.code == "INVALID_PARAM"


@pytest.mark.parametrize("ok", ["", "/", "/orders", "/orders/123", "/a-b.c_d", "/%E4%B8%AD"])
def test_assert_safe_sub_path_allows_normal_paths(ok):
    assert_safe_sub_path(ok)


def test_split_sub_path_basic():
    assert split_sub_path("/p/aB3xK9mQ2wR4/orders", "aB3xK9mQ2wR4") == "/orders"


def test_split_sub_path_empty_root():
    assert split_sub_path("/p/aB3xK9mQ2wR4", "aB3xK9mQ2wR4") == ""


def test_split_sub_path_prefix_mismatch_400():
    with pytest.raises(AppError) as ei:
        split_sub_path("/other/orders", "aB3xK9mQ2wR4")
    assert ei.value.status == 400
```

`tests/integration/test_mgmt_api.py` 末尾追加：

```python
async def test_resolve_rejects_foreign_netloc(client):
    """终审债务：带 netloc 的 proxy_url，host 必须等于 EXTERNAL_BASE 的 host。"""
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.get(
        f"/api/v1/mappings/resolve?proxy_url=http%3A%2F%2Fevil.example.com%2Fp%2F{mid}",
        headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"
    # 本服务 host 正常回显（EXTERNAL_BASE=http://testserver，既有用例已覆盖 200）
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_http_forward.py tests/integration/test_mgmt_api.py::test_resolve_rejects_foreign_netloc -v`
Expected: FAIL（ModuleNotFoundError: agent_proxy.forward；foreign netloc 用例返回 200）

- [ ] **Step 3: 实现 forward 包与纯函数**

`src/agent_proxy/forward/__init__.py`:

```python
"""转发领域能力（M2：HTTP 前缀流式转发；M3/M4：MCP SSE / Streamable）。"""
```

`src/agent_proxy/forward/http_forward.py`（本 Task 版本，仅纯函数；Task 5 填充流式转发）:

```python
"""HTTP 前缀流式转发（设计 §8.1 / §8.2）。

本模块职责：路径分发（dot-segment 拒绝）→ URL 拼接 → 出站 header 重建 →
httpx 流式转发（请求体字节计数限流）→ 同源重定向内部跟随 → 响应 hop-by-hop
过滤流式回传。全程不整体缓冲；trace / metrics / 审计全接线。
"""
from __future__ import annotations

from urllib.parse import unquote

from ..errors import AppError


def split_sub_path(full_path: str, mapping_id: str) -> str:
    """/p/{id} 之后的子路径（含前导 /；可为空串）。前缀不匹配 → 400。"""
    prefix = f"/p/{mapping_id}"
    if not full_path.startswith(prefix):
        raise AppError(400, "INVALID_PARAM", "路径与映射不匹配")
    return full_path[len(prefix):]


def _seg_is_dot_segment(seg: str) -> bool:
    # 两层解码：覆盖 %2e（一层编码）与 %252e（两层双重编码）变体
    cur = seg
    for _ in range(2):
        cur = unquote(cur)
        if cur.lower() in (".", ".."):
            return True
    return False


def assert_safe_sub_path(sub_path: str) -> None:
    """拒绝 dot-segment 及 URL 编码变体（设计 §8.1 第 8 条）——防止拼接后逃逸注册前缀。"""
    for seg in sub_path.split("/"):
        if seg and _seg_is_dot_segment(seg):
            raise AppError(400, "INVALID_PARAM", "代理子路径含非法 dot-segment")


def build_forward_target(upstream_url: str, sub_path: str, query: str) -> str:
    """转发URL = upstream_url(规范化去尾斜杠) + /子路径 [+ ?query]（设计 §8.2）。

    子路径为空时直达注册 URL；query 为调用方原始 query 串（不重编码，透传）。
    """
    base = upstream_url.rstrip("/")
    trimmed = sub_path.lstrip("/")
    target = f"{base}/{trimmed}" if trimmed else base
    return f"{target}?{query}" if query else target
```

`src/agent_proxy/api/mgmt.py`：`parse_proxy_url` 整体替换（新增 external_base 参数与 host 校验），并更新 resolve 路由调用点：

```python
def parse_proxy_url(raw: str, external_base: str = "") -> str:
    """proxy_url（URL 编码）或裸 12 位 mapping_id → mapping_id。无法解析 → 400。

    加固（终审债务）：带 netloc 的输入，host 必须等于 EXTERNAL_BASE 的 host，
    防止把任意第三方 URL 当作本服务代理地址解析（探测/混淆）。
    """
    value = unquote(raw)
    if MAPPING_ID_RE.match(value):
        return value
    parsed = urlparse(value)
    if parsed.netloc:
        base_host = urlparse(external_base).hostname if external_base else None
        if not base_host or (parsed.hostname or "") != base_host:
            raise AppError(400, "INVALID_PARAM", "代理地址 host 与本服务不符")
    matched = _PROXY_PATH_RE.match(parsed.path)
    if not matched:
        raise AppError(400, "INVALID_PARAM", "无法解析为本服务代理地址")
    return matched.group(1)
```

resolve 路由中的调用改为：

```python
    mapping_id = parse_proxy_url(proxy_url, settings.external_base)
```

- [ ] **Step 4: 运行确认通过 + 全量回归**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_http_forward.py tests/integration/test_mgmt_api.py -v`
Expected: 新增 21 条 PASS（单测 20：3 拼接 + 8 dot-segment 拒绝 + 6 放行 + 3 分发；集成 1），test_mgmt_api 原有用例无回归

Run: `.venv/Scripts/python.exe -m pytest`
Expected: 全部 PASS（134）

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/forward/ src/agent_proxy/api/mgmt.py tests/unit/test_http_forward.py tests/integration/test_mgmt_api.py
git commit -m "feat(M2): forward 纯函数（前缀拼接/dot-segment 拒绝）+ resolve netloc 加固" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 4: 真实 echo 上游（uvicorn 真实监听）+ session 夹具 + TCP 冒烟

**Files:**
- Create: `tests/integration/mock_upstream.py`
- Modify: `tests/integration/conftest.py`（追加 `real_upstream_server` 夹具）
- Create: `tests/integration/test_echo_upstream.py`

- [ ] **Step 1: 实现 echo 上游应用**

`tests/integration/mock_upstream.py`:

```python
"""真实 echo 上游（测试专用）：FastAPI 应用，经 uvicorn.Server 真实监听 127.0.0.1:9901。

用户明确要求「真实的 http 代理测试」：集成测试经代理→上游走真实 TCP，
不用 ASGI 直连伪造上游。端点能力：全路径回显 / 大响应 / 慢响应 / 状态码 /
同源重定向 / 跨源重定向（→ 9902 不存在端口）/ 重定向循环 / 307 保方法。
注意：具体端点必须定义在 /api/v1/{path:path} 回显兜底之前（先注册先匹配）。
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response


def build_echo_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/api/v1/slow")
    async def slow(seconds: float = 1.0):
        await asyncio.sleep(seconds)
        return {"woke": True}

    @app.get("/api/v1/big")
    async def big(kb: int = 1024):
        size = kb * 1024
        pattern = bytes(range(256))
        body = (pattern * (size // len(pattern) + 1))[:size]
        return Response(content=body, media_type="application/octet-stream")

    @app.get("/api/v1/status/{code}")
    async def status_code(code: int):
        return Response(content=f"upstream-status-{code}", status_code=code,
                        media_type="text/plain")

    @app.get("/api/v1/redirect/same-origin")
    async def redirect_same_origin():
        return RedirectResponse("/api/v1/final?via=redirect", status_code=302)

    @app.get("/api/v1/redirect/cross-origin")
    async def redirect_cross_origin():
        return RedirectResponse("http://127.0.0.1:9902/nowhere", status_code=302)

    @app.get("/api/v1/redirect/loop")
    async def redirect_loop():
        return RedirectResponse("/api/v1/redirect/loop", status_code=302)

    @app.post("/api/v1/redirect/307")
    async def redirect_307():
        return RedirectResponse("/api/v1/final", status_code=307)

    @app.api_route("/api/v1", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    @app.api_route("/api/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def echo(request: Request, path: str = ""):
        body = await request.body()
        return {
            "path": "/" + path,
            "method": request.method,
            "query": dict(request.query_params.multi_items()),
            "headers": dict(request.headers.items()),
            "body": body.decode("utf-8", "replace"),
            "body_bytes": len(body),
        }

    return app
```

- [ ] **Step 2: session 夹具（uvicorn.Server 真实监听）**

`tests/integration/conftest.py` 顶部 import 区追加，并在文件末尾追加夹具：

```python
import asyncio

import pytest_asyncio
import uvicorn

from tests.integration.mock_upstream import build_echo_app
```

```python
@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def real_upstream_server():
    """真实 echo 上游：uvicorn 真实监听 127.0.0.1:9901（一次启动，全集成测试共享）。

    uvicorn 生命周期挂在独立 session loop 上；测试用例各自的 function loop
    经真实 TCP 访问它（跨 loop 只过网络，无共享 asyncio 对象）。
    断言 server.started 前最多等 10s（端口被占用时快速失败）。
    """
    config = uvicorn.Config(build_echo_app(), host="127.0.0.1", port=9901,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    task = asyncio.get_running_loop().create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.05)
    assert server.started, "echo 上游启动失败（127.0.0.1:9901 被占用？）"
    yield server
    server.should_exit = True
    await task
```

- [ ] **Step 3: 写冒烟测试（真实 TCP 连通）**

`tests/integration/test_echo_upstream.py`:

```python
import httpx


async def test_echo_upstream_reachable_over_real_tcp():
    """冒烟：不经代理，直连 echo 上游，验证 9901 真实监听可用。"""
    async with httpx.AsyncClient() as c:
        resp = await c.get("http://127.0.0.1:9901/api/v1/ping")
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "GET" and echo["path"] == "/ping"


async def test_echo_upstream_post_body_echo():
    async with httpx.AsyncClient() as c:
        resp = await c.post("http://127.0.0.1:9901/api/v1/orders?x=1",
                            content=b'{"a":1}', headers={"Content-Type": "application/json"})
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "POST" and echo["body"] == '{"a":1}'
    assert echo["query"] == {"x": "1"}
```

- [ ] **Step 4: 运行确认通过**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_echo_upstream.py -v`
Expected: 2 PASS（日志出现 uvicorn 启动信息；无 9901 占用时启动 <1s）

- [ ] **Step 5: Commit**

```bash
git add tests/integration/mock_upstream.py tests/integration/conftest.py tests/integration/test_echo_upstream.py
git commit -m "test(M2): 真实 echo 上游（uvicorn 127.0.0.1:9901）+ session 夹具 + 真实 TCP 冒烟" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 5: 转发上线——lifespan http_client + api/proxy.py + stream_http_forward 基础管线

**Files:**
- Create: `src/agent_proxy/api/proxy.py`
- Modify: `src/agent_proxy/main.py`（lifespan 建 http_client；挂 proxy router）
- Modify: `src/agent_proxy/forward/http_forward.py`（填充 stream_http_forward，本 Task 无重定向跟随）
- Modify: `src/agent_proxy/trace.py`（`log_request` 加 `body_bytes` 可选参数；新增 `capture_limit`）
- Create: `tests/integration/test_proxy_http.py`（第一批）

- [ ] **Step 1: 写失败集成测试（第一批：转发回显 / 权限 / 404 / 401 / dot-segment / mcp 400）**

`tests/integration/test_proxy_http.py`:

```python
"""端到端代理测试（真实 TCP）：注册 → /p/{id}/... 转发 → echo 上游回显验证。

链路：测试 client（ASGITransport）→ 代理 app → 真实 TCP → echo 上游（uvicorn 9901）。
上游地址含 SSRF_ALLOW_PRIVATE=true 放行的 127.0.0.1（测试环境既定）。
"""
import re

from tests.utils import make_token

UPSTREAM = "http://127.0.0.1:9901/api/v1"
BODY = {"type": "http", "upstream_url": UPSTREAM,
        "headers": {"Authorization": "Bearer sk-real-12345678",
                    "X-API-Key": "stored-key-0000"}}


async def _register(client, user="u888", **overrides):
    payload = {**BODY, **overrides}
    resp = await client.post("/api/v1/mappings", json=payload,
                             headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _call(client, mapping_id, method, path, *, user="u888", headers=None, **kw):
    hdrs = {"Authorization": f"Bearer {make_token(user)}", **(headers or {})}
    return await client.request(method, f"/p/{mapping_id}{path}", headers=hdrs, **kw)


async def test_forward_get_echoes_stored_headers_not_caller(client):
    created = await _register(client)
    mid = created["mapping_id"]
    resp = await _call(client, mid, "GET", "/orders?status=paid&page=2",
                       headers={"Authorization": "Bearer caller-jwt-not-forwarded",
                                "X-Caller-Only": "should-not-leak",
                                "Accept": "application/json"})
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "GET" and echo["path"] == "/orders"
    assert echo["query"] == {"status": "paid", "page": "2"}
    sent = echo["headers"]
    assert sent["authorization"] == "Bearer sk-real-12345678"  # 存储还原
    assert sent["x-api-key"] == "stored-key-0000"
    assert "x-caller-only" not in sent                          # 调用方非白名单 header 不透传
    assert sent["accept"] == "application/json"                 # 白名单透传
    assert "stub." not in resp.text                             # 调用方 JWT 绝不到上游
    assert "${PX:" not in resp.text                             # 占位符绝不到上游


async def test_forward_root_path_hits_registered_url(client):
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "")
    assert resp.status_code == 200
    assert resp.json()["path"] == "/"  # upstream_url 直达（path 可为空，设计 §6.2）


async def test_forward_post_body_and_content_type(client):
    created = await _register(client)
    mid = created["mapping_id"]
    resp = await _call(client, mid, "POST", "/orders",
                       headers={"Content-Type": "application/json"},
                       content=b'{"item":"book","qty":2}')
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "POST"
    assert echo["body"] == '{"item":"book","qty":2}' and echo["body_bytes"] == 22
    assert echo["headers"]["content-type"] == "application/json"


async def test_forward_deep_path(client):
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/orders/42/items?limit=5")
    echo = resp.json()
    assert echo["path"] == "/orders/42/items" and echo["query"] == {"limit": "5"}


async def test_forward_upstream_404_passthrough(client):
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/status/404")
    assert resp.status_code == 404                      # 上游 4xx 原样透传（设计 §10）
    assert "upstream-status-404" in resp.text
    assert resp.headers["content-type"].startswith("text/plain")
    assert resp.headers["x-request-id"]                 # 代理自身中间件仍在


async def test_proxy_unauthenticated_401(client):
    created = await _register(client)
    resp = await client.get(f"/p/{created['mapping_id']}/orders")
    assert resp.status_code == 401 and resp.json()["code"] == "INVALID_TOKEN"


async def test_non_owner_private_403(client):
    created = await _register(client, user="u888")
    resp = await _call(client, created["mapping_id"], "GET", "/orders", user="u999")
    assert resp.status_code == 403 and resp.json()["code"] == "FORBIDDEN"


async def test_missing_mapping_404(client):
    resp = await _call(client, "aB3xK9mQ2wR4", "GET", "/orders")
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_disabled_mapping_404(client):
    created = await _register(client)
    mid = created["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"status": "disabled"},
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    resp = await _call(client, mid, "GET", "/orders")
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_mcp_mapping_forward_400(client):
    created = await _register(client, type="mcp", upstream_url="https://mcp.ex.com/sse")
    resp = await _call(client, created["mapping_id"], "GET", "/sse")
    assert resp.status_code == 400 and "M3" in resp.json()["message"]


async def test_dot_segment_sub_path_400(client):
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/%2e%2e/etc/passwd")
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_proxy_trace_metadata_wired(client, monkeypatch, tmp_path):
    """metadata 模式下 /p/ 转发写 trace request/response 行（url 含上游 target）。"""
    import glob
    import json as jsonlib

    import agent_proxy.trace as trace_mod
    from agent_proxy.logging_setup import flush_trace

    handler_target = tmp_path / "trace.log"
    import logging
    logger = logging.getLogger("agent_proxy.trace")
    saved = logger.handlers
    logger.handlers = [logging.FileHandler(handler_target, encoding="utf-8")]
    try:
        created = await _register(client)
        resp = await _call(client, created["mapping_id"], "GET", "/orders?status=paid")
        assert resp.status_code == 200
        flush_trace()
        recs = [jsonlib.loads(x) for x in
                handler_target.read_text(encoding="utf-8").splitlines() if x.strip()]
    finally:
        logger.handlers = saved
    mine = [r for r in recs if r.get("mapping_id") == created["mapping_id"]]
    req = [r for r in mine if r["phase"] == "request"]
    rsp = [r for r in mine if r["phase"] == "response"]
    assert req and rsp
    assert re.match(r"http://127\.0\.0\.1:9901/api/v1/orders\?status=", req[0]["url"])
    assert "sk-real-12345678" not in jsonlib.dumps(req[0])  # 指纹化
    assert rsp[0]["status"] == 200
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_proxy_http.py -v`
Expected: 全部 FAIL（/p/* 无路由 → 401/404 与预期不符；trace 用例无记录）

- [ ] **Step 3: 实现 lifespan http_client + trace 扩展 + api/proxy.py + stream_http_forward**

`src/agent_proxy/main.py` 整体替换为（import httpx；lifespan 建/关 http_client；挂 proxy router）：

```python
"""FastAPI 组装：lifespan（引擎/Redis/http_client/建表/自检/优雅停机）、中间件、路由、健康检查。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
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
from . import models as _models  # noqa: F401  注册 ORM 元数据供 create_all
from .api.mgmt import router as mgmt_router
from .api.proxy import router as proxy_router

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
    # 全局共享上游 AsyncClient（设计 §8.1 第 11 条）：连接复用、池上限、超时配置；
    # 重定向由转发层按同源策略手动跟随（第 7 条），不交给 httpx 自动跟随。
    limits = httpx.Limits(max_connections=settings.upstream_max_connections,
                          max_keepalive_connections=settings.upstream_max_connections)
    app.state.http_client = httpx.AsyncClient(
        limits=limits,
        timeout=httpx.Timeout(connect=settings.upstream_connect_timeout,
                              read=settings.upstream_read_timeout, write=60.0,
                              pool=settings.upstream_pool_timeout),
        follow_redirects=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await app.state.redis.ping()
    log.info("agent-proxy 启动: listen=%s external_base=%s", settings.listen, settings.external_base)
    yield
    await app.state.http_client.aclose()
    # redis-py 4.x 无 aclose()（5.0 起引入），close() 即异步关闭
    close = getattr(app.state.redis, "aclose", None) or app.state.redis.close
    await close()
    await engine.dispose()
    log.info("agent-proxy 已停止")
    shutdown_logging()  # 最后一步：关闭过程（redis/engine）异常仍可落盘


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
    app.include_router(proxy_router)

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

`src/agent_proxy/trace.py`：`log_request` 替换为（新增 `body_bytes` 可选参数——流式转发事后传入实际计数；其余不变）：

```python
def log_request(request_id: str, uid: str, mapping_id: str, method: str, url: str,
                headers: dict[str, str], body: bytes = b"",
                body_bytes: int | None = None, content_type: str = "") -> None:
    if _mode == "off":
        return
    record: dict = {
        "request_id": request_id, "uid": uid, "mapping_id": mapping_id,
        "phase": "request", "method": method, "url": redact_query(url),
        "headers": _headers_for_log(headers, body_mode=(_mode == "body")),
        # 流式转发无法预知 body 长度：body_bytes 由转发层传入实际计数（缺省=len(body)）
        "body_bytes": len(body) if body_bytes is None else body_bytes,
    }
    if _mode == "body":
        record.update(_truncate(body, content_type))
    _write(record)
```

同文件追加：

```python
def capture_limit() -> int:
    """body 模式返回截断上限（转发层据此 tee 捕获 body 前缀）；其余模式 0（不捕获）。"""
    return _max_body if _mode == "body" else 0
```

`src/agent_proxy/api/proxy.py`:

```python
"""代理端点 /p/{mapping_id}/{path}（设计 §6.2/§8.2）。

管线：JWT 鉴权 → load_mapping → 可见性（private 仅注册者；public 任意有效身份）→
status=active 拦截（disabled → 404 隐藏）→ http_forward。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..forward.http_forward import stream_http_forward
from ..services import load_mapping
from .deps import get_current_identity, get_db

router = APIRouter(tags=["proxy"])

_PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


async def _handle_proxy(request: Request, mapping_id: str, identity: Identity,
                        session, settings: Settings) -> Response:
    data = await load_mapping(session, request.app.state.redis, mapping_id,
                              settings.cache_ttl)
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    if data["visibility"] == "private" and data["owner_uid"] != identity.user_id:
        raise AppError(403, "FORBIDDEN", "仅注册者可调用该映射")
    # visibility=public：任意有效身份放行（M6 内置映射场景；M2 数据中不出现 public 用户映射）
    if data["status"] != "active":
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在或已禁用")
    if data["type"] != "http":
        # mcp 的 SSE/Streamable 转发随 M3/M4 交付（本计划范围外）
        raise AppError(400, "INVALID_PARAM", "mcp 类型映射转发随 M3 交付，当前仅支持 http")
    request.state.mapping_id = mapping_id
    return await stream_http_forward(request.app.state, data, request)


@router.api_route("/p/{mapping_id}/{path:path}", methods=_PROXY_METHODS)
async def proxy_with_path(request: Request, mapping_id: str, path: str,
                          identity: Identity = Depends(get_current_identity),
                          session=Depends(get_db),
                          settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, session, settings)


@router.api_route("/p/{mapping_id}", methods=_PROXY_METHODS)
async def proxy_root(request: Request, mapping_id: str,
                     identity: Identity = Depends(get_current_identity),
                     session=Depends(get_db),
                     settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, session, settings)
```

`src/agent_proxy/forward/http_forward.py`：在 Task 3 纯函数之后追加（import 区补齐；本 Task 版本不含重定向跟随）：

```python
# Task 5 import 区最终形态（替换 Task 3 的 import 区）：
import logging
import time
from urllib.parse import unquote

import httpx
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

from .. import metrics, trace
from ..errors import AppError
from ..headers import build_outbound_headers, filter_response_headers

log = logging.getLogger("agent_proxy")

_STREAM_CHUNK = 64 * 1024
```

```python
async def stream_http_forward(app_state, mapping_data: dict, request: Request) -> Response:
    """HTTP 前缀流式转发主管线（本 Task 版本：3xx 一律透传；同源内部跟随在 Task 6 加入）。"""
    settings = app_state.settings
    client: httpx.AsyncClient = app_state.http_client
    mapping_id = mapping_data["mapping_id"]
    request_id = request.state.request_id
    uid = request.state.uid

    sub_path = split_sub_path(request.scope["path"], mapping_id)
    assert_safe_sub_path(sub_path)
    target = build_forward_target(mapping_data["upstream_url"], sub_path, request.url.query)

    stored = mapping_data["upstream_headers"] or {}
    outbound = build_outbound_headers(
        stored, dict(request.headers.items()),
        content_type=request.headers.get("content-type"),
        content_length=request.headers.get("content-length"),
        content_encoding=request.headers.get("content-encoding"))

    # 请求体流式转发 + 字节计数限流（设计 §8.1 第 2 条）：无 body 迹象时 content=None，
    # 避免对 GET 发空 chunked body；有 body 时 httpx 保留入站 Content-Length 分帧（已验证）
    has_body = "content-length" in request.headers or "transfer-encoding" in request.headers
    max_body = settings.max_body_size
    capture_limit = trace.capture_limit()
    body_size = 0
    req_capture = bytearray()

    async def _request_stream():
        nonlocal body_size
        if not has_body:
            return
        async for chunk in request.stream():
            body_size += len(chunk)
            if body_size > max_body:
                # 响应尚未开始，可回标准错误体（设计 §10）
                raise AppError(413, "BODY_TOO_LARGE", f"请求体超过上限 {max_body} 字节")
            if capture_limit and len(req_capture) < capture_limit:
                req_capture.extend(chunk[: capture_limit - len(req_capture)])
            yield chunk

    def _log_request() -> None:
        trace.log_request(request_id, uid, mapping_id, request.method, target, outbound,
                          body=bytes(req_capture), body_bytes=body_size,
                          content_type=request.headers.get("content-type", ""))

    start = time.monotonic()
    # 真流式（评审 Critical 修复）：必须 build_request + send(stream=True)。
    # client.request 内部 send(stream=False) 会 aread() 把响应体整体读进内存——
    # 假流式：大文件 OOM、M3 SSE 永不结束的流永远等不到 EOF。流式消费由下方
    # aiter_bytes 逐块 + finally aclose 负责。
    req = client.build_request(request.method, target, headers=outbound,
                               content=_request_stream())
    try:
        upstream_resp = await client.send(req, stream=True)
    except AppError:
        _log_request()
        raise
    except httpx.PoolTimeout as exc:  # 池上限（必须先于 TimeoutException 捕获）
        metrics.upstream_errors_total.labels(type="http", code="pool_exhausted").inc()
        _log_request()
        raise AppError(503, "PROXY_BUSY", "上游连接池已满，请稍后重试") from exc
    except httpx.TimeoutException as exc:
        metrics.upstream_errors_total.labels(type="http", code="timeout").inc()
        _log_request()
        raise AppError(504, "UPSTREAM_TIMEOUT", f"上游超时: {exc}") from exc
    except httpx.HTTPError as exc:
        metrics.upstream_errors_total.labels(type="http", code="connect").inc()
        _log_request()
        raise AppError(502, "UPSTREAM_ERROR", f"上游连接失败: {exc}") from exc
    _log_request()

    # duration_ms 语义：time-to-headers——上游响应头到达耗时，不含 body 流式传输时长
    duration_ms = int((time.monotonic() - start) * 1000)
    metrics.upstream_duration.labels(type="http").observe(duration_ms / 1000)

    resp_capture = bytearray()
    stream_broken = False

    async def _response_stream():
        nonlocal stream_broken
        try:
            async for chunk in upstream_resp.aiter_bytes(_STREAM_CHUNK):
                if capture_limit and len(resp_capture) < capture_limit:
                    resp_capture.extend(chunk[: capture_limit - len(resp_capture)])
                yield chunk
        except httpx.HTTPError as exc:
            # 流中断可观测（评审 Important 项，设计 §10）：响应头已发出无法改写
            # 状态码，客户端表现为连接截断；计数 + 异常日志留痕
            stream_broken = True
            metrics.upstream_errors_total.labels(type="http", code="stream_broken").inc()
            log.exception("上游响应流中断: %s", exc)
            raise
        finally:
            # 流结束/客户端断开都释放上游连接（设计 §8.1 第 4 条）
            await upstream_resp.aclose()
            if stream_broken:
                return  # 中断：不写误导性的 status=200 response 行（log.exception 已留痕）
            if capture_limit:
                # filter_response_headers 保留上游原始大小写，content-type 按小写不敏感取
                resp_ct = next((v for k, v in resp_headers.items()
                                if k.lower() == "content-type"), "")
                trace.log_response(request_id, upstream_resp.status_code, duration_ms,
                                   headers=dict(resp_headers), body=bytes(resp_capture),
                                   content_type=resp_ct)
            else:
                trace.log_response(request_id, upstream_resp.status_code, duration_ms)

    # send 成功到 StreamingResponse 交棒之间的小窗口：异常时关闭上游流防泄漏
    try:
        resp_headers = filter_response_headers(upstream_resp.headers)
        # 大小写不敏感判重（评审 Minor）：上游已带该头时不重复注入
        if not any(k.lower() == "x-accel-buffering" for k in resp_headers):
            resp_headers["X-Accel-Buffering"] = "no"  # 网关关闭缓冲（设计 §8.1 第 9 条）
        return StreamingResponse(_response_stream(), status_code=upstream_resp.status_code,
                                 headers=resp_headers)
    except BaseException:
        await upstream_resp.aclose()
        raise
```

- [ ] **Step 4: 运行确认通过 + 全量回归**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_proxy_http.py -v`
Expected: 12 PASS

Run: `.venv/Scripts/python.exe -m pytest`
Expected: 全部 PASS（148 = 136 + 本任务 12）

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/main.py src/agent_proxy/api/proxy.py src/agent_proxy/forward/http_forward.py src/agent_proxy/trace.py tests/integration/test_proxy_http.py
git commit -m "feat(M2): /p/ 转发上线——lifespan http_client + api/proxy + stream_http_forward（流式/413/502/504/trace/metrics 接线）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 6: 同源重定向内部跟随 + 大响应流式 + 413 + PROXY_BUSY 集成验证

**Files:**
- Modify: `src/agent_proxy/forward/http_forward.py`（加入同源重定向跟随循环）
- Modify: `tests/conftest.py`（`MAX_BODY_SIZE=1MB`，供 413 用例）
- Modify: `tests/integration/test_proxy_http.py`（第二批追加）

- [ ] **Step 1: 写失败集成测试（第二批追加到 test_proxy_http.py 末尾）**

```python
# ---------- 第二批：重定向 / 大响应 / 413 / 连接池 ----------


async def test_same_origin_redirect_followed_internally(client):
    """同源 302：代理内部跟随，存储 header 每跳重放；同源 Location 永不回传（§8.1 第 7 条）。"""
    created = await _register(client)
    mid = created["mapping_id"]
    resp = await _call(client, mid, "GET", "/redirect/same-origin")
    assert resp.status_code == 200                                   # 内部跟随完成
    echo = resp.json()
    assert echo["path"] == "/final" and echo["query"] == {"via": "redirect"}
    assert echo["headers"]["authorization"] == "Bearer sk-real-12345678"  # 每跳重放
    assert "location" not in {k.lower() for k in resp.headers.keys()}


async def test_same_origin_307_post_keeps_method(client):
    """307 保方法（body 不重放为 M2 已知限制：首跳已流式消耗，断言只看方法与路径）。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "POST", "/redirect/307",
                       headers={"Content-Type": "application/json"}, content=b'{"a":1}')
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "POST" and echo["path"] == "/final"


async def test_cross_origin_redirect_passthrough(client):
    """跨源 302（→9902 不存在端口）：不跟随原样透传；若被跟随会得到 502 而非 302。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/redirect/cross-origin")
    assert resp.status_code == 302
    assert "127.0.0.1:9902" in resp.headers["location"]


async def test_redirect_loop_stops_at_limit(client):
    """超过 UPSTREAM_MAX_REDIRECTS(默认 3) 后最后一跳原样透传。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/redirect/loop")
    assert resp.status_code == 302


async def test_request_body_over_limit_413(client):
    """流式计数超限立即 413（conftest MAX_BODY_SIZE=1MB；响应未开始，标准错误体）。"""
    created = await _register(client)
    big = b"x" * (1024 * 1024 + 1024)
    resp = await _call(client, created["mapping_id"], "POST", "/orders",
                       headers={"Content-Type": "application/octet-stream"}, content=big)
    assert resp.status_code == 413 and resp.json()["code"] == "BODY_TOO_LARGE"


async def test_large_response_streamed_intact(client):
    """8MB 响应经代理逐块回传，字节级完整（不整体驻留：转发层为 aiter_bytes 逐块 yield）。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/big?kb=8192")
    assert resp.status_code == 200
    size = 8192 * 1024
    pattern = bytes(range(256))
    expected = (pattern * (size // len(pattern) + 1))[:size]
    assert resp.content == expected


async def test_pool_exhausted_returns_503():
    """max_connections=1 + 慢上游：第二个请求等池超时（5s）→ 503 PROXY_BUSY。

    用 8s 慢响应保证确定性（5s 池超时 < 8s 占用）。专用 app（UPSTREAM_MAX_CONNECTIONS=1）。
    """
    import asyncio
    import os

    from agent_proxy.config import Settings
    from agent_proxy.main import create_app
    from httpx import ASGITransport, AsyncClient

    settings = Settings.from_env({**os.environ, "UPSTREAM_MAX_CONNECTIONS": "1"})
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        async with AsyncClient(transport=ASGITransport(app=application),
                               base_url="http://testserver") as c:
            resp = await c.post("/api/v1/mappings",
                                json={"type": "http",
                                      "upstream_url": "http://127.0.0.1:9901/api/v1",
                                      "headers": {}},
                                headers={"Authorization": f"Bearer {make_token('u888')}"})
            mid = resp.json()["mapping_id"]
            r1, r2 = await asyncio.gather(
                _call(c, mid, "GET", "/slow?seconds=8"),
                _call(c, mid, "GET", "/slow?seconds=8"))
    statuses = [r.status_code for r in (r1, r2)]
    assert 503 in statuses, f"应有请求因连接池耗尽得到 503: {statuses}"
    for r in (r1, r2):
        if r.status_code == 503:
            assert r.json()["code"] == "PROXY_BUSY"
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_proxy_http.py -k "redirect or 413 or large or pool" -v`
Expected: 同源两条/循环 FAIL（当前 302 直接透传而非跟随 200）；413 FAIL（默认 10MB 未拦）；large/pool FAIL（large 可能已过，pool 未按预期 503——以实际运行为准记录基线）

- [ ] **Step 3: 实现重定向跟随 + conftest 体积上限**

`tests/conftest.py` 的 `os.environ.update({...})` 块内追加一行（放在 `"MAX_BODY_SIZE": "1MB",`——413 用例依赖；其余测试不受影响）：

```python
    "MAX_BODY_SIZE": "1MB",
```

`src/agent_proxy/forward/http_forward.py`：模块级新增两个辅助函数（放在 `build_forward_target` 之后），并在 `stream_http_forward` 中插入同源跟随循环——插入位置：`_log_request()`（成功路径那次）之后、`duration_ms = ...` 之前：

```python
def _origin(url: httpx.URL) -> tuple[str, str, int]:
    default = 443 if url.scheme == "https" else 80
    return (url.scheme, url.host, url.port or default)


def _redirect_method(status: int, method: str) -> str:
    """303 → GET（载荷类方法），301/302/307/308 保方法（设计 §8.1 第 7 条）。"""
    if status == 303 and method in ("POST", "PUT", "PATCH", "DELETE"):
        return "GET"
    return method
```

```python
    # 同源重定向内部跟随（设计 §8.1 第 7 条）：与「注册 upstream_url 的 origin」比较；
    # 存储 header 每跳重放；跨源不跟随原样透传（Location 指向第三方属上游自身行为）。
    upstream_origin = _origin(httpx.URL(mapping_data["upstream_url"]))
    redirects = 0
    while upstream_resp.is_redirect and redirects < settings.upstream_max_redirects:
        location = upstream_resp.headers.get("location")
        if not location:
            break
        next_url = httpx.URL(target).join(location)
        if _origin(next_url) != upstream_origin:
            break  # 跨源：透传
        await upstream_resp.aclose()
        target = str(next_url)
        method = _redirect_method(upstream_resp.status_code, request.method)
        # 已知限制：首跳 body 已流式消耗，跳间不重放 body（303 已降为 GET）
        hop_headers = {k: v for k, v in outbound.items() if k.lower() != "content-length"}
        try:
            upstream_resp = await client.request(method, target, headers=hop_headers)
        except httpx.PoolTimeout as exc:
            metrics.upstream_errors_total.labels(type="http", code="pool_exhausted").inc()
            raise AppError(503, "PROXY_BUSY", "上游连接池已满，请稍后重试") from exc
        except httpx.TimeoutException as exc:
            metrics.upstream_errors_total.labels(type="http", code="timeout").inc()
            raise AppError(504, "UPSTREAM_TIMEOUT", f"上游超时: {exc}") from exc
        except httpx.HTTPError as exc:
            metrics.upstream_errors_total.labels(type="http", code="connect").inc()
            raise AppError(502, "UPSTREAM_ERROR", f"上游连接失败: {exc}") from exc
        redirects += 1
```

- [ ] **Step 4: 运行确认通过 + 全量回归**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_proxy_http.py -v`
Expected: 19 PASS（第一批 12 + 第二批 7）

Run: `.venv/Scripts/python.exe -m pytest`
Expected: 全部 PASS（155；本任务起全套含 ~8s 慢用例 pool_exhausted）

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/forward/http_forward.py tests/conftest.py tests/integration/test_proxy_http.py
git commit -m "feat(M2): 同源重定向内部跟随（存储头每跳重放/跨源透传/303→GET）+ 大响应流式 + 413 + PROXY_BUSY 集成验证" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 7: test 接口（§6.6）——http 连通 / 严格验证 / 5s 短超时

**Files:**
- Modify: `src/agent_proxy/schemas.py`（MappingTestOut）
- Modify: `src/agent_proxy/forward/http_forward.py`（probe_http_mapping）
- Modify: `src/agent_proxy/api/mgmt.py`（POST /{mapping_id}/test 路由）
- Create: `tests/integration/test_mgmt_test_endpoint.py`

- [ ] **Step 1: 写失败集成测试**

`tests/integration/test_mgmt_test_endpoint.py`:

```python
"""test 接口（设计 §6.6）：http 连通判定 / test_request 严格验证 / 5s 短超时 / 安全边界。

上游失败一律 ok=false + detail，不产生代理自身 502/504；仅注册者可测；
mcp 类型 M2 明确返回未支持（M3/M4 补语义验证）。
"""
import glob
import json

from tests.utils import make_token

AUTH = {"Authorization": f"Bearer {make_token('u888')}"}


async def _register(client, user="u888", **overrides):
    payload = {"type": "http", "upstream_url": "http://127.0.0.1:9901/api/v1",
               "headers": {"Authorization": "Bearer sk-real-12345678"}, **overrides}
    resp = await client.post("/api/v1/mappings", json=payload,
                             headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _test(client, mapping_id, user="u888"):
    hdrs = {"Authorization": f"Bearer {make_token(user)}"}
    return await client.post(f"/api/v1/mappings/{mapping_id}/test", headers=hdrs)


async def test_http_probe_connectivity_ok(client):
    """默认 GET upstream_url：任意 HTTP 响应 = 可达（base URL 可能天然 404，不硬判失败）。"""
    created = await _register(client)
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert body["latency_ms"] >= 0 and body["detail"]


async def test_http_probe_strict_expect_match(client):
    created = await _register(client, test_request={"method": "GET",
                                                    "path": "/status/201",
                                                    "expect_status": 201})
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 201


async def test_http_probe_strict_expect_mismatch(client):
    created = await _register(client, test_request={"method": "GET",
                                                    "path": "/status/201",
                                                    "expect_status": 200})
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 201
    assert "200" in body["detail"] and "201" in body["detail"]


async def test_http_probe_strict_post_method_used(client):
    created = await _register(client, test_request={"method": "POST",
                                                    "path": "/orders",
                                                    "expect_status": 200})
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200


async def test_http_probe_timeout_ok_false_no_502(client):
    """上游超 5s：ok=false + detail 超时说明；绝不抛 502/504（设计 §6.6）。"""
    created = await _register(client, upstream_url="http://127.0.0.1:9901/api/v1/slow?seconds=8")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200  # 上游失败不变成代理 5xx
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None
    assert "超时" in body["detail"]


async def test_http_probe_upstream_down_ok_false(client):
    """上游不可达（9902 不存在端口）：ok=false，status_code=None。"""
    created = await _register(client, upstream_url="http://127.0.0.1:9902/api/v1")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None and body["detail"]


async def test_test_endpoint_owner_only_404(client):
    created = await _register(client, user="u888")
    resp = await _test(client, created["mapping_id"], user="u999")
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_test_endpoint_mcp_not_supported_400(client):
    created = await _register(client, type="mcp", upstream_url="https://mcp.ex.com/sse")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 400
    body = resp.json()
    assert body["code"] == "INVALID_PARAM" and "M3" in body["message"]


async def test_test_endpoint_audited_as_test_mapping(client):
    created = await _register(client)
    resp = await _test(client, created["mapping_id"])
    request_id = resp.headers["x-request-id"]
    entries = []
    for path in glob.glob("logs-test/audit.log.*"):
        with open(path, encoding="utf-8") as fh:
            entries.extend(json.loads(x) for x in fh.read().splitlines() if x.strip())
    mine = [e for e in entries if e["request_id"] == request_id]
    assert mine and mine[0]["action"] == "test_mapping"
    assert mine[0]["mapping_id"] == created["mapping_id"]
    assert "sk-real-12345678" not in json.dumps(mine[0])  # 审计不含 header 值（§6.6）
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_mgmt_test_endpoint.py -v`
Expected: 全部 FAIL（POST /{id}/test 无路由 → 404/405）

- [ ] **Step 3: 实现 probe + 路由 + schema**

`src/agent_proxy/schemas.py` 末尾追加：

```python
class MappingTestOut(BaseModel):
    """POST /api/v1/mappings/{id}/test 响应（设计 §6.6）。"""
    ok: bool
    status_code: int | None = None
    latency_ms: int
    detail: str
```

`src/agent_proxy/forward/http_forward.py` 末尾追加：

```python
TEST_PROBE_TIMEOUT = 5.0  # 设计 §6.6：测试专用短超时


async def probe_http_mapping(app_state, mapping_data: dict) -> dict:
    """http 类型 test（设计 §6.6）：默认 GET upstream_url 判连通（任意 HTTP 响应=可达）；
    有 test_request 时按 method/path/expect_status 严格验证。

    复用转发管线的 URL 拼接与出站 header 重建（测的即真实路径）；
    上游失败一律 ok=false + detail，不抛 502/504。审计由调用方记 action=test_mapping。
    """
    stored = mapping_data["upstream_headers"] or {}
    headers = build_outbound_headers(stored, {}, None, None, None)
    tr = mapping_data.get("test_request") or {}
    strict = bool(tr)
    if strict:
        assert_safe_sub_path(str(tr.get("path", "/")))
        method = str(tr.get("method", "GET")).upper()
        target = build_forward_target(mapping_data["upstream_url"], str(tr.get("path", "/")), "")
        expect = tr.get("expect_status")
    else:
        method, target, expect = "GET", mapping_data["upstream_url"], None

    start = time.monotonic()

    def _result(ok: bool, status_code: int | None, detail: str) -> dict:
        return {"ok": ok, "status_code": status_code,
                "latency_ms": int((time.monotonic() - start) * 1000), "detail": detail}

    try:
        resp = await app_state.http_client.request(method, target, headers=headers,
                                                   timeout=TEST_PROBE_TIMEOUT)
    except httpx.TimeoutException as exc:
        return _result(False, None, f"上游超时（>{TEST_PROBE_TIMEOUT:.0f}s）: {type(exc).__name__}")
    except httpx.HTTPError as exc:
        return _result(False, None, f"上游不可达: {type(exc).__name__}: {exc}")
    status_code = resp.status_code
    await resp.aclose()
    if strict:
        ok = expect is not None and status_code == int(expect)
        detail = "状态码匹配" if ok else f"预期状态码 {expect}，实际 {status_code}"
    else:
        ok = True
        detail = f"可达（status={status_code}，base URL 状态码仅作参考）"
    return _result(ok, status_code, detail)
```

`src/agent_proxy/api/mgmt.py`：import 区追加 `MappingTestOut`（schemas import 列表）与 `from ..forward.http_forward import probe_http_mapping`；路由追加到文件末尾（delete 路由之后即可——`/{mapping_id}/test` 与既有 `/{mapping_id}` 路径/方法组合均不冲突）：

```python
@router.post("/{mapping_id}/test", response_model=MappingTestOut)
async def test_mapping_route(request: Request, mapping_id: str,
                             identity: Identity = Depends(get_current_identity),
                             session=Depends(get_db),
                             settings: Settings = Depends(get_settings)):
    """配置有效性测试（设计 §6.6）：仅注册者、仅已注册映射（防探测滥用）。"""
    data = await get_owned(session, request.app.state.redis, mapping_id,
                           identity.user_id, settings.cache_ttl)
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.audit_action = "test_mapping"
    request.state.mapping_id = data["mapping_id"]
    if data["type"] == "mcp":
        # M3/M4 补 SSE endpoint / Streamable initialize 语义验证（设计 §16）
        raise AppError(400, "INVALID_PARAM", "mcp 类型 test 随 M3/M4 交付，当前仅支持 http")
    return await probe_http_mapping(request.app.state, data)
```

- [ ] **Step 4: 运行确认通过 + 全量回归**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_mgmt_test_endpoint.py -v`
Expected: 9 PASS（含 ~5s probe 超时用例）

Run: `.venv/Scripts/python.exe -m pytest`
Expected: 全部 PASS（164）

- [ ] **Step 5: Commit**

```bash
git add src/agent_proxy/schemas.py src/agent_proxy/forward/http_forward.py src/agent_proxy/api/mgmt.py tests/integration/test_mgmt_test_endpoint.py
git commit -m "feat(M2): test 接口——http 连通/test_request 严格验证/5s 短超时（audit=test_mapping，上游失败 ok=false 不抛 5xx）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 8: trace body 模式集成验证 + README 更新 + M2 收尾

**Files:**
- Create: `tests/integration/test_proxy_trace.py`
- Modify: `README.md`

- [ ] **Step 1: 写失败集成测试（body 模式 trace：request/response 记录 + query 脱敏）**

`tests/integration/test_proxy_trace.py`:

```python
"""trace body 模式集成：/p/ 转发的 request/response 记录 + URL query 脱敏（终审债务 #3）。

body 模式经 TRACE_MODE=body 环境启动专用 app（trace.configure 为进程级全局，
用毕恢复 metadata，避免污染后续用例）。
"""
import glob
import json
import logging
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from tests.utils import make_token

BODY = {"type": "http", "upstream_url": "http://127.0.0.1:9901/api/v1",
        "headers": {"Authorization": "Bearer sk-real-12345678",
                    "X-Plain-Header": "visible-plain-value"}}


@pytest.fixture
def body_env(monkeypatch):
    monkeypatch.setenv("TRACE_MODE", "body")
    yield
    from agent_proxy import trace
    trace.configure("metadata", 64 * 1024)  # 恢复进程级全局（集成夹具 app 会在下次 lifespan 重配）


@pytest_asyncio.fixture
async def body_app(body_env):
    from agent_proxy import trace
    from agent_proxy.config import Settings
    from agent_proxy.main import create_app

    application = create_app(Settings.from_env(os.environ))
    async with application.router.lifespan_context(application):
        trace.configure("body", application.state.settings.trace_body_max_size)  # 钉住全局
        yield application


@pytest_asyncio.fixture
async def body_client(body_app):
    async with AsyncClient(transport=ASGITransport(app=body_app),
                           base_url="http://testserver") as c:
        yield c


def _trace_records():
    records = []
    for path in glob.glob("logs-test/trace.log.*"):
        with open(path, encoding="utf-8") as fh:
            records.extend(json.loads(x) for x in fh.read().splitlines() if x.strip())
    return records


async def test_proxy_trace_body_mode_records_and_redacts_query(body_client):
    from agent_proxy.logging_setup import flush_trace

    resp = await body_client.post("/api/v1/mappings", json=BODY,
                                  headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 201
    mid = resp.json()["mapping_id"]
    resp = await body_client.get(f"/p/{mid}/orders?token=secret-token-12345678&status=paid",
                                 headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    flush_trace()

    recs = [r for r in _trace_records() if r.get("mapping_id") == mid]
    req = [r for r in recs if r["phase"] == "request"]
    rsp = [r for r in recs if r["phase"] == "response"]
    assert req and rsp, "body 模式下 /p/ 转发应有 request 与 response 记录"

    # URL query 值脱敏（键名保留，值指纹化；"secret-token-12345678" 长 21）
    url = req[0]["url"]
    assert "secret-token-12345678" not in url
    assert "token=secr****5678(len=21)" in url
    assert "status=****(len=4)" in url

    # body 模式：非敏感头显原值，敏感头指纹化（"Bearer sk-real-12345678" 长 23）
    assert req[0]["headers"]["X-Plain-Header"] == "visible-plain-value"
    assert req[0]["headers"]["Authorization"] == "Bear****5678(len=23)"
    assert "sk-real-12345678" not in json.dumps(req[0])

    # 响应记录：状态码 + body（echo JSON，截断上限内）
    assert rsp[0]["status"] == 200
    assert '"path":"/orders"' in rsp[0]["body"] and rsp[0]["body_truncated"] is False
```

- [ ] **Step 2: 运行确认失败**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_proxy_trace.py -v`
Expected: FAIL（若 Task 5/2 实现正确可能直接 PASS——预期为绿；若 FAIL 按 Task 5 的 capture_limit/log_response 接线排查修正后转绿。此用例是 §16 验收「trace body 模式可用」的行为验证）

- [ ] **Step 3: 更新 README**

`README.md` 的「接口速览」表更新为：

```markdown
| 方法 | 路径 | 说明 |
|---|---|---|
| POST/GET/PUT/DELETE | /api/v1/mappings[/{id}] | 映射 CRUD（JWT） |
| POST | /api/v1/mappings/{id}/test | 配置有效性测试：http 连通 / test_request 严格验证（mcp 随 M3/M4） |
| GET | /api/v1/mappings/resolve?proxy_url= | 按代理地址回显真实配置 |
| ANY | /p/{mapping_id}/{path} | 代理转发（M2 已支持 http 前缀流式转发；mcp 随 M3/M4） |
| GET | /healthz /readyz /metrics | 运维端点 |
```

- [ ] **Step 4: 全量回归**

Run: `.venv/Scripts/python.exe -m pytest -v`
Expected: 全部 PASS（165 = 基线 101 + M2 新增 64）。特别确认：无 mapping_id/user_id 出现在 metrics 标签；trace.log 中无完整凭据值。

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_proxy_trace.py README.md
git commit -m "test(M2): trace body 模式集成（query 脱敏/request+response 记录）+ README /p/ 更新（M2 完成）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## M2 验收清单（对照设计 §16 M2 行 + 终审确认项）

- [ ] **echo 上游全链路（真实 TCP）**：注册指向 `http://127.0.0.1:9901/api/v1` 的映射 → 经 `/p/{id}/orders` 真实转发 → echo 回显验证出站 header == 存储值、调用方 JWT/占位符/非白名单 header 不透传、query/method/body/深路径透传（test_proxy_http.py 第一批 12 条）
- [ ] **大文件流式不驻留内存**：8MB 响应字节级完整回传（test_large_response_streamed_intact）；转发层为 `aiter_bytes` 逐块 yield + `StreamingResponse`，无整体缓冲代码路径；请求体流式计数、超限 413（MAX_BODY_SIZE=1MB 用例）
- [ ] **http test 可用**：连通判定 / test_request 严格匹配与不匹配 / POST 方法 / 5s 超时 ok=false / 上游不可达 ok=false / owner 404 / mcp 400 明确提示 / audit=test_mapping（test_mgmt_test_endpoint.py 9 条）
- [ ] **权限与错误码（§10）**：无 token 401、非 owner 403、不存在/禁用 404、dot-segment（含 %2e%2e/%252e）400、上游 404 原样透传、连接失败 502、超时 504、池耗尽 503 PROXY_BUSY
- [ ] **重定向（§8.1 第 7 条）**：同源 302 内部跟随（存储 header 每跳重放、Location 不回传）、307 保方法、跨源透传、循环封顶透传
- [ ] **终审债务关闭**：① trace URL query 值脱敏（键名保留）② 审计 bytes_in/bytes_out + `ap_bytes_total` 接线 ③ `ap_request_duration_seconds`/`ap_upstream_duration_seconds` 自定义桶（5ms~300s）④ resolve 拒绝 netloc host ≠ EXTERNAL_BASE host
- [ ] **可观测接线**：/p/ 转发写 trace request/response（metadata 即有；body 模式含截断 body，test_proxy_trace.py）；metrics upstream_duration/upstream_errors 全接线；标签无 user_id/mapping_id
- [ ] **全量回归**：`pytest` 全绿（约 165 passed，基线 101 + 新增 ~64）
- [ ] **M2 不含**：SSE endpoint 改写、Streamable、OAuth、公共映射接口、管理页面（M3–M7 交付）

## 已知限制（M2 明示接受，均有代码注释）

1. 重定向跳间不重放请求 body（首跳已流式消耗；303 已降为 GET，307/308 保方法但 body 为空）。
2. `filter_response_headers` 返回 dict，上游多值响应头（如多个 Set-Cookie）折叠加密为单值（M2 无多 cookie 场景）。
3. DNS rebinding 强防护不做（设计 §9.10 已知限制，注册时校验 + 转发时不重校验）。
4. 审计 bytes_in 为应用实际读取字节数（鉴权即拒的请求为 0）。
5. Connection 列举的附加头不剥离（RFC 9110 允许 Connection 头枚举额外 hop-by-hop 头名；本实现只剥离固定集合 + Proxy-* 前缀，RFC 完整性缺口，M2 接受）。
