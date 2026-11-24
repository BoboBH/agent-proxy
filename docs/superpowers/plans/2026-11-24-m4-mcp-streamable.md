# M4 实施计划：MCP Streamable HTTP 代理 + accept-encoding 统一 + probe 语义定稿

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付 agent-proxy M4：MCP Streamable HTTP 传输（§8.4 单一 `/mcp` 端点 POST/GET/DELETE、`Mcp-Session-Id` 白名单双向透传、JSON 或 SSE 响应流式回传、无需改写——转发复用 M2/M3 既有管线，仅 test 接口新增形态细分探测）；M3 终审确认的 M4 前置硬项/债务全部落位（accept-encoding 透明性全管线 aiter_raw、probe 总挂钟期限定稿、mcp test 探测式 auto 细分、GET `/p/{id}/mcp` 分发语义定稿、M3 Minor 批逐项处置）；真实 MCP Streamable mock 上游（uvicorn 真实监听 9903）经真实 TCP 全链路测试；MCP Inspector Streamable 联调人工验收文档。

**Architecture:** 延续 M1–M3 分层 `api → services → forward → infra`。**不新增转发管线**：Streamable POST/DELETE 按「上游 origin 根还原」走 `stream_http_forward`（M3 已就绪的 `target_override` / `metrics_type`），GET 注册端点（服务端推送流）走 `stream_sse_forward`（rewriter 对 Streamable 流为字节级无操作，论证见关键决策 4 与 Task 5 注释）。新增 `forward/mcp_streamable.py` 仅承载 test 探测（`probe_streamable_mapping` + `probe_mcp_mapping` 探测式 auto）。新增 mock 上游 `tests/integration/mock_mcp_streamable.py`（uvicorn 真实监听 127.0.0.1:9903）与集成测试 `tests/integration/test_proxy_mcp_streamable.py`（真实 TCP 经 9910 代理）、`tests/integration/test_proxy_encoding.py`（accept-encoding 回归，真实 TCP）。

**Tech Stack:** Python 3.12（venv `.venv`，Git Bash 下 `.venv/Scripts/python.exe`）、FastAPI、httpx 0.28.1（异步流式，`build_request(timeout=...)` 逐请求超时）、SQLAlchemy 2 async、redis 4.x、prometheus-client、uvicorn（既作服务入口也作测试上游/被测代理）、pytest + pytest-asyncio（asyncio_mode=auto）。无新增依赖。

**对应设计文档:** §6.6 test 接口（mcp+Streamable 行 / 总挂钟期限 / 探测式 auto 细分）、§8.1 第 1/2/3/4/5/7/9 条（header 白名单 / 流式 / 响应过滤 / 断开 / 超时表 / 重定向 / 缓冲）、§8.3（SSE 分支重定向策略注记回写）、§8.4 MCP Streamable（实现注记回写）、§8.5 统一与差异、§10 错误码、§11.1 追踪日志（压缩体二进制语义）、§13 测试策略（真实客户端 Inspector Streamable 行）、§16 M4 验收。

**范围说明:** 本计划只覆盖 M4。M5（集成测试补全批次 + README 收尾 + 联调）、M6（公共映射 / OAuth）、M7（管理页面）不在本计划内。

**约定（延续 M1–M3）:** 测试令牌 `stub.<base64url(payload)>.sig`；测试库 `agent_proxy_test` + Redis db9、`SSRF_ALLOW_PRIVATE=true`、`LOG_DIR=logs-test`。当前基线 **246 passed** 全绿为出发点（实测确认）。commit 中文 + `Co-Authored-By: Claude Code <noreply@anthropic.com>`；真实 TCP 测试风格（mock 上游 uvicorn 真实监听）。

**端口簿:** 9901 echo 上游（不变）、9902 MCP SSE mock（不变）、**9903 MCP Streamable mock（新）**、9909 死端口（不变）、9910 被测代理（不变）。

**关键决策（实现前先读）：**

1. **accept-encoding 透明性选 `aiter_raw()`（不是出站钉 `identity`），全管线统一无参调用**。httpx 0.28.1 实测确认（venv）：出站默认 `accept-encoding: gzip, deflate`；上游返回 gzip 时 `aiter_bytes` 自动解压（41B 压缩体解成 1100B）而响应头按原样透传（`content-encoding: gzip` + 按压缩字节计的 `content-length: 41`）→ 头体不一致，严格客户端（uvicorn/h11 侧）对「超过声明 Content-Length 的响应体」报错断连。`aiter_raw()` 无参按网络到达块即时产出**压缩字节**（源码确认：`aiter_raw` 与无参 `aiter_bytes` 同为到达粒度，仅少一层 content-decoder；EOF 后自动 aclose）——头体一致、零解压成本、上游压缩收益保留。**必须无参**：带 `chunk_size` 的 ByteChunker 会攒_buf 不足即不产出，M3 已实测该行为破坏 SSE 增量下发——Streamable 的 POST SSE 形态响应同样经 http 管线，故四处（M2 `_response_stream`、M3 `_plain_stream`、M3 `_sse_stream`、SSE probe `_first_endpoint`）统一为无参 `aiter_raw()`。探针属唯一「要解析响应体」的路径：`probe_streamable_mapping` 出站钉 `accept-encoding: identity` 读明文（见决策 3），与转发管线不冲突。
2. **probe 超时语义定稿为「总挂钟期限」**：`TEST_PROBE_TIMEOUT`（5s）为 send（响应头到达）与读流/读响应共享的总 deadline，后继阶段仅享剩余量（`asyncio.wait_for(..., remaining)`）。现状缺口在 SSE probe（send 与读流各 5s，最坏 ~10s）；http probe 已是单阶段 wait_for 包裹（headers 即决，天然满足总期限），仅设计 §6.6 注记同步。
3. **mcp test 端点形态细分用「探测式 auto」**：先按 Streamable 语义 POST 标准 `initialize` JSON-RPC——2xx 且响应体（JSON 直接解析；SSE 形态取首个 `message` 事件 data）含 `serverInfo` → ok=true（§6.6 硬性判定）；端点以 **405/404/406** 拒绝 POST（SSE-only 上游对注册端点 POST 的典型行为，mock 实证）→ 回落 `probe_sse_mapping`。**不新增 `transport` 注册字段**（设计 §5.1 无此列，新增将连带 schema/建表/缓存/管理 API 变更且要求用户正确填写传输形态）；**不用端点路径后缀启发式**（`/mcp` 仅生态惯例，SSE 服务也可注册在 `/mcp`）——以真实协议行为判定误判面最小，且 `detail` 回告实际形态供排障。其余非 2xx（401/500 等）直接判失败不回落（凭据失效等应显式暴露，不掩盖为形态回落）。
4. **GET `/p/{id}/mcp`（Streamable 服务端推送流）维持现有分发，不新增字段、不建运行时探测缓存**：一条分发表同时正确服务两种传输——POST/DELETE 本就走 origin 根还原的 http 管线；GET 注册端点进 SSE 解析管线，其 rewriter 仅改写 `event: endpoint` 的 data 行，而 Streamable 流只有 `message` 事件 → 字节级无操作透传；`read=None`（§8.1 第 5 条流式行）、`Connection: close`（连接生命周期=请求生命周期）、`sse_active` 计数（推送流确为活跃 SSE 连接）对推送流语义全部成立。行为零差异下引入 transport 字段（schema/DB/缓存连带）或运行时探测缓存（失效/竞态复杂度）均为负收益——以 `api/proxy.py` 分发注释 + 设计 §8.4 注记定稿，集成测试用 `Connection: close` 出站钉住 + `sse_active` 计数钉住该语义。
5. **mock 形态切换两种机制并存**：客户端转发形态切换用查询参数 `?form=sse`（query 透传已被 M3 验证）；probe 用例注册地址用路径别名 `/mcp-sse-form`（probe 的 `upstream_url` 直拼请求目标，路径别名无 query 语义歧义）。短 SSE 流 = 单条 `event: message` 后 EOF（「可结束」的响应，覆盖代理 SSE 形态回传分支且测试可确定性收敛）。
6. **trace 压缩体二进制语义**：`aiter_raw` 后 body 模式捕获的是压缩字节，按文本解码必乱码——`trace.log_response` 增加 `content_encoding` 参数，非空时走二进制路径（只记 `body_bytes`，与既有非文本 Content-Type 行为一致）。
7. **SseEndpointRewriter 单行缓冲上限 1MB**（`MAX_LINE_BYTES` 公开常量）：无换行超长行降级为原样透传（超限即冲出已缓冲字节 + 直至行尾持续透传，行尾后恢复正常解析），字节级保真且内存有界。

---

## 文件结构（M4 变更后）

```
agent-proxy/
├── docs/superpowers/plans/
│   └── 2026-11-24-m4-mcp-streamable.md     # 本计划
├── docs/superpowers/specs/
│   └── 2026-11-21-agent-proxy-design.md    # [改] §6.6 总挂钟期限 + 探测式 auto 注记；
│                                           #      §8.1 第 7 条 / §8.3 SSE 重定向注记；
│                                           #      §8.4 代理实现注记（GET 分发语义定稿）
├── scripts/
│   ├── inspector_m4.md                     # [新] Inspector Streamable 联调人工验收清单（§16 M4 硬要求）
│   └── mock_mcp_streamable_server.py       # [新] mock MCP Streamable 上游独立入口（python 直跑）
├── src/agent_proxy/
│   ├── forward/
│   │   ├── http_forward.py                 # [改] _response_stream aiter_raw（压缩字节透传）+
│   │   │                                   #      trace response 传 content_encoding（M4 硬项 1）
│   │   ├── mcp_sse.py                      # [改] _plain_stream/_sse_stream/_first_endpoint aiter_raw；
│   │   │                                   #      中止路径不写 response 行（Minor 统一）；
│   │   │                                   #      Connection 小写键；probe 总期限共享；
│   │   │                                   #      SseEndpointRewriter 单行上限（Minor 批）
│   │   └── mcp_streamable.py               # [新] probe_streamable_mapping / probe_mcp_mapping
│   │                                       #      （探测式 auto；§6.6 mcp+Streamable 行）
│   ├── trace.py                            # [改] log_response/_truncate 增 content_encoding（压缩体二进制语义）
│   └── api/
│       ├── proxy.py                        # [改] mcp 分发注释定稿（GET /mcp → SSE 解析管线论证，无 transport 字段）
│       └── mgmt.py                         # [改] test 接口 mcp 分支 → probe_mcp_mapping（探测式 auto）
├── tests/
│   ├── unit/
│   │   ├── test_mcp_sse.py                 # [改] 单行上限降级透传用例 ×3
│   │   ├── test_mcp_streamable.py          # [新] _first_message_data 纯逻辑用例
│   │   └── test_trace.py                   # [改] 压缩体二进制语义用例
│   └── integration/
│       ├── mock_upstream.py                # [改] echo 增 /api/v1/gzip-text（gzip 响应端点）
│       ├── mock_mcp_sse.py                 # [改] 增 /sse-gzip-html（plain 分支 gzip）+ /sse-slow-hello（probe 总期限用例）
│       ├── mock_mcp_streamable.py          # [新] 最小 MCP Streamable 上游（uvicorn 9903）
│       ├── conftest.py                     # [改] mcp_streamable_upstream_server(9903) 夹具
│       ├── test_mcp_streamable_upstream.py # [新] mock 上游直连冒烟
│       ├── test_proxy_encoding.py          # [新] accept-encoding 回归（M2/M3 两管线，真实 TCP）
│       ├── test_proxy_mcp_sse.py           # [改] 中止路径无 response 行用例（Minor 统一）
│       ├── test_proxy_mcp_streamable.py    # [新] Streamable 全链路（真实 TCP）
│       └── test_mgmt_test_endpoint.py      # [改] mcp probe 探测式 auto：新增/迁移用例
└── README.md                               # [改] 接口速览 + Inspector Streamable 联调指引
```

---

### Task 1: accept-encoding 透明性（M4 前置硬项）——全管线 aiter_raw 压缩字节透传 + trace 压缩体二进制语义

**Files:**
- Modify: `src/agent_proxy/forward/http_forward.py`（`_response_stream` aiter_raw + trace content_encoding）
- Modify: `src/agent_proxy/forward/mcp_sse.py`（`_plain_stream` / `_sse_stream` / `_first_endpoint` aiter_raw）
- Modify: `src/agent_proxy/trace.py`（`log_response` / `_truncate` 增 `content_encoding`）
- Modify: `tests/integration/mock_upstream.py`（echo 增 gzip 端点）
- Modify: `tests/integration/mock_mcp_sse.py`（增 `/sse-gzip-html`）
- Modify: `tests/unit/test_trace.py`
- New: `tests/integration/test_proxy_encoding.py`

- [ ] **Step 1: 写失败测试**

`tests/unit/test_trace.py` 末尾追加：

```python
def test_compressed_body_recorded_as_binary(tmp_path):
    """M4 accept-encoding 配套：压缩传输编码下的响应体为压缩字节，按文本解码必乱码
    ——content_encoding 非空时走二进制路径（只记 body_bytes），与既有非文本
    Content-Type 行为一致。"""
    path = _capture(tmp_path, "body")
    trace.log_response("r1", 200, 12, body=b"\x1f\x8b\x08\x00binary",
                       content_type="application/json", content_encoding="gzip")
    recs = _read(path)
    assert recs[0] == {"ts": recs[0]["ts"], "request_id": "r1", "phase": "response",
                       "status": 200, "duration_ms": 12,
                       "body_bytes": 8, "body_skipped": "binary"}
```

`tests/integration/test_proxy_encoding.py`（新文件）：

```python
"""accept-encoding 透明性回归（M4 前置硬项）：上游启用 gzip 时代理必须按压缩
字节透传（aiter_raw），响应头保真——头体一致，严格客户端（uvicorn/h11 侧）不再
因「解压体超过声明 content-length」断连报错。覆盖 M2 http 管线与 M3 SSE 管线
plain 分支两条路径。

必须真实 TCP（uvicorn 9910）：只有真实服务器按声明 content-length 校验响应体
（h11 "Too much data"），ASGI 直连无此强校验，抓不住「头体不一致」缺陷。
测试侧 httpx 同样会按响应头自动解压，故用 aiter_raw 读线上原始字节断言。
"""
import gzip

import httpx

from tests.utils import make_token

PROXY = "http://127.0.0.1:9910"
AUTH = {"Authorization": f"Bearer {make_token('u888')}"}
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)


async def _register(user, payload):
    payload = {"headers": {"Authorization": "Bearer sk-enc-12345678"}, **payload}
    async with httpx.AsyncClient() as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json=payload,
                            headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _raw_response(method: str, url: str, headers: dict):
    """经代理取响应：返回 (status, headers, 线上原始字节)——aiter_raw 不解压。"""
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream(method, url, headers=headers) as resp:
            raw = b"".join([chunk async for chunk in resp.aiter_raw()])
            return resp.status_code, dict(resp.headers), raw


async def test_http_pipeline_gzip_body_passthrough_bytes_exact():
    """M2 _response_stream：上游 gzip 响应字节级透传 + 响应头保真（头体一致）。

    修复前：aiter_bytes 自动解压（明文体 > 声明 content-length），真实链路上
    代理侧 uvicorn/h11 报 "Too much data" 断连；修复后压缩字节原样透传。
    """
    created = await _register("u888", {"type": "http",
                                       "upstream_url": "http://127.0.0.1:9901/api/v1"})
    status, headers, raw = await _raw_response(
        "GET", f"{PROXY}/p/{created['mapping_id']}/gzip-text", AUTH)
    assert status == 200
    assert headers["content-encoding"] == "gzip"
    declared = int(headers["content-length"])
    assert declared == len(raw), "响应体必须等于声明的压缩长度（头体一致）"
    assert raw.startswith(b"\x1f\x8b")                       # gzip magic：未解压的压缩字节
    assert gzip.decompress(raw) == b"gzip-upstream-payload-" * 40


async def test_sse_pipeline_plain_branch_gzip_passthrough_bytes_exact():
    """M3 SSE 管线 plain 分支（非 event-stream 响应原样回传路径）同样 aiter_raw。"""
    created = await _register("u888", {"type": "mcp",
                                       "upstream_url": "http://127.0.0.1:9902/sse-gzip-html"})
    status, headers, raw = await _raw_response(
        "GET", f"{PROXY}/p/{created['mapping_id']}/sse-gzip-html", AUTH)
    assert status == 200
    assert headers["content-encoding"] == "gzip"
    assert int(headers["content-length"]) == len(raw)
    assert raw.startswith(b"\x1f\x8b")
    assert b"upstream-gzip-html" in gzip.decompress(raw)
```

- [ ] **Step 2: mock 上游增 gzip 端点**

`tests/integration/mock_upstream.py`：模块顶部 import 区加 `import gzip`；在 `@app.get("/api/v1/status/{code}")` 路由之后、`/api/v1` 兜底回显路由之前插入（必须先注册先匹配）：

```python
    @app.get("/api/v1/gzip-text")
    async def gzip_text():
        # M4 前置硬项（accept-encoding 透明性）：上游主动 gzip——httpx 出站默认
        # accept-encoding: gzip, deflate 下真实上游会压缩响应；代理必须按压缩字节
        # 透传（aiter_raw）并保真响应头（content-encoding/content-length 为压缩侧值）。
        # Starlette 按 body 自动设 content-length=压缩长度，与手动声明的
        # content-encoding 组成「头体一致」的压缩响应。
        payload = b"gzip-upstream-payload-" * 40
        return Response(content=gzip.compress(payload), media_type="text/plain",
                        headers={"content-encoding": "gzip"})
```

`tests/integration/mock_mcp_sse.py`：模块顶部 import 区加 `import gzip`；在 `build_mcp_sse_app` 内 `/sse-503` 路由之后插入：

```python
    @app.get("/sse-gzip-html")
    async def sse_gzip_html():
        # M4 accept-encoding 回归：注册端点路径返回 200 + gzip HTML（非
        # event-stream）——进 SSE 管线 plain 分支（原样回传），压缩字节透传、
        # 响应头保真（与 /sse-503 同路径不同编码，plain 分支双覆盖）
        body = gzip.compress(b"<html><body>upstream-gzip-html</body></html>")
        return Response(content=body, media_type="text/html",
                        headers={"content-encoding": "gzip"})
```

- [ ] **Step 3: 实现（aiter_raw 统一 + trace content_encoding）**

`src/agent_proxy/trace.py`：`_truncate` 与 `log_response` 改为（其余不动）：

```python
def _truncate(body: bytes | str, content_type: str = "",
              content_encoding: str = "") -> dict:
    ct = content_type.lower().split(";")[0].strip()
    # +json 后缀（如 application/vnd.api+json）与 yaml 属文本，不能当二进制丢弃
    is_text = ct.startswith(_TEXT_TYPES) or ct.endswith("+json") or ct == "application/yaml"
    # M4：压缩传输编码（gzip/deflate…）下 body 为压缩字节（aiter_raw 透传），
    # 按文本解码必乱码——一律走二进制路径只记字节数
    if content_encoding or (content_type and not is_text):
        size = len(body) if isinstance(body, bytes) else len(body.encode("utf-8"))
        return {"body_bytes": size, "body_skipped": "binary"}
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    raw = text.encode("utf-8")
    truncated = len(raw) > _max_body
    if truncated:
        text = raw[:_max_body].decode("utf-8", "replace")
    return {"body": text, "body_truncated": truncated}
```

```python
def log_response(request_id: str, status: int, duration_ms: int,
                 headers: dict[str, str] | None = None, body: bytes = b"",
                 content_type: str = "", content_encoding: str = "") -> None:
    if _mode == "off":
        return
    record: dict = {"request_id": request_id, "phase": "response",
                    "status": status, "duration_ms": duration_ms}
    if headers is not None:
        record["headers"] = _headers_for_log(headers, body_mode=(_mode == "body"))
    if _mode == "body":
        record.update(_truncate(body, content_type, content_encoding))
    _write(record)
```

`src/agent_proxy/forward/http_forward.py` 两处：

1. 删除模块级常量 `_STREAM_CHUNK = 64 * 1024`（无参 aiter_raw 后无消费者）；
2. `_response_stream` 整体替换为：

```python
    async def _response_stream():
        nonlocal stream_broken
        try:
            # M4 accept-encoding 透明性（M3 已知限制 9 定稿修复）：aiter_raw 无参
            # 透传压缩字节（不解压、按网络到达块即时产出）——响应头按原样回传时
            # 头体一致（content-encoding/content-length 为压缩侧值），严格客户端
            # 不再因「解压体 > 声明 content-length」断连。禁用带 chunk_size 的调用：
            # ByteChunker 攒_buf 不足即不产出，会破坏 SSE 形态响应的增量下发
            # （M3 已实测同款缺陷）。无 content-encoding 时与 aiter_bytes 等价。
            async for chunk in upstream_resp.aiter_raw():
                if capture_limit and len(resp_capture) < capture_limit:
                    resp_capture.extend(chunk[: capture_limit - len(resp_capture)])
                yield chunk
        except httpx.HTTPError as exc:
            # 流中断可观测（评审 Important 项，设计 §10）：响应头已发出无法改写
            # 状态码，客户端表现为连接截断；计数 + 异常日志留痕
            stream_broken = True
            metrics.upstream_errors_total.labels(type=metrics_type, code="stream_broken").inc()
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
                resp_ce = next((v for k, v in resp_headers.items()
                                if k.lower() == "content-encoding"), "")
                # 压缩体为压缩字节：trace 走二进制语义只记字节数（M4 配套）
                trace.log_response(request_id, upstream_resp.status_code, duration_ms,
                                   headers=dict(resp_headers), body=bytes(resp_capture),
                                   content_type=resp_ct, content_encoding=resp_ce)
            else:
                trace.log_response(request_id, upstream_resp.status_code, duration_ms)
```

`src/agent_proxy/forward/mcp_sse.py` 三处 `aiter_bytes()` → `aiter_raw()`（各补一行注释「M4：压缩字节透传（见 http_forward._response_stream 注释），无参保持到达粒度」）：

- `_plain_stream` 内：`async for chunk in upstream_resp.aiter_raw():`
- `_sse_stream` 内：`async for chunk in upstream_resp.aiter_raw():`（原「无参按网络到达块即时产出」注释语义保留）
- `probe_sse_mapping._first_endpoint` 内：`async for chunk in resp.aiter_raw():`（探测读体与转发管线同规——「测的即真实路径」）

- [ ] **Step 4: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_trace.py tests/integration/test_proxy_encoding.py -p no:cacheprovider -q`
Expected: 全部 PASS（含既有 trace 用例）。两条 gzip 用例在真实 TCP 上字节级相等。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **249** = 基线 246 + 新增 3，以实际为准）——既有 SSE/HTTP 全链路用例是 aiter_raw 换装的天然回归面（无 content-encoding 时与 aiter_bytes 行为等价）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "fix(M4): accept-encoding 透明性——全管线 aiter_raw 压缩字节透传 + trace 压缩体二进制语义" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 2: probe 超时语义定稿 + M3 遗留 Minor 批（中止 trace 统一 / Connection 小写 / 单行上限 / 设计注记回写）

**Files:**
- Modify: `src/agent_proxy/forward/mcp_sse.py`（probe 总期限共享；中止路径不写 response 行；`Connection` 小写键；`SseEndpointRewriter` 单行上限）
- Modify: `tests/integration/mock_mcp_sse.py`（增 `/sse-slow-hello` 总期限用例端点）
- Modify: `tests/unit/test_mcp_sse.py`（单行上限用例 ×3）
- Modify: `tests/integration/test_proxy_mcp_sse.py`（中止 trace 用例）
- Modify: `tests/integration/test_mgmt_test_endpoint.py`（probe 总期限用例）
- Modify: `docs/superpowers/specs/2026-11-21-agent-proxy-design.md`（§6.6 总挂钟期限注记；§8.1 第 7 条 / §8.3 SSE 重定向注记）

- [ ] **Step 1: 写失败测试（单行上限 + 中止 trace + probe 总期限）**

`tests/unit/test_mcp_sse.py`：import 行改为
`from agent_proxy.forward.mcp_sse import (MAX_LINE_BYTES, SseEndpointRewriter, build_origin_target, registered_endpoint_path)`
末尾追加：

```python
# ---------- M3 遗留 Minor（M4 落地）：单行缓冲上限——无换行超长行降级透传 ----------


def test_rewriter_overlong_no_newline_line_degrades_to_passthrough():
    """无换行超长行（> MAX_LINE_BYTES 上限）：降级原样透传已缓冲字节并进入透传
    模式——内存有界、字节级保真，且不产 trace 记录（降级行不改写）。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    assert rw.feed(b"event: endpoint\ndata: ") == []            # 半行缓冲
    blob = b"x" * (MAX_LINE_BYTES + 16)
    out = rw.feed(blob)                                          # 无换行且超上限
    assert out == [b"event: endpoint\ndata: " + blob]            # 已缓冲字节原样冲出
    assert rw.take_trace_records() == []


def test_rewriter_overflow_mode_resumes_normal_parsing_after_line_end():
    """透传模式持续到行尾：超长行的残余字节原样透传，行尾之后恢复正常解析
    （后续 endpoint 事件照常改写）。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    head = b"event: endpoint\ndata: "
    blob = b"x" * (MAX_LINE_BYTES + 16)
    produced = []
    produced += rw.feed(head)
    produced += rw.feed(blob)                    # 超限：冲出 head+blob，进入透传模式
    produced += rw.feed(b"\n")                   # 超长行行尾：残余原样透传，模式复位
    produced += rw.feed(b"event: endpoint\ndata: /messages?sid=1\n\n")
    produced += rw.flush()
    assert produced == [head + blob, b"\n", b"event: endpoint\n",
                        b"data: /p/m1m2m3m4m5m6/messages?sid=1\n", b"\n"]


def test_rewriter_flush_after_overflow_passthrough_remaining():
    """透传模式下流结束：EOF 残余（超长行末段）原样透传。"""
    rw = SseEndpointRewriter("m1m2m3m4m5m6")
    rw.feed(b"y" * (MAX_LINE_BYTES + 4))         # 超限冲出 + 进入透传模式
    assert rw.feed(b"tail-no-newline") == []
    assert rw.flush() == [b"tail-no-newline"]
```

`tests/integration/test_proxy_mcp_sse.py` 末尾追加：

```python
async def test_sse_same_origin_abort_writes_no_response_trace_row(tmp_path):
    """M3 遗留 Minor（M4 落地）：同源 30x 中止（502）不写 trace response 行——
    该 30x 从未下发给客户端，与 http 管线 TOO_MANY_REDIRECTS 中止语义统一
    （仅 request 行留痕，502 由错误体与审计表达）。"""
    import json as jsonlib
    import logging

    from agent_proxy.logging_setup import flush_trace

    created = await _register_mcp(upstream_url=f"{UPSTREAM_BASE}/sse-redirect-same")
    mid = created["mapping_id"]
    handler_target = tmp_path / "trace.log"
    logger = logging.getLogger("agent_proxy.trace")
    saved = logger.handlers
    logger.handlers = [logging.FileHandler(handler_target, encoding="utf-8")]
    try:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            r = await c.get(f"{PROXY}/p/{mid}/sse-redirect-same", headers=AUTH)
    finally:
        logger.handlers = saved
    assert r.status_code == 502
    flush_trace()
    recs = [jsonlib.loads(x) for x in
            handler_target.read_text(encoding="utf-8").splitlines() if x.strip()]
    ids = {r["request_id"] for r in recs if r.get("mapping_id") == mid}
    rows = [r for r in recs if r["request_id"] in ids]
    assert [r for r in rows if r["phase"] == "request"], "中止路径仍应留 request 行"
    assert not [r for r in rows if r["phase"] == "response"], "中止（502）不写 response 行"
```

`tests/integration/test_mgmt_test_endpoint.py` 末尾追加（5s 级慢用例，suite 已有同类）：

```python
async def test_mcp_sse_probe_total_deadline_shared_across_phases(client, mcp_sse_upstream_server):
    """probe 总挂钟期限定稿（M3 Minor 3 → M4 落地）：send（响应头 3s 到达）与读流
    （endpoint 再 3s）共享 5s deadline——旧分阶段语义（各 5s）会 ~6s 返回 ok=true，
    总期限语义必须 ~5s 即 ok=false。"""
    import time as time_mod

    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-slow-hello")
    t0 = time_mod.monotonic()
    resp = await _test(client, created["mapping_id"])
    elapsed = time_mod.monotonic() - t0
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 200
    assert "总期限" in body["detail"]
    assert elapsed < 5.8, f"probe 应在总期限 ~5s 内返回，实际 {elapsed:.1f}s"
```

- [ ] **Step 2: mock 上游增总期限用例端点**

`tests/integration/mock_mcp_sse.py` 在 `/sse-eof-no-endpoint` 路由之后插入：

```python
    @app.get("/sse-slow-hello")
    async def sse_slow_hello():
        # M4 probe 总期限定稿用例：响应头迟到 3s（handler 内 sleep，send 阶段耗时）
        # + endpoint 事件再迟 3s（读流阶段耗时）= 总 6s > 5s 总期限。旧「分阶段
        # 5s×2」语义会 ok=true（~6s 返回）；总期限语义必 ok=false（~5s 即决）。
        # 头后立即发一条注释行证明流已启动（区别于上游整体无响应的 /slow 路径）。
        async def gen():
            yield b": stream started\n\n"
            await asyncio.sleep(3)
            yield b"event: endpoint\ndata: /messages?session_id=slow\n\n"
            await asyncio.sleep(3)
            yield b"event: message\ndata: {}\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")
```

- [ ] **Step 3: 实现（mcp_sse.py 四组改动）**

3a. `SseEndpointRewriter` 单行上限。模块级常量（`log = ...` 之后）：

```python
# 单行缓冲上限（M3 遗留 Minor）：无换行超长行降级透传，防无界累积。SSE 正常
# 行（endpoint 值 / JSON-RPC data 行）远小于该值；超限即冲出已缓冲字节并持续
# 原样透传至行尾，行尾后恢复正常解析（字节级保真，仅放弃改写）
MAX_LINE_BYTES = 1024 * 1024
```

`__init__` 增一行 `self._overflow = False  # 无换行超长行的降级透传模式`；`feed` / `flush` 整体替换：

```python
    def feed(self, chunk: bytes) -> list[bytes]:
        self._buffer += chunk
        lines: list[bytes] = []
        while True:
            idx = self._buffer.find(b"\n")
            if idx < 0:
                if len(self._buffer) > MAX_LINE_BYTES:
                    # 无换行超长行：冲出已缓冲字节原样透传，直至行尾持续透传
                    # （内存有界；事件名复位——该行不可能再参与改写）
                    lines.append(self._buffer)
                    self._buffer = b""
                    self._overflow = True
                    self._current_event = ""
                break
            line = self._buffer[: idx + 1]           # 含行尾 \n
            self._buffer = self._buffer[idx + 1:]
            if self._overflow:
                lines.append(line)                   # 超长行残余：原样透传至行尾
                self._overflow = False               # 行尾之后恢复正常解析
                continue
            lines.append(self._handle_line(line))
        return lines

    def flush(self) -> list[bytes]:
        """流结束时冲出无行尾的残留末行（SSE 允许最后一行无换行）；透传模式下
        残余属超长行末段，原样透传。"""
        rest, self._buffer = self._buffer, b""
        if not rest:
            return []
        if self._overflow:
            self._overflow = False
            return [rest]
        return [self._handle_line(rest)]
```

3b. `stream_sse_forward` 两处：`outbound["Connection"] = "close"` 改为 `outbound["connection"] = "close"`（原注释保留，追加「键与 build_outbound_headers 小写归一一致（M3 Minor，无行为差异——httpx 头大小写不敏感，仅一致化）」）；trace 中止统一见下方 Step 3c 的段重组。

3c. trace 中止统一：`stream_sse_forward` 从 `is_sse = ...` 到 `_sse_stream` 定义前的段重组（唯一变化是 `trace.log_response` 的位置与中止路径提前 raise）：

```python
    is_sse = status == 200 and "text/event-stream" in resp_ct.lower()

    if not is_sse:
        # 同源重定向防护（§8.1 第 7 条「同源 Location 永不回传」，评审 Issue 1）：
        # SSE 分支不跟随重定向——非 SSE 的 30x 若 Location 与注册 upstream_url 同源，
        # 透传会把注册上游真实 origin 直达调用方，必须中止回 502；跨源重定向属上游
        # 自身行为，透传不变（与 http 管线跨源透传语义一致）
        if upstream_resp.is_redirect:
            location = upstream_resp.headers.get("location") or ""
            try:
                still_same_origin = bool(location) and _origin(
                    httpx.URL(target).join(location)) == _origin(
                    httpx.URL(mapping_data["upstream_url"]))
            except httpx.InvalidURL:
                still_same_origin = False  # 畸形 Location 无 origin 可判，按透传交下游自行处理
            if still_same_origin:
                await upstream_resp.aclose()
                # trace 中止语义统一（M3 Minor → M4 落地）：中止路径不写 response 行
                # ——该 30x 从未下发给客户端，502 由错误体/审计表达（log_request 已
                # 留痕）；与 http 管线 TOO_MANY_REDIRECTS 中止行为完全一致
                raise AppError(502, "TOO_MANY_REDIRECTS",
                               "上游返回同源重定向，已中止转发（Location 不回传）")
        # 非 SSE 响应（上游 4xx/5xx 错误体、跨源 30x 等）：不改写、不计 sse_active，
        # 原样流式回传；response 行在确认真实回传时写（time-to-headers）
        trace.log_response(request_id, status, duration_ms)

        async def _plain_stream():
            try:
                async for chunk in upstream_resp.aiter_raw():
                    yield chunk
            except httpx.HTTPError as exc:
                # 流中断可观测（评审 Issue 3）：与 http 管线 _response_stream 对称
                metrics.upstream_errors_total.labels(type="mcp", code="stream_broken").inc()
                log.exception("上游响应流中断: %s", exc)
                raise
            finally:
                await upstream_resp.aclose()
        return StreamingResponse(_plain_stream(), status_code=status, headers=resp_headers)

    # SSE 握手成立：response 行 = 连接建立记录（time-to-headers；原在分支前统一写，
    # M4 中止语义统一后移至此处——中止路径不再产生误导性的 30x response 行）
    trace.log_response(request_id, status, duration_ms)

    rewriter = SseEndpointRewriter(mapping_id)
    metrics.sse_active.inc()
```

（其后 `_sse_stream` 定义与 try/return 段不变。）

3d. probe 总期限共享（`probe_sse_mapping`）：读流阶段替换为剩余量版本，docstring 超时注记替换：

docstring 中原「超时语义注记（评审 Minor 3，M4 接入 Streamable initialize 探测前需定稿）…」整段替换为：

```python
    超时语义（M4 定稿，替换原「分阶段 5s×2」注记）：TEST_PROBE_TIMEOUT 为**总
    挂钟期限**——send（响应头到达）与读流（首个 endpoint 事件）共享同一 deadline
    （读流仅享剩余量），最坏总挂钟 5s；分项超时先到仍按 httpx 异常映射。
    probe_http_mapping（http probe）同为 wait_for 总期限（单阶段，headers 即决）。
```

读流调用替换为：

```python
    # 总挂钟期限（M4 定稿）：读流阶段只享总 deadline 的剩余量——send 与读流共享
    # TEST_PROBE_TIMEOUT，最坏总挂钟 5s（原分阶段语义最坏 ~10s）
    remaining = max(TEST_PROBE_TIMEOUT - (time.monotonic() - start), 0.05)
    try:
        endpoint_value = await asyncio.wait_for(_first_endpoint(), remaining)
    except asyncio.TimeoutError:
        await resp.aclose()
        return _result(False, status_code,
                       f"未在 {TEST_PROBE_TIMEOUT:.0f}s 总期限内收到 endpoint 事件（非 MCP SSE 端点？）")
```

- [ ] **Step 4: 设计文档注记回写**（`docs/superpowers/specs/2026-11-21-agent-proxy-design.md` 三处）

1. §6.6「**返回**」段中「测试专用短超时 5s」替换为：
   `测试专用短超时 5s（**总挂钟期限**：连接建立与读流 / 读响应各阶段共享同一 deadline，后继阶段仅享剩余时间，最坏 5s 内必有结论）`
2. §8.1 第 7 条末尾追加一句：
   `SSE 初始连接分支一律不跟随（同源 30x 中止 502，Location 不回传），见 §8.3 注记。`
3. §8.3「**SSE 改写实现要点**」段之后新增一段：

```markdown
**SSE 分支重定向策略（M3 落地回写）**：SSE 初始连接不跟随重定向——非 SSE 的 30x 若 `Location` 与注册上游同源，代理中止回 502 `TOO_MANY_REDIRECTS`（同源 `Location` 永不回传 Agent，§8.1 第 7 条）；跨源 30x 属上游自身行为，原样透传。trace 语义：中止路径不写 response 行（该上游响应从未下发给客户端），由 502 错误体与审计日志表达。
```

- [ ] **Step 5: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_mcp_sse.py tests/integration/test_proxy_mcp_sse.py tests/integration/test_mgmt_test_endpoint.py -p no:cacheprovider -q`
Expected: 全部 PASS。新单测 3 条 PASS；`test_sse_same_origin_abort_writes_no_response_trace_row` PASS（实现前 FAIL：旧代码在分支前已写 30x response 行）；`test_mcp_sse_probe_total_deadline_shared_across_phases` PASS 且耗时 ~5s（实现前 FAIL：~6s 返回 ok=true）。既有 `test_mcp_sse_probe_no_endpoint_event_ok_false` 等不受影响（detail 消息含「endpoint」子串兼容）。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **254** = 249 + 单测 3 + 集成 2，以实际为准）。

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "fix(M4): probe 总挂钟期限定稿 + M3 遗留 Minor 批（中止 trace 统一/Connection 小写/SSE 单行上限/设计注记回写）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 3: mock MCP Streamable 上游（uvicorn 9903）+ conftest 夹具 + 独立入口 + 直连冒烟

**Files:**
- New: `tests/integration/mock_mcp_streamable.py`
- Modify: `tests/integration/conftest.py`（`mcp_streamable_upstream_server` 夹具）
- New: `scripts/mock_mcp_streamable_server.py`
- New: `tests/integration/test_mcp_streamable_upstream.py`

- [ ] **Step 1: mock 上游（完整文件）**

`tests/integration/mock_mcp_streamable.py`：

```python
"""最小 MCP Streamable HTTP 上游（测试专用）：经 uvicorn.Server 真实监听 127.0.0.1:9903。

协议形态与官方 MCP Streamable HTTP 服务一致（设计 §8.4 场景）：
- 单一 /mcp 端点，POST 接 JSON-RPC——initialize 返回 application/json +
  `Mcp-Session-Id: sess-m4` 响应头（会话由上游自持，§8.4）；tools/list /
  tools/call 默认返回 JSON 形态，查询参数 `?form=sse`（或路径别名
  /mcp-sse-form）切换为**短 SSE 流形态**（单条 `event: message` 后 EOF），
  覆盖代理对两种响应形态的回传分支；
- 会话语义：非 initialize 的 POST 缺（或错值）`Mcp-Session-Id` 头 → 400
  （代理必须把客户端会话头双向透传：请求侧带上游、响应侧带客户端）；
- notifications（无 id）→ 202 Accepted 无响应体（MCP Streamable 规范形态）；
- GET /mcp：服务端推送流——连接即发一条 `notifications/message` 服务端推送
  事件，随后每 0.2s 发 `: ping` 心跳注释行；
- DELETE /mcp：204 会话结束；
- POST /mcp-no-serverinfo：initialize 可达但 result 缺 serverInfo（非 MCP 端点
  典型形态，§6.6 硬判定 ok=false 用例）；
- POST /mcp-slow：8s 后才回 initialize（> probe 5s 总期限，超时用例）。

模块级 streamable_state 供测试直读（received / deletes / last_get_headers /
last_delete_headers / get_open；测试自行清空；headers dict 为 Starlette 小写键）。
"""
from __future__ import annotations

import asyncio
import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

SESSION_ID = "sess-m4"

streamable_state: dict = {"received": [], "deletes": [],
                          "last_get_headers": {}, "last_delete_headers": {},
                          "get_open": 0}


def _result_for(rpc: dict) -> dict:
    method = rpc.get("method")
    if method == "initialize":
        params = rpc.get("params") or {}
        return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp-streamable", "version": "0.1.0"}}
    if method == "tools/list":
        return {"tools": [{"name": "echo",
                           "description": "回显输入文本",
                           "inputSchema": {"type": "object",
                                           "properties": {"text": {"type": "string"}}}}]}
    if method == "tools/call":
        args = (rpc.get("params") or {}).get("arguments") or {}
        return {"content": [{"type": "text", "text": json.dumps(args, ensure_ascii=False)}]}
    return {"echo": method}


def build_mcp_streamable_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    async def _handle_rpc(request: Request, sse_form: bool):
        rpc = json.loads(await request.body())
        streamable_state["received"].append({
            "rpc": rpc,
            "query": dict(request.query_params),
            "headers": dict(request.headers.items()),
        })
        if rpc.get("method") != "initialize" \
                and request.headers.get("mcp-session-id") != SESSION_ID:
            # 会话由上游自持（§8.4）：代理必须把客户端的 Mcp-Session-Id 原样带到上游
            return JSONResponse({"error": "missing or invalid Mcp-Session-Id"},
                                status_code=400)
        if "id" not in rpc:  # notifications 无 id：202 无响应体（MCP Streamable 规范）
            return Response(status_code=202)
        payload = json.dumps({"jsonrpc": "2.0", "id": rpc["id"],
                              "result": _result_for(rpc)}, ensure_ascii=False)
        if sse_form:
            async def gen():
                yield f"event: message\ndata: {payload}\n\n".encode("utf-8")
            return StreamingResponse(gen(), media_type="text/event-stream")
        return Response(content=payload.encode("utf-8"), media_type="application/json",
                        headers={"mcp-session-id": SESSION_ID})

    @app.post("/mcp")
    async def mcp_post(request: Request):
        return await _handle_rpc(request, sse_form="sse" in request.query_params)

    @app.post("/mcp-sse-form")
    async def mcp_post_sse_form(request: Request):
        # 路径别名：SSE 形态（probe 用例的 upstream_url 走路径别名，不带 query）
        return await _handle_rpc(request, sse_form=True)

    @app.post("/mcp-no-serverinfo")
    async def mcp_post_no_serverinfo():
        # initialize 可达但 result 缺 serverInfo（§6.6 硬判定的失败面）
        return JSONResponse({"jsonrpc": "2.0", "id": 1,
                             "result": {"protocolVersion": "2025-06-18",
                                        "capabilities": {}}})

    @app.post("/mcp-slow")
    async def mcp_post_slow():
        # 8s 后才响应（> TEST_PROBE_TIMEOUT 5s 总期限）：probe 超时用例
        await asyncio.sleep(8)
        return JSONResponse({"jsonrpc": "2.0", "id": 1,
                             "result": {"serverInfo": {"name": "slow", "version": "0"}}})

    @app.get("/mcp")
    async def mcp_get(request: Request):
        streamable_state["last_get_headers"] = dict(request.headers.items())

        async def gen():
            # gen 首行计数：与 finally 的 -1 对称（客户端在首块下发前断开时生成器
            # 未启动、finally 永不执行——同 mock_mcp_sse 的泄漏路径修正）
            streamable_state["get_open"] += 1
            try:
                push = json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                                   "params": {"level": "info", "data": "push-hello"}},
                                  ensure_ascii=False)
                yield f"event: message\ndata: {push}\n\n".encode("utf-8")
                while True:
                    yield b": ping\n\n"
                    await asyncio.sleep(0.2)
            finally:
                streamable_state["get_open"] -= 1

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.delete("/mcp")
    async def mcp_delete(request: Request):
        streamable_state["last_delete_headers"] = dict(request.headers.items())
        streamable_state["deletes"].append({"path": request.url.path,
                                            "query": dict(request.query_params)})
        return Response(status_code=204)

    return app
```

- [ ] **Step 2: conftest 夹具 + 独立入口**

`tests/integration/conftest.py`：import 区加 `from tests.integration.mock_mcp_streamable import build_mcp_streamable_app`；在 `mcp_sse_upstream_server` 夹具之后新增（模式与 9901/9902 夹具一致）：

```python
@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def mcp_streamable_upstream_server():
    """真实 MCP Streamable 上游：uvicorn 真实监听 127.0.0.1:9903（session 级，独立线程 loop）。

    启动/停机模式与 echo(9901)/SSE(9902) 夹具一致：uvicorn.serve() 挂独立线程
    独立 loop，测试用例经真实 TCP 访问（跨 loop 只过网络，无共享 asyncio 对象）。
    autouse 统一随 session 启动（启动成本 ~1s 一次性）。
    """
    config = uvicorn.Config(build_mcp_streamable_app(), host="127.0.0.1", port=9903,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_until_complete, args=(server.serve(),),
                              daemon=True, name="mcp-streamable-upstream-9903")
    thread.start()
    for _ in range(200):
        if server.started or not thread.is_alive():
            break
        await asyncio.sleep(0.05)
    assert server.started, "MCP Streamable 上游启动失败（127.0.0.1:9903 被占用？）"
    yield server
    server.should_exit = True
    thread.join(timeout=10)
    server.force_exit = True  # 兜底：长连接下优雅停机可能超时，强制置位防 join 卡死
    thread.join(timeout=5)
    assert not thread.is_alive(), "MCP Streamable 上游未在 15s 内停机"
    loop.close()
```

`scripts/mock_mcp_streamable_server.py`（新文件，与 `mock_mcp_sse_server.py` 同构）：

```python
"""独立入口：mock MCP Streamable 上游（与 tests/integration/mock_mcp_streamable.py 同一应用）。

用法（Inspector 联调，见 scripts/inspector_m4.md）：
    .venv/Scripts/python.exe scripts/mock_mcp_streamable_server.py          # 监听 127.0.0.1:9903
    .venv/Scripts/python.exe scripts/mock_mcp_streamable_server.py --port 9913   # 自定义端口
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 仓库根（使 tests 包可导入）

import uvicorn  # noqa: E402

from tests.integration.mock_mcp_streamable import build_mcp_streamable_app  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="mock MCP Streamable 上游（Inspector 联调用）")
    parser.add_argument("--port", type=int, default=9903,
                        help="监听端口（默认 9903）")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    uvicorn.run(build_mcp_streamable_app(), host="127.0.0.1", port=args.port,
                log_level="info", access_log=False)
```

- [ ] **Step 3: 直连冒烟测试**

`tests/integration/test_mcp_streamable_upstream.py`（新文件）：

```python
"""mock MCP Streamable 上游直连冒烟（真实 TCP 127.0.0.1:9903）：不经代理先钉住
mock 自身协议形态，代理链路测试（test_proxy_mcp_streamable.py）才有可信参照。"""
import json

import httpx

from tests.integration.mock_mcp_streamable import streamable_state

BASE = "http://127.0.0.1:9903"
SESSION = {"Mcp-Session-Id": "sess-m4"}


async def test_post_initialize_returns_json_and_session_header():
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{BASE}/mcp",
                         json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": "2025-06-18"}})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["mcp-session-id"] == "sess-m4"
    assert r.json()["result"]["serverInfo"]["name"] == "mock-mcp-streamable"


async def test_post_without_session_rejected_400():
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{BASE}/mcp",
                         json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert r.status_code == 400


async def test_post_notification_returns_202():
    # notifications 无 id：202 无响应体（MCP Streamable 规范形态，mock 钉住）
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{BASE}/mcp",
                         json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                         headers=SESSION)
    assert r.status_code == 202


async def test_post_tools_call_sse_form_short_stream():
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{BASE}/mcp?form=sse",
                         json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                               "params": {"name": "echo", "arguments": {"text": "hi"}}},
                         headers=SESSION)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    data_lines = [x for x in r.text.splitlines() if x.startswith("data:")]
    assert len(data_lines) == 1                      # 短流：单条 message 后 EOF
    msg = json.loads(data_lines[0][len("data:"):].strip())
    assert msg["id"] == 3 and "hi" in json.dumps(msg["result"])


async def test_get_mcp_push_stream_first_event_then_heartbeat():
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5, read=5, write=5, pool=5)) as c:
        async with c.stream("GET", f"{BASE}/mcp",
                            headers={**SESSION, "Accept": "text/event-stream"}) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            saw_push, saw_ping = False, False
            async for line in resp.aiter_lines():
                if line.startswith("data:"):
                    push = json.loads(line[len("data:"):].strip())
                    assert push["method"] == "notifications/message"
                    assert push["params"]["data"] == "push-hello"
                    saw_push = True
                if line.startswith(": ping"):
                    saw_ping = True
                if saw_push and saw_ping:
                    break
            assert saw_push and saw_ping
    assert streamable_state["get_open"] == 0         # 客户端断开 → mock 生成器 finally 执行


async def test_delete_mcp_204():
    async with httpx.AsyncClient() as c:
        r = await c.delete(f"{BASE}/mcp", headers=SESSION)
    assert r.status_code == 204
```

- [ ] **Step 4: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_mcp_streamable_upstream.py -p no:cacheprovider -q`
Expected: 6 passed（夹具随 session autouse 启动 9903）。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **260** = 254 + 6，以实际为准）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(M4): mock MCP Streamable 上游（uvicorn 9903）+ 夹具 + 独立入口 + 直连冒烟" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 4: mcp test 探测式 auto——`forward/mcp_streamable.py`（Streamable initialize 硬判定 + SSE 回落）+ mgmt 分发迁移

**Files:**
- New: `src/agent_proxy/forward/mcp_streamable.py`
- Modify: `src/agent_proxy/api/mgmt.py`（test 路由 mcp 分支 → `probe_mcp_mapping`）
- New: `tests/unit/test_mcp_streamable.py`
- Modify: `tests/integration/test_mgmt_test_endpoint.py`（新增 Streamable 用例 + 迁移 2 条既有用例）
- Modify: `docs/superpowers/specs/2026-11-21-agent-proxy-design.md`（§6.6 探测式 auto 注记）

- [ ] **Step 1: 写失败测试**

`tests/unit/test_mcp_streamable.py`（新文件）：

```python
"""mcp_streamable 纯逻辑单测：SSE 形态 initialize 响应的首个 message data 提取
（§6.6 硬判定的输入；与 SseEndpointRewriter / probe_sse 的行解析同风格）。"""
from agent_proxy.forward.mcp_streamable import _first_message_data


def test_first_message_data_explicit_event():
    raw = b"event: message\ndata: {\"result\": 1}\n\n"
    assert _first_message_data(raw) == b'{"result": 1}'


def test_first_message_data_default_unnamed_event_accepted():
    assert _first_message_data(b"data: {\"x\": 2}\n\n") == b'{"x": 2}'


def test_first_message_data_blank_line_resets_event_name():
    """空行复位事件名（与转发解析器同规）：`event: endpoint` 块后的 data 行不被误取。"""
    raw = b"event: endpoint\ndata: /messages\n\ndata: {\"ok\": 3}\n\n"
    assert _first_message_data(raw) == b'{"ok": 3}'


def test_first_message_data_none_without_data_line():
    assert _first_message_data(b": comment only\n\n") is None
    assert _first_message_data(b"event: message\n\n") is None
```

`tests/integration/test_mgmt_test_endpoint.py` 末尾追加：

```python
# ---------- M4：mcp test 探测式 auto（先 Streamable initialize，拒绝 POST 回落 SSE） ----------


async def test_mcp_streamable_probe_ok(client, mcp_streamable_upstream_server):
    """§6.6 mcp+Streamable：POST initialize → 200 JSON 含 serverInfo → ok=true。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert "Streamable initialize 成功" in body["detail"]
    assert "mock-mcp-streamable" in body["detail"]       # serverInfo.name 回告
    assert body["latency_ms"] >= 0


async def test_mcp_streamable_probe_sse_form_ok(client, mcp_streamable_upstream_server):
    """initialize 以短 SSE 流形态响应（Streamable 允许）：首个 message 事件含
    serverInfo 同样通过（JSON / SSE 两形态判定均覆盖）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp-sse-form")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert "Streamable initialize 成功" in body["detail"]


async def test_mcp_streamable_probe_no_serverinfo_ok_false(client, mcp_streamable_upstream_server):
    """POST 被接受（200 JSON）但 result 缺 serverInfo——§6.6 硬判定 ok=false
    （不回落 SSE：POST 未被拒绝，端点只是非 MCP）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp-no-serverinfo")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 200
    assert "缺少 serverInfo" in body["detail"]


async def test_mcp_streamable_probe_timeout_ok_false_no_5xx(client, mcp_streamable_upstream_server):
    """Streamable 上游可达但 initialize 8s 不响应（> 5s 总期限）：ok=false，
    不产生代理 5xx，也不回落（超时 ≠ 拒绝 POST）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp-slow")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200                       # 上游失败不变成代理 5xx（§6.6）
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None
    assert "超时" in body["detail"]


async def test_mcp_streamable_probe_upstream_down_ok_false(client):
    """上游不可达（9909 不存在端口）：ok=false + status_code=None，不抛 502。"""
    created = await _register(client, type="mcp", upstream_url="http://127.0.0.1:9909/mcp")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None and "不可达" in body["detail"]


async def test_mcp_probe_fallback_non_sse_ok_false(client, mcp_sse_upstream_server):
    """回落路径：SSE-only 上游对 POST 回 405 → SSE 握手探测 → 注册端点回非 SSE
    （503 html）→ ok=false 且 detail 不含 Location（真实 origin 不外泄）；
    detail 前缀回告「SSE 端点」来源供排障。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-503")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 503
    assert "非 SSE 响应" in body["detail"]
    assert "SSE 端点" in body["detail"]
    assert "9902/sse" not in body["detail"]
```

- [ ] **Step 2: 实现 probe 模块（完整文件）**

`src/agent_proxy/forward/mcp_streamable.py`（上半：模块头 + 纯逻辑）：

```python
"""MCP Streamable HTTP 探测（设计 §6.6 mcp+Streamable 行 / §8.4）。

M4 定稿：**Streamable 转发本身复用 §8.5 统一管线**（POST/DELETE 按上游 origin
根还原走 stream_http_forward；GET 注册端点走 stream_sse_forward 字节透传，见
api/proxy.py 分发注释），本模块只承载 test 接口的端点形态细分（探测式 auto）：

- 先按 Streamable 语义 POST 标准 initialize JSON-RPC；2xx 且响应体（JSON 形态
  直接解析；SSE 形态取首个 message 事件的 data）为含 serverInfo 的 JSON-RPC
  result → ok=true（§6.6 硬性判定）；
- 端点以 405/404/406 拒绝 POST（SSE-only 上游对注册端点 POST 的典型行为）→
  回落 probe_sse_mapping（SSE 握手探测，§8.3）；
- 其余非 2xx（401/500 等）直接判失败不回落——凭据失效等应显式暴露，不掩盖为
  形态回落。

超时语义与 probe_sse_mapping 同规：TEST_PROBE_TIMEOUT 为**总挂钟期限**（send
与读响应共享同一 deadline，读响应仅享剩余量）。探测需解析 initialize 响应体，
出站钉 `accept-encoding: identity` 读明文（与转发管线的 aiter_raw 压缩透传不
冲突——转发不解析载荷，探测是唯一读体路径）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx

from ..forward.http_forward import TEST_PROBE_TIMEOUT
from ..forward.mcp_sse import probe_sse_mapping
from ..headers import build_outbound_headers

log = logging.getLogger("agent_proxy")

# initialize 响应读取上限：判定只需前缀（serverInfo 响应通常 < 1KB），防异常上游
# 无界响应拖垮探测（超限即止，按截断内容判定）
INITIALIZE_MAX_BYTES = 64 * 1024

_INIT_REQUEST = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "agent-proxy-test", "version": "0"}},
}


class _NotStreamable(Exception):
    """端点拒绝 POST（405/404/406）——SSE-only 上游典型形态，触发回落 SSE 探测。"""


def _first_message_data(raw: bytes) -> bytes | None:
    """SSE 形态取首个 message（或未具名）事件的 data 载荷；空行复位事件名
    （与 SseEndpointRewriter / probe_sse 行解析同规）。"""
    current_event = ""
    for line in raw.split(b"\n"):
        text = line.decode("utf-8", "replace").rstrip("\r")
        if text.startswith("event:"):
            current_event = text[len("event:"):].strip()
        elif text.startswith("data:") and current_event in ("", "message"):
            return text[len("data:"):].strip().encode("utf-8")
        elif text == "":
            current_event = ""               # 事件块结束，事件名复位
    return None
```

（下半，同文件续写）：

```python
async def probe_streamable_mapping(app_state, mapping_data: dict) -> dict:
    """mcp+Streamable 类型 test（设计 §6.6）：POST 标准 initialize，硬判定响应
    含 serverInfo（JSON 或短 SSE 两种形态）。上游失败一律 ok=false + detail，
    不抛 502/504；端点拒绝 POST 抛 _NotStreamable 由 probe_mcp_mapping 回落。
    OAuth 绑定用户（M6）以本人凭证走同一规则：注入 Authorization 后复用本函数。
    """
    stored = mapping_data["upstream_headers"] or {}
    headers = build_outbound_headers(stored,
                                     {"Accept": "application/json, text/event-stream"},
                                     "application/json", None, None)
    # 探测需解析响应体：钉 identity 读明文（httpx 默认 gzip 出站 + aiter_raw 会
    # 拿到压缩字节无法解析；转发管线不解析载荷不受影响）
    headers["accept-encoding"] = "identity"
    # 探测连接不复用（与 probe_sse_mapping 同规：读到即断的连接绝不回流 keepalive 池）
    headers["connection"] = "close"
    target = mapping_data["upstream_url"]
    start = time.monotonic()

    def _result(ok: bool, status_code: int | None, detail: str) -> dict:
        return {"ok": ok, "status_code": status_code,
                "latency_ms": int((time.monotonic() - start) * 1000), "detail": detail}

    client: httpx.AsyncClient = app_state.http_client
    try:
        req = client.build_request("POST", target, headers=headers,
                                   content=json.dumps(_INIT_REQUEST).encode("utf-8"),
                                   timeout=TEST_PROBE_TIMEOUT)
        resp = await asyncio.wait_for(client.send(req, stream=True), TEST_PROBE_TIMEOUT)
    except asyncio.TimeoutError as exc:  # 3.11+ 即内置 TimeoutError（wait_for 总期限）
        return _result(False, None,
                       f"上游超时（>{TEST_PROBE_TIMEOUT:.0f}s 总期限）: {type(exc).__name__}")
    except httpx.TimeoutException as exc:  # 分项超时先到（connect/read/pool）
        return _result(False, None, f"上游超时（>{TEST_PROBE_TIMEOUT:.0f}s）: {type(exc).__name__}")
    except httpx.HTTPError as exc:
        return _result(False, None, f"上游不可达: {type(exc).__name__}: {exc}")

    status = resp.status_code
    content_type = next((v for k, v in resp.headers.items()
                         if k.lower() == "content-type"), "")
    if status in (404, 405, 406):
        await resp.aclose()
        raise _NotStreamable()

    ok, detail = await _judge_initialize_response(resp, status, content_type, start)
    await resp.aclose()  # _pump 读到 EOF 已自动关；截断/超限路径兜底（幂等）
    return _result(ok, status, detail)


async def _judge_initialize_response(resp: httpx.Response, status: int,
                                     content_type: str, start: float) -> tuple[bool, str]:
    """读 initialize 响应并硬判定（JSON / 短 SSE 两种形态；§6.6：含 serverInfo）。"""
    buf = bytearray()

    async def _pump() -> None:
        async for chunk in resp.aiter_raw():
            buf.extend(chunk)
            if len(buf) > INITIALIZE_MAX_BYTES:
                return                       # 超限即止：判定只需前缀，截断内容交解析兜底

    remaining = max(TEST_PROBE_TIMEOUT - (time.monotonic() - start), 0.05)
    try:
        await asyncio.wait_for(_pump(), remaining)
    except asyncio.TimeoutError:
        return False, f"上游超时（>{TEST_PROBE_TIMEOUT:.0f}s 总期限，读响应阶段）"
    except httpx.HTTPError as exc:
        return False, f"上游响应读取失败: {type(exc).__name__}: {exc}"

    if "text/event-stream" in content_type.lower():
        data = _first_message_data(bytes(buf))
        if data is None:
            return False, f"initialize SSE 响应无 message 事件（status={status}）"
    else:
        data = bytes(buf)
    try:
        payload = json.loads(data)
    except ValueError:
        return False, (f"initialize 响应非合法 JSON（status={status}，"
                       f"content-type={content_type or '无'}）")
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, dict) or "serverInfo" not in result:
        return False, (f"initialize 响应缺少 serverInfo（status={status}，"
                       "非 MCP Streamable 端点？）")
    server_info = result["serverInfo"]
    name = server_info.get("name", "?") if isinstance(server_info, dict) else "?"
    return True, f"Streamable initialize 成功（serverInfo.name={name}）"


async def probe_mcp_mapping(app_state, mapping_data: dict) -> dict:
    """mcp 类型 test 探测式 auto（M4 定稿）：先 Streamable（POST initialize 硬判定），
    端点拒绝 POST（405/404/406）回落 SSE 握手探测；detail 前缀回告实际判定的
    端点形态供排障。

    选择理由（评审定稿，替代新增 transport 注册字段）：设计 §5.1 无 transport 列，
    新增将连带 schema/建表/缓存/管理 API 变更且要求用户正确填写传输形态（生态
    并存下易错）；端点路径后缀（/mcp）仅惯例非协议（SSE 服务也可注册在 /mcp）；
    以真实协议行为判定误判面最小。
    """
    try:
        return await probe_streamable_mapping(app_state, mapping_data)
    except _NotStreamable:
        result = await probe_sse_mapping(app_state, mapping_data)
        result["detail"] = ("SSE 端点（Streamable initialize 被拒，回落 SSE 握手）→ "
                            + result["detail"])
        return result
```

- [ ] **Step 3: mgmt 分发迁移 + 设计注记**

`src/agent_proxy/api/mgmt.py`：import 区 `from ..forward.mcp_sse import probe_sse_mapping` 删除，改 `from ..forward.mcp_streamable import probe_mcp_mapping`；test 路由 mcp 分支改为：

```python
    if data["type"] == "mcp":
        # mcp test 探测式 auto（M4 定稿，§6.6）：先 Streamable initialize 硬判定，
        # 端点拒绝 POST（405/404/406）回落 SSE 握手探测（理由见 probe_mcp_mapping
        # docstring：不新增 transport 字段、不用路径后缀启发式）
        return await probe_mcp_mapping(request.app.state, data)
    return await probe_http_mapping(request.app.state, data)
```

设计文档 §6.6 在「**返回**」段之后新增一段：

```markdown
**mcp 类型形态细分（M4 定稿，探测式 auto）**：不新增 `transport` 注册字段（§5.1 无此列；端点路径 `/mcp` 仅为生态惯例，SSE 服务亦可注册于 `/mcp`）——test 时先按 Streamable 语义 POST 标准 `initialize`：端点以 405/404/406 拒绝 POST（SSE-only 上游对注册端点 POST 的典型行为）→ 回落 SSE 握手探测（上表第 2 行）；其余响应按「含 `serverInfo`」硬判定（上表第 1 行；响应为 SSE 形态时取首个 `message` 事件的 data 解析）。`detail` 回告实际判定的端点形态（`Streamable initialize 成功…` / `SSE 端点（回落）…`）供排障。
```

- [ ] **Step 4: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_mcp_streamable.py tests/integration/test_mgmt_test_endpoint.py -p no:cacheprovider -q`
Expected: 全部 PASS（单测 4 条 + mgmt 用例全量含迁移后 2 条与新增 6 条）。`test_mcp_streamable_probe_ok` / `_sse_form_ok` / `_no_serverinfo_ok_false` 实现前 FAIL（路由当前按 SSE probe 探测 9903 会判「非 SSE 响应」）。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **269** = 260 + 单测 4 + 集成净增 5（新增 ok / sse-form / no-serverinfo / upstream-down / fallback-non-sse；timeout 为旧用例替换、echo 为改名替换，净 0）= +9，以实际为准）。注意本任务含两条 ~5s 慢用例（总期限 / mcp-slow 超时）。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(M4): mcp test 探测式 auto——Streamable initialize 硬判定 + SSE 回落（§6.6 定稿）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 5: Streamable 转发全链路集成（真实 TCP）+ GET `/p/{id}/mcp` 分发语义定稿注释 + 设计 §8.4 注记

**Files:**
- Modify: `src/agent_proxy/api/proxy.py`（mcp 分发注释定稿——无代码行为变更）
- Modify: `docs/superpowers/specs/2026-11-21-agent-proxy-design.md`（§8.4 代理实现注记）
- New: `tests/integration/test_proxy_mcp_streamable.py`

- [ ] **Step 1: 写失败测试（完整新文件）**

`tests/integration/test_proxy_mcp_streamable.py`（第一批：协议链路）：

```python
"""MCP Streamable HTTP 全链路集成（真实 TCP）：测试客户端 → 真实 uvicorn 代理
（9910）→ 真实 TCP → mock MCP Streamable 上游（9903）。

§8.4：单一 /mcp 端点 POST/GET/DELETE；Mcp-Session-Id 白名单双向透传；JSON 或
SSE 响应均流式回传（无需改写）；GET /mcp 服务端推送流经 SSE 解析管线字节透传
（rewriter 对 Streamable 流无操作——见 api/proxy.py 分发注释与设计 §8.4 注记）。
"""
import asyncio
import json
import re

import httpx

from tests.integration.mock_mcp_streamable import streamable_state
from tests.utils import make_token, sse_line_iter

PROXY = "http://127.0.0.1:9910"
UPSTREAM = "http://127.0.0.1:9903/mcp"
AUTH = {"Authorization": f"Bearer {make_token('u888')}"}
SESSION = {"Mcp-Session-Id": "sess-m4"}
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)

INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "m4-test", "version": "0"}}}


async def _register_streamable(user="u888", **overrides):
    payload = {"type": "mcp", "upstream_url": UPSTREAM,
               "headers": {"Authorization": "Bearer sk-mcp4-12345678"}, **overrides}
    async with httpx.AsyncClient() as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json=payload,
                            headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _sse_active_gauge(metrics_text: str) -> float:
    m = re.search(r"^ap_sse_active_connections ([0-9.]+)$", metrics_text, re.M)
    assert m, "ap_sse_active_connections 不在 metrics 输出中"
    return float(m.group(1))


async def test_initialize_json_response_and_session_header_back_to_client():
    """§8.4 主链路：POST initialize（JSON 响应形态）——响应头 Mcp-Session-Id
    透传回客户端（会话由上游自持，代理无会话状态），出站 header 为存储值。"""
    streamable_state["received"].clear()
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp", json=INITIALIZE, headers=AUTH)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["mcp-session-id"] == "sess-m4"      # 响应侧会话头透传（§8.4）
    assert r.headers.get("x-accel-buffering") == "no"    # §8.1 第 9 条
    assert r.json()["result"]["serverInfo"]["name"] == "mock-mcp-streamable"
    rec = streamable_state["received"][-1]
    assert rec["query"] == {}
    # 出站 header 重建（§8.1 第 1 条）：上游收到存储值，调用方 JWT 不透传
    assert rec["headers"]["authorization"] == "Bearer sk-mcp4-12345678"
    assert not any(v.startswith("stub.") for v in rec["headers"].values())


async def test_tools_list_json_with_session_header_upstream_passthrough():
    """请求侧会话头透传（§8.4）：tools/list 携带 Mcp-Session-Id 经代理原样到达上游。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp",
                         json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                         headers={**AUTH, **SESSION})
    assert r.status_code == 200
    assert [t["name"] for t in r.json()["result"]["tools"]] == ["echo"]
    rec = streamable_state["received"][-1]
    assert rec["headers"]["mcp-session-id"] == "sess-m4"   # 白名单透传（M2 建全的头）
    assert rec["rpc"]["method"] == "tools/list"


async def test_tools_call_sse_form_streamed_back():
    """§8.4「application/json 或 text/event-stream」的 SSE 形态：tools/call 短 SSE
    流经代理流式回传（query 透传切换 mock 形态），JSON-RPC 载荷不改写。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("POST", f"{PROXY}/p/{mid}/mcp?form=sse",
                            json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "echo",
                                             "arguments": {"text": "hello-m4"}}},
                            headers={**AUTH, **SESSION}) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            msg = None
            async for line in sse_line_iter(resp):
                if line.startswith("data:"):
                    msg = json.loads(line[len("data:"):].strip())
                    break
    assert msg is not None and msg["id"] == 3
    assert "hello-m4" in json.dumps(msg["result"])
    rec = streamable_state["received"][-1]
    assert rec["query"] == {"form": "sse"}                 # query 原样透传（origin 根还原）


async def test_get_mcp_push_stream_passthrough_with_sse_pipeline_semantics():
    """§8.4 GET /mcp 服务端推送流：GET 命中注册端点路径 → SSE 解析管线——
    Streamable 流无 endpoint 事件，rewriter 字节级无操作透传；Connection: close
    出站钉住 + sse_active 计入，钉住「一条分发表服务两种传输」的分发语义定稿
    （无 transport 字段，见 api/proxy.py 注释 / 设计 §8.4 注记）。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as mc:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            async with c.stream("GET", f"{PROXY}/p/{mid}/mcp",
                                headers={**AUTH, "Accept": "text/event-stream",
                                         **SESSION}) as resp:
                assert resp.status_code == 200
                assert resp.headers["content-type"].startswith("text/event-stream")
                push = None
                async for line in sse_line_iter(resp):
                    if line.startswith("data:"):
                        push = json.loads(line[len("data:"):].strip())
                        break
                m = await mc.get(f"{PROXY}/metrics")
                assert _sse_active_gauge(m.text) == 1.0    # 推送流计入 SSE 活跃连接
        # 退出 stream 上下文 → 客户端断开 → 代理取消上游（§8.1 第 4 条）
        for _ in range(50):
            if streamable_state["get_open"] == 0:
                break
            await asyncio.sleep(0.1)
        assert streamable_state["get_open"] == 0
        m = await mc.get(f"{PROXY}/metrics")
        assert _sse_active_gauge(m.text) == 0.0
    assert push["method"] == "notifications/message"
    assert push["params"]["data"] == "push-hello"
    get_headers = streamable_state["last_get_headers"]
    assert get_headers["connection"] == "close"            # SSE 管线出站语义钉住
    assert get_headers["mcp-session-id"] == "sess-m4"      # 会话头随 GET 透传


async def test_delete_mcp_204_passthrough():
    """§8.4 DELETE /mcp 会话结束：204 原样透传，会话头透传，路径按 origin 根还原。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.delete(f"{PROXY}/p/{mid}/mcp", headers={**AUTH, **SESSION})
    assert r.status_code == 204
    assert streamable_state["last_delete_headers"]["mcp-session-id"] == "sess-m4"
    assert streamable_state["deletes"][-1]["path"] == "/mcp"
    assert streamable_state["deletes"][-1]["query"] == {}
```

（第二批：错误透传 / 可观测 / 权限，同文件续写）：

```python
async def test_missing_session_header_upstream_400_passthrough():
    """无会话头（mock 400）→ 上游 4xx 原样透传（§10）：状态码与错误体不改写。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp",
                         json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
                         headers=AUTH)                       # 缺 Mcp-Session-Id
    assert r.status_code == 400
    assert "Mcp-Session-Id" in r.text                        # mock 错误体原样


async def test_streamable_trace_body_mode_records_request_and_response(tmp_path):
    """§11.1 body 模式：Streamable POST 的 request/response body 记录（JSON-RPC
    载荷），敏感头指纹化。"""
    import json as jsonlib
    import logging

    from agent_proxy import trace as trace_mod
    from agent_proxy.logging_setup import flush_trace

    created = await _register_streamable()
    mid = created["mapping_id"]
    handler_target = tmp_path / "trace.log"
    logger = logging.getLogger("agent_proxy.trace")
    saved = logger.handlers
    logger.handlers = [logging.FileHandler(handler_target, encoding="utf-8")]
    trace_mod.configure("body", 64 * 1024)
    try:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            r = await c.post(f"{PROXY}/p/{mid}/mcp", json=INITIALIZE, headers=AUTH)
            assert r.status_code == 200
    finally:
        logger.handlers = saved
        flush_trace()
        trace_mod.configure("metadata", 64 * 1024)           # 恢复（集成夹具 lifespan 亦会重配）
    recs = [jsonlib.loads(x) for x in
            handler_target.read_text(encoding="utf-8").splitlines() if x.strip()]
    mine = [r for r in recs if r.get("mapping_id") == mid]
    reqs = [r for r in mine if r["phase"] == "request"]
    assert reqs and reqs[0]["url"] == "http://127.0.0.1:9903/mcp"
    assert '"method": "initialize"' in reqs[0]["body"]       # 请求体记录（body 模式）
    assert "sk-mcp4-12345678" not in jsonlib.dumps(reqs[0])  # 敏感头指纹化
    req_ids = {r["request_id"] for r in reqs}
    rsps = [r for r in recs if r["phase"] == "response" and r["request_id"] in req_ids]
    assert rsps and rsps[0]["status"] == 200
    assert "serverInfo" in rsps[0]["body"]                   # 响应体记录（JSON-RPC 载荷）


async def test_streamable_auth_and_path_security_matrix():
    """权限与路径安全复用既有用例形态（§7 / §8.1 第 8 条 / §10）：无 token 401、
    非注册者 403、dot-segment 400。"""
    created = await _register_streamable(user="u888")
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r401 = await c.post(f"{PROXY}/p/{mid}/mcp",
                            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        r403 = await c.post(f"{PROXY}/p/{mid}/mcp",
                            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                            headers={"Authorization": f"Bearer {make_token('u999')}"})
        r400 = await c.get(f"{PROXY}/p/{mid}/%2e%2e/etc/passwd", headers=AUTH)
    assert r401.status_code == 401 and r401.json()["code"] == "INVALID_TOKEN"
    assert r403.status_code == 403 and r403.json()["code"] == "FORBIDDEN"
    assert r400.status_code == 400 and r400.json()["code"] == "INVALID_PARAM"
```

- [ ] **Step 2: api/proxy.py 分发注释定稿 + 设计 §8.4 注记**

`src/agent_proxy/api/proxy.py`：`if data["type"] == "mcp":` 分支注释整体替换为：

```python
    if data["type"] == "mcp":
        # 路径分发（§8.3 表，M4 起同时服务 Streamable）：仅 GET/HEAD 且命中注册
        # 端点路径 → SSE 解析管线（stream_sse_forward 不转发请求体，故非 GET/HEAD
        # 不走此分支）；其余方法/路径按上游 origin 根还原后复用 http 流式管线。
        # M4 分发语义定稿（不新增 transport 字段）：Streamable 上游的 POST/DELETE
        # （JSON-RPC 调用 / 会话结束）本就走 origin 根还原的 http 管线；GET /mcp
        # （服务端推送流）进 SSE 解析管线——rewriter 仅改写 `event: endpoint` 的
        # data 行，Streamable 流只有 message 事件 → 字节级无操作透传，read=None /
        # Connection: close / sse_active 计数对推送流语义同样成立。一条分发表即可
        # 同时正确服务两种传输；设计 §5.1 无 transport 列，不为零行为差异引入
        # schema/DB/缓存连带变更（评审定稿记录，设计 §8.4 注记同步）。
        # 评审 Issue 2（M3）：裸 origin 注册（端点路径为 /）时根路径 /p/{id} 与
        # /p/{id}/ 同为注册端点——空 sub_path 归一为 / 参与匹配
        sub_path = split_sub_path(request.scope["path"], mapping_id)
        assert_safe_sub_path(sub_path)
        if request.method in ("GET", "HEAD") and \
                (sub_path or "/") == registered_endpoint_path(data["upstream_url"]):
            return await stream_sse_forward(request.app.state, data, request)
        target = build_origin_target(data["upstream_url"], sub_path, request.url.query)
        return await stream_http_forward(request.app.state, data, request,
                                         target_override=target, metrics_type="mcp")
```

（代码本体与现有实现逐字符一致——本步只改注释，集成测试全部 PASS 即验证无回归。）

设计文档 §8.4 末段「`Mcp-Session-Id` 经白名单透传，会话状态由上游自持。」之后新增：

```markdown
> **代理实现注记（M4）**：Streamable 与 SSE 共用同一路径分发表与转发管线（§8.5 统一骨架）——POST/DELETE 按上游 origin 根还原走 http 流式管线；GET 注册端点（服务端推送流）走 SSE 解析管线，其 endpoint 改写器对 Streamable 流为字节级无操作（Streamable 流无 `endpoint` 事件），读超时不设 / 连接不复用 / SSE 活跃连接计数对推送流语义同样成立，故不新增传输形态字段。test 接口按探测式 auto 细分（见 6.6）。
```

- [ ] **Step 3: 运行预期**

Run: `.venv/Scripts/python.exe -m pytest tests/integration/test_proxy_mcp_streamable.py -p no:cacheprovider -q`
Expected: 8 passed。initialize / tools-list / tools-call-SSE / GET 推送流 / DELETE 204 / 无会话 400 / trace body / 权限矩阵全部经真实 TCP 通过；`streamable_state` 断言钉住出站 header（存储还原、会话头双向、JWT 不透传）与 query 透传。

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -q`
Expected: 全部 PASS（约 **277** = 269 + 8，以实际为准）。

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(M4): Streamable 全链路集成（真实 TCP）+ GET /mcp 分发语义定稿注释 + 设计 §8.4 注记" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 6: MCP Inspector Streamable 联调（人工验收清单）+ mock 独立入口复用 + README 更新 + 全量回归

**Files:**
- New: `scripts/inspector_m4.md`
- Modify: `README.md`（接口速览 + Inspector 联调指引）
- （无代码变更——纯文档 + 回归批）

- [ ] **Step 1: Inspector 联调人工验收清单**

`scripts/inspector_m4.md`（新文件）：

````markdown
# M4 MCP Inspector 联调（Streamable HTTP 传输）——人工验收清单

对照设计 §16 M4 验收行：Inspector 以 **Streamable HTTP** 传输经代理完成
initialize / tools/list / tools/call。协议级自动化等价覆盖见
`tests/integration/test_proxy_mcp_streamable.py`。

## 0. 前置

项目根 `.env`（不存在则从以下最小集创建；测试/演示用，生产勿抄）：

```bash
EXTERNAL_BASE=http://127.0.0.1:8800
MYSQL_DSN=mysql+aiomysql://root:123456@127.0.0.1:3306/agent_proxy
REDIS_URL=redis://127.0.0.1:6379/1
SSRF_ALLOW_PRIVATE=true
TRACE_MODE=metadata              # 排障时临时改 body
```

首次运行需建库（MySQL 已有实例，仅建库不动表结构，表由应用 lifespan create_all）：

```bash
mysql -h127.0.0.1 -uroot -p123456 -e "CREATE DATABASE IF NOT EXISTS agent_proxy DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
```

## 1. 启动三个进程

终端 1——代理：

```bash
.venv/Scripts/python.exe -m agent_proxy     # 监听 127.0.0.1:8800
```

终端 2——mock MCP Streamable 上游：

```bash
.venv/Scripts/python.exe scripts/mock_mcp_streamable_server.py    # 监听 127.0.0.1:9903
```

终端 3——MCP Inspector：

```bash
npx @modelcontextprotocol/inspector
```

## 2. 生成 stub token（TOKEN_VERIFY_IMPL=stub 本地身份，不验签）

```bash
.venv/Scripts/python.exe -c "import base64,json; print('stub.'+base64.urlsafe_b64encode(json.dumps({'user_id':'u888','user_name':'inspector-demo'}).encode()).decode().rstrip('=')+'.sig')"
```

下文记为 `<TOKEN>`（Inspector 与注册接口共用）。

## 3. 注册 mcp 映射（Streamable 上游）

```bash
curl -s -X POST http://127.0.0.1:8800/api/v1/mappings \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"type":"mcp","upstream_url":"http://127.0.0.1:9903/mcp","headers":{"Authorization":"Bearer sk-demo-123456"}}'
```

响应 `proxy_url` 应为 `http://127.0.0.1:8800/p/<mapping_id>/mcp`；记 `<mapping_id>`。

（可选）保存前先调 test 接口验证（M4 探测式 auto：先 Streamable initialize）：

```bash
curl -s -X POST http://127.0.0.1:8800/api/v1/mappings/<mapping_id>/test \
  -H "Authorization: Bearer <TOKEN>"
# 预期 {"ok": true, "status_code": 200, ..., "detail": "Streamable initialize 成功（serverInfo.name=mock-mcp-streamable）"}
```

## 4. Inspector 连接（Streamable HTTP 传输）

1. 打开 Inspector UI（默认 http://localhost:6274），左侧连接配置：
   - Transport Type：`Streamable HTTP`
   - URL：`http://127.0.0.1:8800/p/<mapping_id>/mcp`
   - Authentication → Custom Header：名称 `Authorization`，值 `Bearer <TOKEN>`
2. 点击 **Connect**。

预期：连接成功。内部发生了什么——Inspector 向代理 POST initialize（JSON-RPC），
代理按上游 origin 根还原转发到 `http://127.0.0.1:9903/mcp`；上游返回
application/json + `Mcp-Session-Id: sess-m4`，代理把会话头透传回 Inspector；
后续 tools/list / tools/call 携带同一会话头原样透传（载荷零改写，§8.4）。

## 5. 人工验收清单（对照 §16 M4 行）

- [ ] **tools/list**：Tools 标签列出 1 个工具 `echo`（description「回显输入文本」）
- [ ] **tools/call**：运行 `echo`，参数 `{"text":"hello-m4"}` → 结果文本包含 `hello-m4`
- [ ] **（可选）test 接口**：第 3 步的 test 调用返回 ok=true 且 detail 含
      `Streamable initialize 成功`
- [ ] **（可选）Disconnect**：断开后代理无异常堆积，`logs/agent-proxy.log` 可见
      相关连接关闭记录（Inspector 会话结束 DELETE /mcp 的 204 经代理透传；
      mock 独立入口关闭 access log，如需观察上游访问可临时改
      `scripts/mock_mcp_streamable_server.py` 的 `access_log=True`）

## 6. trace 观察（可选，排障向）

`.env` 改 `TRACE_MODE=body` 并重启代理后重复第 4-5 步，`logs/trace.log.*` 同
request_id 下应能看到：

- `phase=request`（POST，`url=http://127.0.0.1:9903/mcp`，Authorization 为指纹，
  body 为 initialize JSON-RPC 全文）
- `phase=response`（status=200，body 含 serverInfo）
- 同一会话的 tools/list / tools/call 各有一对 request/response 行，`Mcp-Session-Id`
  头名在列（值非敏感，body 模式显原值）

## 7. 常见问题

| 现象 | 原因与处理 |
|---|---|
| Connect 后 401 | Custom Header 未配置或拼写错误（stub token 不验签、不过期） |
| Connect 后 400 | mock 会话头校验：Inspector 初始化丢失 Mcp-Session-Id（检查代理未改写响应头；直连 9903 对照） |
| 注册 400（内网/SSRF 拒绝） | `.env` 未设 `SSRF_ALLOW_PRIVATE=true` |
| 9903 被占用 | 结束遗留的 mock 进程（终端 2 Ctrl+C）后重启 |
| Inspector UI 字段对不上 | 以当前版本 UI 为准，关键字段为 Transport Type=Streamable HTTP、URL、Custom Header |
````

- [ ] **Step 2: README 更新**

`README.md`「接口速览」表 mcp 相关两行更新为：

```markdown
| POST | /api/v1/mappings/{id}/test | 配置有效性测试：http 连通 / test_request 严格验证；mcp 探测式 auto（先 Streamable initialize，拒绝 POST 回落 SSE 握手） |
| ANY | /p/{mapping_id}/{path} | 代理转发：http 前缀流式转发（M2）；mcp SSE 传输 + endpoint 事件改写（M3）；mcp Streamable HTTP（M4，POST/GET/DELETE 透传 + 会话头双向透传） |
```

「MCP Inspector 联调（M3）」小节之后追加：

```markdown
## MCP Inspector 联调（M4：Streamable HTTP）

见 `scripts/inspector_m4.md`：以 Streamable HTTP 传输经代理连接 mock MCP 上游
（`scripts/mock_mcp_streamable_server.py`，9903），完成 tools/list 与 tools/call
的人工验收步骤（协议级自动化覆盖见 `tests/integration/test_proxy_mcp_streamable.py`）。
```

- [ ] **Step 3: 全量回归 + 占位扫描**

Run: `.venv/Scripts/python.exe -m pytest -p no:cacheprovider`
Expected: 全部 PASS（**约 277** = 基线 246 + 净增 31，以实际为准；含 2 条 ~5s 慢用例）。特别确认：metrics 标签无 user_id/mapping_id；trace.log 与审计日志无完整凭据值；`sess-m4` 为非敏感测试值可明文（与 M3 `session_id=test123` 同级判定——mock 固定测试会话值，非真实凭据）。

Run: `grep -rn "TODO\|FIXME\|占位" src/agent_proxy/forward/ src/agent_proxy/api/ scripts/ tests/integration/mock_mcp_streamable.py`
Expected: 无匹配（`placeholder` 模块与占位符 header 语义不在上述文件/词表中）。

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs(M4): MCP Inspector Streamable 联调步骤（人工验收清单）+ README 更新（M4 完成）" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## M4 验收清单（对照设计 §16 M4 行 + §8.4 逐条）

- [ ] **§8.4 单一端点 POST**：POST `/p/{id}/mcp` JSON-RPC 经 origin 根还原到上游（test_initialize_json_response_and_session_header_back_to_client：出站 header 存储还原、调用方 JWT 不透传、`x-accel-buffering: no`）；**JSON 响应形态**直接回传；**SSE 响应形态**流式回传（test_tools_call_sse_form_streamed_back，query `form=sse` 透传）
- [ ] **§8.4 GET 推送流**：GET `/p/{id}/mcp` 服务端推送流透传 + 客户端断开取消上游（test_get_mcp_push_stream_passthrough_with_sse_pipeline_semantics：`get_open` 归零 + `sse_active` 1.0→0.0 + 出站 `connection: close` / `mcp-session-id` 钉住）
- [ ] **§8.4 DELETE**：DELETE `/p/{id}/mcp` 204 原样透传（test_delete_mcp_204_passthrough，会话头透传、路径 origin 根还原）
- [ ] **§8.4 会话头**：`Mcp-Session-Id` 白名单双向透传（响应侧回客户端 + 请求侧到上游，两条用例分别断言）；代理无会话状态（session 值由 mock 固定 `sess-m4` 自持，代理零感知）
- [ ] **§8.4 无需改写**：JSON-RPC 载荷零改写（tools/list / tools/call 结果断言；trace body 模式记录 request/response 全文可回放，test_streamable_trace_body_mode_records_request_and_response）
- [ ] **§8.4 实现注记**：一条分发表服务两种传输的论证落位（api/proxy.py 注释 + 设计 §8.4 注记；无 transport 字段、无运行时探测缓存）
- [ ] **§6.6 mcp+Streamable test 可用**：POST initialize 硬判定含 serverInfo（ok=true，JSON 与短 SSE 两形态）；上游不可达 / 超时 / 无 serverInfo / POST 被拒回落 SSE 均有 ok=false 用例，不产生代理 502/504；仅注册者（既有 owner 404 用例延续）
- [ ] **§6.6 总挂钟期限**：5s 总 deadline 注记入设计（send + 读流/读响应共享，读阶段仅享剩余量）；http probe 单阶段 wait_for 确认在位
- [ ] **§16 M4 验收（硬要求）**：Inspector 以 Streamable HTTP 完成 tools/call——`scripts/inspector_m4.md` 人工验收清单（启动代理 + `scripts/mock_mcp_streamable_server.py` → npx Inspector Streamable HTTP 连 `/p/{id}/mcp` + stub token header → tools/list / tools/call）；自动化替代：`tests/integration/test_proxy_mcp_streamable.py` 协议级全链路（initialize / tools/list / tools/call 经真实 TCP）
- [ ] **accept-encoding 透明性（M4 前置硬项）**：gzip 上游响应在 M2 `_response_stream` 与 M3 SSE plain 分支两条管线字节级透传 + 响应头保真（content-length == 实发压缩字节，真实 TCP h11 强校验）；trace 压缩体二进制语义（单测钉住）
- [ ] **M3 Minor 批全部处置**：见下节逐项表
- [ ] **权限与错误码（§10）**：无 token 401、非注册者 403、dot-segment（%2e%2e）400、上游 400（无会话）原样透传——test_streamable_auth_and_path_security_matrix + test_missing_session_header_upstream_400_passthrough
- [ ] **全量回归**：`pytest` 全绿（约 277，基线 246 + 净增 31）
- [ ] **M4 不含**：集成测试补全批次 / OAuth 公共映射 / 管理页面（M5/M6/M7 交付）

## 债务处置节（M3 终审确认的 M4 前置硬项/债务逐项）

| # | 债务/硬项 | 处置 | 落点 |
|---|---|---|---|
| 1 | **accept-encoding 透明性（前置硬项）**：httpx 默认出站 gzip + `aiter_bytes` 自动解压 + 响应头原样透传 → 上游 gzip 时头体不一致（h11 "Too much data"，venv 实测确认），波及 M2/M3 管线 | **本轮修复，选 `aiter_raw()` 方案**（不是出站钉 identity）：零解压成本、保留上游压缩收益、头体一致；全管线四处统一**无参**调用（M2 `_response_stream`、M3 `_plain_stream`/`_sse_stream`、SSE probe `_first_endpoint`）；测试覆盖 M2 与 M3 plain 分支两处字节级透传 + 头保真（真实 TCP h11 强校验）；trace 压缩体二进制语义配套 | Task 1 实现 + `test_proxy_encoding.py` 2 条 + `test_compressed_body_recorded_as_binary` |
| 2 | **probe 超时语义定稿**：SSE probe send 与读流分阶段各 5s（最坏 ~10s）；http probe 已是单阶段 wait_for 总期限 | **定稿为总挂钟期限**：SSE probe 读流改享剩余量（`remaining = 5s − 已耗`）；http probe 确认已在位（单阶段 headers 即决，无第二阶段）；设计 §6.6 注记同步；区分性用例（3s 头 + 3s 事件 = 6s 总）钉住新旧语义差异 | Task 2 实现 + `test_mcp_sse_probe_total_deadline_shared_across_phases` + 设计 §6.6 编辑 |
| 3 | **mcp test 端点形态细分**：mgmt test 路由 mcp 分支需区分 SSE / Streamable 上游（当前对 Streamable 上游 5s 无 endpoint 误判 ok=false） | **探测式 auto**（评审定稿）：先 Streamable POST initialize（405/404/406 → 回落 SSE probe；含 serverInfo 硬判定，SSE 形态取首 message）；不新增 transport 字段（设计 §5.1 无此列）、不用路径后缀启发式（`/mcp` 仅惯例）；detail 回告形态；2 条既有用例迁移保义 | Task 4 新模块 + mgmt 迁移 + 用例迁移/新增 + 设计 §6.6 注记 |
| 4 | **GET `/p/{id}/mcp` 显式分发**：Streamable 推送流进 SSE 管线（rewriter 无 endpoint 事件 = 字节透传 + read=None 恰好兼容），语义归属需定稿 | **定稿：维持一条分发表，不加字段、不建运行时探测缓存**——SSE 解析管线是 Streamable GET 的正确超集（rewriter 字节级无操作 + read=None / Connection: close / sse_active 语义对推送流全部成立），行为零差异下引入 transport 字段（schema/DB/缓存连带）或探测缓存（失效/竞态复杂度）均为负收益；注释论证 + 设计 §8.4 注记 + 集成测试钉住（`connection: close` 出站 + sse_active 计数） | Task 5 api/proxy.py 注释 + 设计 §8.4 注记 + `test_get_mcp_push_stream_passthrough_with_sse_pipeline_semantics` |
| 5a | **M3 Minor：trace 中止路径语义不统一**（SSE 分支中止写 30x response 行 vs http 中止不写） | **统一为「中止不写 response 行」**：`stream_sse_forward` 的 `trace.log_response` 移到中止判定之后（plain 回传与 SSE 握手各自写）；与 http 管线 TOO_MANY_REDIRECTS 中止一致；30x 从未下发故不落 response 行 | Task 2 实现 + `test_sse_same_origin_abort_writes_no_response_trace_row` |
| 5b | **M3 Minor：`outbound["Connection"]="close"` 大写键** | **改小写键**（两处：`stream_sse_forward` + `probe_sse_mapping`）：与 build_outbound_headers 小写归一一致化；无行为差异（httpx 头大小写不敏感），既有 `connection == "close"` mock 断言继续钉住出站语义 | Task 2 实现（3b） |
| 5c | **M3 Minor：SSE 重定向策略（中止 502 不跟随）回写设计** | **回写 §8.1 第 7 条 + §8.3 新增注记**（同源 30x 中止 502 不回传 Location；跨源透传；trace 中止语义） | Task 2 Step 4 设计文档编辑 |
| 5d | **M3 Minor：SseEndpointRewriter._buffer 单行长度上限**（无换行超长行无界累积） | **新增 `MAX_LINE_BYTES = 1MB`**：超限冲出已缓冲字节降级透传直至行尾（字节级保真、放弃改写、不产 trace），行尾后恢复解析；flush 透传模式兜底；3 条单测（降级 / 行尾恢复 / EOF 残余） | Task 2 实现（3a）+ `tests/unit/test_mcp_sse.py` ×3 |
| 5e | **M2 评审遗留：proxy_root 死路由清理复议**（M2 评审已否决删除） | **维持保留**：M2/M3 已在 proxy.py 留有完整注释（`{path:path}` 正则要求尾斜杠 + 裸 origin 根路径走 SSE 管线），M4 分发注释更新时一并保留该论证；无代码变更 | Task 5 api/proxy.py 注释（原注释保留），本表即处置记录 |

## 已知限制（明示接受，均有代码注释对应）

1. **gzip SSE 流的 endpoint 改写失效**（aiter_raw 方案的固有边界）：上游若对 `text/event-stream` 响应再压一层 gzip（生态中几乎不存在——SSE 服务均关压缩），代理按压缩字节透传、响应头保真，但 endpoint 改写与 trace 事件解析失效（代理不透明解压）。现有 SSE mock 上游不压缩，不受影响。
2. **trace body 模式记录压缩响应为二进制语义**（body_bytes / body_skipped=binary）：不透明解压是透明性原则的一部分，排障时可对上游直连比对。
3. **探测式 auto 的判定顺序**：以 POST initialize 是否被拒（405/404/406）为回落信号——若存在「接受 POST 但实为 SSE-only」的非典型上游，会以「缺少 serverInfo」判失败（detail 明示，可用 /test 结果排障）；不猜测、不二次试探其余方法。
4. **探测钉 `accept-encoding: identity`**：极少数强制压缩且忽略 identity 的上游会导致 initialize 解析失败 ok=false（detail 含 content-type 可见）。
5. **Streamable 会话过期语义**：上游对过期会话通常回 404（MCP 规范），代理原样透传（§10 上游 4xx 原样原则）；代理不解释、不刷新会话。
6. **mock 限制**：`/mcp-slow` 请求被探测取消后 mock 侧 handler 仍会睡满 8s（测试进程内无害）；SSE 形态响应为单事件短流（覆盖代理回传分支，不做多事件编排）。

## 自查记录（对照任务要求）

- **§8.4 逐条覆盖**：单一 `/mcp` 端点 POST/GET/DELETE → Task 5 三条方法用例；JSON 或 SSE 响应流式回传 → initialize（JSON）+ tools/call（SSE 形态）两用例；`Mcp-Session-Id` 透传 → 双向两条断言；无需改写 → 载荷断言 + trace body 可回放；均复用 §8.5 统一管线（`stream_http_forward` 的 `target_override`/`metrics_type` 与 `stream_sse_forward` 现有签名，未新增管线 API）。
- **§16 M4 验收**：Inspector Streamable tools/call → Task 6 人工清单 + Task 5 自动化全链路；initialize test 可用 → Task 4。
- **签名一致性**：`probe_streamable_mapping(app_state, mapping_data)` / `probe_mcp_mapping(app_state, mapping_data)` 与既有 `probe_sse_mapping` / `probe_http_mapping` 同构；`build_outbound_headers(stored, caller, ct, cl, ce)`、`TEST_PROBE_TIMEOUT`、`trace.log_response(..., content_type, content_encoding)`（新增参数带默认值，向后兼容）、`metrics.sse_active.inc()/dec()`、`filter_response_headers`、`split_sub_path` / `registered_endpoint_path` / `build_origin_target` 均按现有代码调用，无臆造 API。
- **回归面**：accept-encoding 修复覆盖 M2 `_response_stream`（http 映射 gzip 用例）与 M3 SSE 管线 plain 分支（mcp 注册端点 gzip 用例）两处；SSE 事件流分支由 M3 既有全链路用例回归（无 content-encoding 时 aiter_raw ≡ aiter_bytes）。
- **无占位**：全部代码块为最终形态；迁移用例给出整条替换文本；两处 ~5s 慢用例已显式标注（总期限 / mcp-slow）。
- **端口簿**：9901 echo 上游、9902 MCP SSE mock、9903 MCP Streamable mock（新）、9909 死端口、9910 被测代理——与 conftest/脚本/文档一致。
- **预期计数**：246 → 约 277（Task1 +3 / Task2 +5 / Task3 +6 / Task4 +9 / Task5 +8 / Task6 +0），各任务「运行预期」以实际为准；执行者遇计数偏差应核对用例清单而非放宽断言。
