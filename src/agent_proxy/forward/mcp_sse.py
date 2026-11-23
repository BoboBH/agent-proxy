"""MCP SSE 传输代理（设计 §8.3）。

纯逻辑部分：路径分发辅助（注册端点路径 / 上游 origin 根还原）与 SSE 增量行
解析器 SseEndpointRewriter——按行读取（保留原始行尾 \\r\\n / \\n）、跟踪当前
`event:` 名（空行复位）；`event: endpoint` 的 data: 行改写为 /p/{id}<path>?<query>
下发，其余行（message 事件 / retry: 行 / `:` 心跳注释行 / 字段行）字节级原样
透传，每行产出即交由管线 yield（每行立即 flush，不做整体缓冲）。

流式转发管线 stream_sse_forward 与 test 探测 probe_sse_mapping（§6.6）同在本模块；
trace 记录由解析器产出（take_trace_records），管线层接 trace.log_sse_event。
"""
from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlparse

import httpx
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

from .. import metrics, trace
from ..errors import AppError
from ..forward.http_forward import (TEST_PROBE_TIMEOUT, _origin,  # 同包私有 origin 判定 helper 共享（评审准许）
                                    assert_safe_sub_path, build_forward_target,
                                    split_sub_path)
from ..headers import build_outbound_headers, filter_response_headers

log = logging.getLogger("agent_proxy")


def registered_endpoint_path(upstream_url: str) -> str:
    """注册 upstream_url 的路径（§8.3 路径分发第 1 行的匹配目标）；无路径按根 `/`。"""
    path = urlparse(upstream_url).path
    return path if path else "/"


def build_origin_target(upstream_url: str, sub_path: str, query: str) -> str:
    """非注册端点路径的转发目标：上游 origin 根 + 子路径 [+ ?query]（§8.3 第 2 行）。

    子路径为空时直达 origin 根；query 为调用方原始 query 串（不重编码，透传）。
    """
    parsed = urlparse(upstream_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    trimmed = sub_path.lstrip("/")
    if not trimmed:
        return origin
    target = f"{origin}/{trimmed}"
    return f"{target}?{query}" if query else target


class SseEndpointRewriter:
    """SSE 增量行解析器（设计 §8.3 实现要点）。

    feed(chunk) → list[bytes]：本次可产出的完整行（保留原始行尾 \\r\\n / \\n）；
    跨 chunk 的半行在内部缓冲。事件名跟踪按 SSE 语义：`event:` 字段设置当前
    事件名，空行（事件块结束）复位；仅 `event: endpoint` 期间的 data: 行改写。
    take_trace_records() 取走自上次调用以来的 trace 记录
    [(event 名, data 字节), ...]，由管线层接 trace.log_sse_event（body 模式生效）。
    """

    def __init__(self, mapping_id: str) -> None:
        self._mapping_id = mapping_id
        self._buffer = b""
        self._current_event = ""
        self._trace_records: list[tuple[str, bytes]] = []

    def feed(self, chunk: bytes) -> list[bytes]:
        self._buffer += chunk
        lines: list[bytes] = []
        while True:
            idx = self._buffer.find(b"\n")
            if idx < 0:
                break
            line = self._buffer[: idx + 1]           # 含行尾 \n
            self._buffer = self._buffer[idx + 1:]
            lines.append(self._handle_line(line))
        return lines

    def flush(self) -> list[bytes]:
        """流结束时冲出无行尾的残留末行（SSE 允许最后一行无换行）。"""
        rest, self._buffer = self._buffer, b""
        return [self._handle_line(rest)] if rest else []

    def take_trace_records(self) -> list[tuple[str, bytes]]:
        records, self._trace_records = self._trace_records, []
        return records

    def _handle_line(self, line: bytes) -> bytes:
        if line.endswith(b"\r\n"):
            body, ending = line[:-2], b"\r\n"
        elif line.endswith(b"\n"):
            body, ending = line[:-1], b"\n"
        else:
            body, ending = line, b""
        text = body.decode("utf-8", "replace")
        if text.startswith(":"):
            return line                              # 心跳注释行：字节级透传，不记 trace
        if text.startswith("event:"):
            self._current_event = text[len("event:"):].strip(" ")
            return line
        if text == "":
            self._current_event = ""                 # 空行 = 事件块结束，事件名复位
            return line
        if text.startswith("data:") and self._current_event == "endpoint":
            return self._rewrite_endpoint_data(text, ending)
        if text.startswith("data:"):
            # message（或未具名事件）的 data 载荷：透传原行 + 产 trace 记录
            self._trace_records.append(
                ("message", text[len("data:"):].lstrip(" ").encode("utf-8")))
        return line                                  # 其余（id:/retry:/字段行）透传

    def _rewrite_endpoint_data(self, text: str, ending: bytes) -> bytes:
        raw_value = text[len("data:"):]
        value = raw_value[1:] if raw_value.startswith(" ") else raw_value
        try:
            parsed = urlparse(value)
        except ValueError:
            # 评审 Issue 6：畸形值（如非法 IPv6 字面量 `http://[bad`）urlparse 抛
            # ValueError——降级为原样透传（不改写），绝不炸整条 SSE 流
            return text.encode("utf-8") + ending
        if parsed.netloc:                            # 绝对 URL：取 path + query（§8.3 改写规则）
            path_query = parsed.path or "/"
            if parsed.query:
                path_query = f"{path_query}?{parsed.query}"
        elif value.startswith("/"):                  # 根相对路径（官方 SDK 形态）
            path_query = value
        else:                                        # 限制说明：其余值不改写，原样透传
            return text.encode("utf-8") + ending
        rewritten = f"/p/{self._mapping_id}{path_query}"
        self._trace_records.append(("endpoint", value.encode("utf-8")))
        self._trace_records.append(("endpoint_rewritten", rewritten.encode("utf-8")))
        return f"data: {rewritten}".encode("utf-8") + ending


async def stream_sse_forward(app_state, mapping_data: dict, request: Request) -> Response:
    """MCP SSE 初始连接转发（设计 §8.3）：GET/HEAD 注册端点 → upstream_url 真流式
    长连接，endpoint 事件增量改写，其余行字节级透传，每行产出即 yield。

    读超时不设（§8.1 第 5 条，依赖上游心跳保活）；非 200 / 非 text/event-stream
    响应（上游错误体等）不进入改写管线，原样流式回传且不计 sse_active；
    客户端断开由 ASGI 取消生成器 → finally 关闭上游连接（§8.1 第 4 条）。
    本函数不转发请求体（调用方仅 GET/HEAD 分发至此）。
    """
    settings = app_state.settings
    client: httpx.AsyncClient = app_state.http_client
    mapping_id = mapping_data["mapping_id"]
    request_id = request.state.request_id
    uid = request.state.uid

    sub_path = split_sub_path(request.scope["path"], mapping_id)  # 与 api 层同检（双保险）
    assert_safe_sub_path(sub_path)
    target = build_forward_target(mapping_data["upstream_url"], "", request.url.query)
    outbound = build_outbound_headers(
        mapping_data["upstream_headers"] or {}, dict(request.headers.items()),
        content_type=request.headers.get("content-type"),
        content_length=request.headers.get("content-length"),
        content_encoding=request.headers.get("content-encoding"))
    # read=None 的请求绝不能消费 keepalive 池连接（Task 5 断开取消端到端实测的
    # 挂死缺陷，sweep/send 竞态 → 无界挂死）：SSE 中途 aclose 的连接本就不会回流
    # 池，真正的死 IDLE 供体是池内「完整响应」连接（POST /messages、503/307 透传、
    # HEAD→SSE 等）——上游（uvicorn keepalive_timeout）可能随后单侧关闭该 IDLE
    # 连接，而 httpcore 的 server_disconnected 过期检测依赖 socket is_readable，
    # 在 Windows Proactor 事件循环上不可靠，连接清理与新建请求的 sweep/send 竞态
    # 下复用到已关闭连接时，「等服务端响应头」因 read=None（§8.1 第 5 条）没有
    # 上限 → 无界挂死。显式 Connection: close 使本请求独占新建连接、结束后不回流
    # 池（SSE 连接生命周期=请求生命周期，池复用本无收益；http/mcp 非 SSE 路径仍
    # 走共享池复用，§8.1 第 11 条不变）。
    outbound["Connection"] = "close"

    def _log_request() -> None:
        trace.log_request(request_id, uid, mapping_id, request.method, target, outbound,
                          body=b"", body_bytes=0)

    start = time.monotonic()
    # SSE 长连接：读超时不设（read=None，§8.1 第 5 条超时表），connect/pool 沿用全局
    timeout = httpx.Timeout(connect=settings.upstream_connect_timeout, read=None,
                            write=60.0, pool=settings.upstream_pool_timeout)
    req = client.build_request(request.method, target, headers=outbound, timeout=timeout)
    try:
        upstream_resp = await client.send(req, stream=True)
    except httpx.PoolTimeout as exc:  # 池上限（必须先于 TimeoutException 捕获）
        metrics.upstream_errors_total.labels(type="mcp", code="pool_exhausted").inc()
        _log_request()
        raise AppError(503, "PROXY_BUSY", "上游连接池已满，请稍后重试") from exc
    except httpx.TimeoutException as exc:
        metrics.upstream_errors_total.labels(type="mcp", code="timeout").inc()
        _log_request()
        raise AppError(504, "UPSTREAM_TIMEOUT", f"上游超时: {exc}") from exc
    except httpx.HTTPError as exc:
        metrics.upstream_errors_total.labels(type="mcp", code="connect").inc()
        _log_request()
        raise AppError(502, "UPSTREAM_ERROR", f"上游连接失败: {exc}") from exc
    _log_request()

    status = upstream_resp.status_code
    resp_ct = next((v for k, v in upstream_resp.headers.items()
                    if k.lower() == "content-type"), "")  # 大小写不敏感（上游原始大小写）
    # duration_ms 语义：time-to-headers（trace response 行充当「连接建立」记录）
    duration_ms = int((time.monotonic() - start) * 1000)
    metrics.upstream_duration.labels(type="mcp").observe(duration_ms / 1000)

    resp_headers = filter_response_headers(upstream_resp.headers)
    if not any(k.lower() == "x-accel-buffering" for k in resp_headers):
        resp_headers["X-Accel-Buffering"] = "no"          # 网关关闭缓冲（§8.1 第 9 条）

    is_sse = status == 200 and "text/event-stream" in resp_ct.lower()
    trace.log_response(request_id, status, duration_ms)

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
                raise AppError(502, "TOO_MANY_REDIRECTS",
                               "上游返回同源重定向，已中止转发（Location 不回传）")
        # 非 SSE 响应（上游 4xx/5xx 错误体等）：不改写、不计 sse_active，原样流式回传
        async def _plain_stream():
            try:
                async for chunk in upstream_resp.aiter_bytes():
                    yield chunk
            except httpx.HTTPError as exc:
                # 流中断可观测（评审 Issue 3）：与 http 管线 _response_stream 对称
                metrics.upstream_errors_total.labels(type="mcp", code="stream_broken").inc()
                log.exception("上游响应流中断: %s", exc)
                raise
            finally:
                await upstream_resp.aclose()
        return StreamingResponse(_plain_stream(), status_code=status, headers=resp_headers)

    rewriter = SseEndpointRewriter(mapping_id)
    metrics.sse_active.inc()

    async def _sse_stream():
        try:
            # 计划缺陷最小修复：原稿 aiter_bytes(_SSE_CHUNK=64KB) 不成立——httpx
            # ByteChunker 按 chunk_size 攒_buf（不足 64KB 时 decode() 返回 []），
            # 仅 EOF flush() 才吐余量，SSE 永不 EOF → endpoint 事件永不增量下发
            # （实测挂死直至客户端读超时）。无参 aiter_bytes() 按网络到达块即时
            # 产出（aiter_lines 内部同款），「每行产出即 yield」的 §8.3 语义成立。
            async for chunk in upstream_resp.aiter_bytes():
                lines = rewriter.feed(chunk)
                for event, data in rewriter.take_trace_records():
                    trace.log_sse_event(request_id, event, data)   # 仅 body 模式生效
                for line in lines:
                    yield line            # 每行立即下发（无整体缓冲，§8.3 实现要点）
            tail = rewriter.flush()
            for event, data in rewriter.take_trace_records():
                trace.log_sse_event(request_id, event, data)
            for line in tail:
                yield line
        except httpx.HTTPError as exc:
            metrics.upstream_errors_total.labels(type="mcp", code="stream_broken").inc()
            log.exception("上游 SSE 流中断: %s", exc)
            raise
        finally:
            metrics.sse_active.dec()
            await upstream_resp.aclose()                  # 客户端断开→取消上游（§8.1 第 4 条）
            log.info("SSE 连接关闭: request_id=%s mapping_id=%s 总时长=%dms",
                     request_id, mapping_id, int((time.monotonic() - start) * 1000))

    try:
        return StreamingResponse(_sse_stream(), status_code=status, headers=resp_headers)
    except BaseException:
        metrics.sse_active.dec()                          # 生成器未启动的交棒窗口防泄漏
        await upstream_resp.aclose()
        raise


async def probe_sse_mapping(app_state, mapping_data: dict) -> dict:
    """mcp+SSE 类型 test（设计 §6.6）：GET 注册端点读流，收到 text/event-stream +
    首个 endpoint 事件即通过；随后立即断开（不维持长连接）。

    复用转发管线的出站 header 重建（测的即真实路径）；上游失败一律 ok=false +
    detail，不抛 502/504；endpoint 值经 redact_query 脱敏后进 detail
    （session_id 不落日志明文，与 trace query 脱敏同规）。
    OAuth 绑定用户（M6）以本人凭证走同一规则：注入 Authorization 后复用本函数。

    超时语义注记（评审 Minor 3，M4 接入 Streamable initialize 探测前需定稿）：
    TEST_PROBE_TIMEOUT 为**分阶段**期限——send（响应头到达）与读流（首个 endpoint
    事件）各享 5s，两阶段不共享总 deadline，最坏总挂钟 ~10s。定稿候选策略：共享
    start 起算剩余时间，或明文保留分阶段语义并修正文档/前端提示。
    """
    stored = mapping_data["upstream_headers"] or {}
    headers = build_outbound_headers(stored, {"Accept": "text/event-stream"},
                                     None, None, None)
    # 与 Task 5 转发管线同规：读到首事件即 aclose 的 SSE 连接绝不回流 keepalive 池
    # （read=None 请求消费死 IDLE 供体 → sweep/send 竞态无界挂死，见 stream_sse_forward）
    headers["Connection"] = "close"
    target = mapping_data["upstream_url"]
    start = time.monotonic()

    def _result(ok: bool, status_code: int | None, detail: str) -> dict:
        return {"ok": ok, "status_code": status_code,
                "latency_ms": int((time.monotonic() - start) * 1000), "detail": detail}

    client: httpx.AsyncClient = app_state.http_client
    try:
        req = client.build_request("GET", target, headers=headers,
                                   timeout=TEST_PROBE_TIMEOUT)
        resp = await asyncio.wait_for(client.send(req, stream=True), TEST_PROBE_TIMEOUT)
    except asyncio.TimeoutError as exc:  # 3.11+ 即内置 TimeoutError（wait_for 总期限）
        return _result(False, None,
                       f"上游超时（>{TEST_PROBE_TIMEOUT:.0f}s 总期限）: {type(exc).__name__}")
    except httpx.TimeoutException as exc:  # 分项超时先到（connect/read/pool）
        return _result(False, None, f"上游超时（>{TEST_PROBE_TIMEOUT:.0f}s）: {type(exc).__name__}")
    except httpx.HTTPError as exc:
        return _result(False, None, f"上游不可达: {type(exc).__name__}: {exc}")

    status_code = resp.status_code
    content_type = next((v for k, v in resp.headers.items()
                         if k.lower() == "content-type"), "")
    if status_code != 200 or "text/event-stream" not in content_type.lower():
        await resp.aclose()
        return _result(False, status_code,
                       f"非 SSE 响应（status={status_code}，content-type={content_type or '无'}）")

    async def _first_endpoint() -> str | None:
        buf = b""
        current_event = ""
        async for chunk in resp.aiter_bytes():
            buf += chunk
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                text = line.decode("utf-8", "replace").rstrip("\r")
                if text.startswith("event:"):
                    current_event = text[len("event:"):].strip()
                elif text.startswith("data:") and current_event == "endpoint":
                    return text[len("data:"):].strip()
                elif text == "":
                    # 评审 Minor 2：空行 = 事件块结束，事件名复位（与
                    # SseEndpointRewriter 对齐）——否则 `event: endpoint\n\n` 之后的
                    # 默认事件类型 data 行被误判为 endpoint → 假 ok=true
                    current_event = ""
        return None

    try:
        endpoint_value = await asyncio.wait_for(_first_endpoint(), TEST_PROBE_TIMEOUT)
    except asyncio.TimeoutError:
        await resp.aclose()
        return _result(False, status_code,
                       f"未在 {TEST_PROBE_TIMEOUT:.0f}s 内收到 endpoint 事件（非 MCP SSE 端点？）")
    except httpx.HTTPError as exc:
        # 评审 Important 1a：读阶段流断（上游头后 RST / gzip 坏流等）必须兜底——
        # 原实现穿透到全局 handler 变 500，且 resp 永不 aclose（连接以 ACTIVE
        # 滞留池内；probe 面向的恰是坏配置上游，高概率触发）
        await resp.aclose()
        return _result(False, status_code,
                       f"上游 SSE 流读取失败: {type(exc).__name__}: {exc}")
    await resp.aclose()  # 首个 endpoint 事件即断开（§6.6）
    if endpoint_value is None:
        return _result(False, status_code, "流结束仍未收到 endpoint 事件")
    try:
        redacted = trace.redact_query(endpoint_value)
    except ValueError:
        # 评审 Important 1b：畸形 endpoint 值（如非法 IPv6 字面量 `http://[bad`）
        # 使 urlparse 抛 ValueError——降级为指纹占位（与转发管线对同一输入降级
        # 透传同规，见 SseEndpointRewriter._rewrite_endpoint_data）
        redacted = trace.fingerprint(endpoint_value)
    return _result(True, status_code, f"SSE 握手成功（endpoint={redacted}）")
