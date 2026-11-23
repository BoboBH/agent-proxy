"""HTTP 前缀流式转发（设计 §8.1 / §8.2）。

本模块职责：路径分发（dot-segment 拒绝）→ URL 拼接 → 出站 header 重建 →
httpx 流式转发（请求体字节计数限流）→ 同源重定向内部跟随 → 响应 hop-by-hop
过滤流式回传。全程不整体缓冲；trace / metrics / 审计全接线。
"""
from __future__ import annotations

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


def split_sub_path(full_path: str, mapping_id: str) -> str:
    """/p/{id} 之后的子路径（含前导 /；可为空串）。前缀不匹配 → 400。"""
    prefix = f"/p/{mapping_id}"
    if not full_path.startswith(prefix):
        raise AppError(400, "INVALID_PARAM", "路径与映射不匹配")
    return full_path[len(prefix):]


def assert_safe_sub_path(sub_path: str) -> None:
    """拒绝 dot-segment 及 URL 编码变体（设计 §8.1 第 8 条）——防止拼接后逃逸注册前缀。

    解码层契约：uvicorn/h11 在 ASGI 边界已对原始请求目标做一次百分号解码（第 0 层，
    即本函数入参），此后每层 unquote 对应「上游再解码一次」的深度（第 1-2 层）。
    每层解码后按 / 切分组件，任一组件为 "." / ".." 即拒绝——不依赖整段相等比较：
    复合逃逸例：线上 `..%252f` 经第 0 层解码为 `..%2f`（既非 `.` 也非 `..`），
    第 2 层解码为 `../`（仍非整段相等），但按组件切分即得 `..`；若放行，上游
    再解码一次即逃逸注册前缀。故必须逐组件判定。
    """
    cur = sub_path
    for layer in range(3):  # 第 0 层（入参）+ 上游解码深度 1-2 层
        # `\` 一并按分隔符判定（评审补充）：`..%5C` 解码为 `..\`，对 Windows 风格
        # 上游即 `../`，可逃逸注册前缀
        for comp in cur.replace("\\", "/").split("/"):
            if comp in (".", ".."):
                raise AppError(400, "INVALID_PARAM", "代理子路径含非法 dot-segment")
        if layer < 2:
            cur = unquote(cur)


def build_forward_target(upstream_url: str, sub_path: str, query: str) -> str:
    """转发URL = upstream_url(规范化去尾斜杠) + /子路径 [+ ?query]（设计 §8.2）。

    子路径为空时直达注册 URL；query 为调用方原始 query 串（不重编码，透传）。
    """
    base = upstream_url.rstrip("/")
    trimmed = sub_path.lstrip("/")
    target = f"{base}/{trimmed}" if trimmed else base
    return f"{target}?{query}" if query else target


def _origin(url: httpx.URL) -> tuple[str, str, int]:
    default = 443 if url.scheme == "https" else 80
    return (url.scheme, url.host, url.port or default)


def _redirect_method(status: int, method: str) -> str:
    """303 → GET（载荷类方法），301/302/307/308 保方法（设计 §8.1 第 7 条）。"""
    if status == 303 and method in ("POST", "PUT", "PATCH", "DELETE"):
        return "GET"
    return method


async def stream_http_forward(app_state, mapping_data: dict, request: Request) -> Response:
    """HTTP 前缀流式转发主管线（设计 §8.1 / §8.2）：同源重定向内部跟随、跨源透传。"""
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

    # 同源重定向内部跟随（设计 §8.1 第 7 条）：同源判定与「注册 upstream_url 的
    # origin」比较（非逐跳 target）；存储 header 每跳重放；跨源不跟随原样透传
    # （Location 指向第三方属上游自身行为）；跟随跳沿用真流式 send（评审 Critical：
    # client.request 内部 send(stream=False) 会 aread() 整体缓冲——假流式会在
    # 跟随路径复活）；超过 UPSTREAM_MAX_REDIRECTS 见循环后超限兜底。
    upstream_origin = _origin(httpx.URL(mapping_data["upstream_url"]))
    redirects = 0
    while upstream_resp.is_redirect and redirects < settings.upstream_max_redirects:
        location = upstream_resp.headers.get("location")
        if not location:
            break
        # Location 解析兜底（评审 Important 3）：畸形 Location 抛 InvalidURL 时
        # 先关流防泄漏，再按上游错误映射 502（httpx 在 follow_redirects=False 下
        # 预解析 next_request 时也会抛 RemoteProtocolError，那层由 HTTPError 映射
        # 覆盖；此处兜住 join 自身解析路径）
        try:
            next_url = httpx.URL(target).join(location)
        except httpx.InvalidURL as exc:
            await upstream_resp.aclose()
            raise AppError(502, "UPSTREAM_ERROR",
                           f"上游返回非法 Location: {location!r}") from exc
        if _origin(next_url) != upstream_origin:
            break  # 跨源：透传（响应流保持打开，交 _response_stream 原样回传）
        # 资源卫生（评审 Important 3）：已确定不再使用本跳响应体（跟随或中止二选一），
        # 先关流——assert_safe_sub_path 抛 400 前流已释放，不漏关
        await upstream_resp.aclose()
        # 跳路径与基本路径同有 dot-segment/编码斜杠逃逸暴露（Task 3 评审携带项）：
        # Location 派生的跳路径必须重过安全检查，否则跟随跳可逃逸注册前缀。
        # 用 .path（httpx 已解一层码、不含 query）而非 raw_path（含 query）；
        # assert_safe_sub_path 自带两层 unquote 深度，解码层次覆盖不变。
        assert_safe_sub_path(next_url.path)
        target = str(next_url)
        method = _redirect_method(upstream_resp.status_code, request.method)
        # 已知限制（M2 接受）：首跳 body 已流式消耗，跳间不重放 body（303 已降为 GET）；
        # content-length 随之失效，跟随跳不再携带
        hop_headers = {k: v for k, v in outbound.items() if k.lower() != "content-length"}
        try:
            # 真流式（评审 Critical）：跟随跳必须 build_request + send(stream=True)，
            # client.request 内部 send(stream=False) 会 aread() 把响应体整体读进内存
            hop_req = client.build_request(method, target, headers=hop_headers)
            upstream_resp = await client.send(hop_req, stream=True)
        except httpx.PoolTimeout as exc:  # 池上限（必须先于 TimeoutException 捕获）
            metrics.upstream_errors_total.labels(type="http", code="pool_exhausted").inc()
            raise AppError(503, "PROXY_BUSY", "上游连接池已满，请稍后重试") from exc
        except httpx.TimeoutException as exc:
            metrics.upstream_errors_total.labels(type="http", code="timeout").inc()
            raise AppError(504, "UPSTREAM_TIMEOUT", f"上游超时: {exc}") from exc
        except httpx.HTTPError as exc:
            metrics.upstream_errors_total.labels(type="http", code="connect").inc()
            raise AppError(502, "UPSTREAM_ERROR", f"上游连接失败: {exc}") from exc
        redirects += 1

    # 超限兜底（评审 Important 2，§8.1 第 7 条「同源 Location 永不回传」）：跟随
    # 次数用尽仍是重定向时——同源 Location（可能为绝对 URL，会暴露注册上游 origin）
    # 必须中止回 502 而非透传；跨源重定向属上游自身行为，保持透传不变。
    if redirects >= settings.upstream_max_redirects and upstream_resp.is_redirect:
        location = upstream_resp.headers.get("location") or ""
        try:
            still_same_origin = bool(location) and _origin(
                httpx.URL(target).join(location)) == upstream_origin
        except httpx.InvalidURL:
            still_same_origin = False  # 畸形 Location 无 origin 可判，按透传交下游自行处理
        if still_same_origin:
            await upstream_resp.aclose()
            raise AppError(502, "TOO_MANY_REDIRECTS",
                           f"上游重定向次数超过上限 {settings.upstream_max_redirects}，"
                           "已中止转发（同源 Location 不回传）")

    # duration_ms 语义：time-to-headers——上游响应头到达耗时，不含 body 流式传输时长
    # （有重定向时含各跳耗时）
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
