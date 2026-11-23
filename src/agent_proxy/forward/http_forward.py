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
        for comp in cur.split("/"):
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
    try:
        upstream_resp = await client.request(request.method, target,
                                             headers=outbound, content=_request_stream())
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

    duration_ms = int((time.monotonic() - start) * 1000)
    metrics.upstream_duration.labels(type="http").observe(duration_ms / 1000)
    resp_headers = filter_response_headers(upstream_resp.headers)
    resp_headers["X-Accel-Buffering"] = "no"  # 网关关闭缓冲（设计 §8.1 第 9 条）

    resp_capture = bytearray()

    async def _response_stream():
        try:
            async for chunk in upstream_resp.aiter_bytes(_STREAM_CHUNK):
                if capture_limit and len(resp_capture) < capture_limit:
                    resp_capture.extend(chunk[: capture_limit - len(resp_capture)])
                yield chunk
        finally:
            # 流结束/客户端断开都释放上游连接（设计 §8.1 第 4 条）
            await upstream_resp.aclose()
            if capture_limit:
                # filter_response_headers 保留上游原始大小写，content-type 按小写不敏感取
                resp_ct = next((v for k, v in resp_headers.items()
                                if k.lower() == "content-type"), "")
                trace.log_response(request_id, upstream_resp.status_code, duration_ms,
                                   headers=dict(resp_headers), body=bytes(resp_capture),
                                   content_type=resp_ct)
            else:
                trace.log_response(request_id, upstream_resp.status_code, duration_ms)

    return StreamingResponse(_response_stream(), status_code=upstream_resp.status_code,
                             headers=resp_headers)
