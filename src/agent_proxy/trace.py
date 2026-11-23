"""追踪日志（trace.log）：三档粒度 + header 指纹脱敏 + body 截断（安全底线：敏感值永不落盘）。"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-auth-token"}
_TEXT_TYPES = ("text/", "application/json", "application/xml", "application/x-www-form-urlencoded")

_trace = logging.getLogger("agent_proxy.trace")
# 未走 setup_logging（如单测直挂 handler）时 logger 为 NOTSET、继承 root 的 WARNING，
# info 记录会被级别过滤丢弃，这里显式钉在 INFO
_trace.setLevel(logging.INFO)
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
    # ts 固定为行首键：排障需时间证明与行序（设计 §11.1）
    line = {"ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"), **record}
    _trace.info(json.dumps(line, ensure_ascii=False))


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
    fields = _truncate(data)
    # 设计 §11.1：SSE 行的载荷键名为 data/data_truncated，非 body/body_truncated
    if "body" in fields:
        fields["data"] = fields.pop("body")
    if "body_truncated" in fields:
        fields["data_truncated"] = fields.pop("body_truncated")
    record.update(fields)
    _write(record)
