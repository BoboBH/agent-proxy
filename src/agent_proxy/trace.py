"""追踪日志（trace.log）：三档粒度 + header 指纹脱敏 + body 截断（安全底线：敏感值永不落盘）。"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlparse, urlunparse

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie",
                     "x-auth-token", "x-api-key", "api-key"}
# 兜底：header 名含这些子串一律按敏感处理（未列入精确集合的敏感头默认安全）
_SENSITIVE_SUBSTRINGS = ("token", "secret", "key", "auth", "cookie")
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


def capture_limit() -> int:
    """body 模式返回截断上限（转发层据此 tee 捕获 body 前缀）；其余模式 0（不捕获）。"""
    return _max_body if _mode == "body" else 0


def fingerprint(value: str) -> str:
    # 门槛 12：len==8 时前4后4恰好拼出全值，9-11 字符短密钥也泄露 8 字符
    if len(value) >= 12:
        return f"{value[:4]}****{value[-4:]}(len={len(value)})"
    return f"****(len={len(value)})"


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


def _is_sensitive(name: str) -> bool:
    lowered = name.lower()
    return lowered in SENSITIVE_HEADERS or any(s in lowered for s in _SENSITIVE_SUBSTRINGS)


def _headers_for_log(headers: dict[str, str], body_mode: bool) -> dict[str, str]:
    out = {}
    for key, value in headers.items():
        sensitive = _is_sensitive(key)
        out[key] = fingerprint(value) if (sensitive or not body_mode) else value
    return out


def _truncate(body: bytes | str, content_type: str = "",
              content_encoding: str = "") -> dict:
    ct = content_type.lower().split(";")[0].strip()
    # +json 后缀（如 application/vnd.api+json）与 yaml 属文本，不能当二进制丢弃
    is_text = ct.startswith(_TEXT_TYPES) or ct.endswith("+json") or ct == "application/yaml"
    # M4：压缩传输编码（gzip/deflate…）下 body 为压缩字节（aiter_raw 透传），
    # 按文本解码必乱码——一律走二进制路径只记字节数；identity = 无压缩（RFC 9110），
    # body 仍为明文，按文本处理
    ce = (content_encoding or "").lower()
    if (ce and ce != "identity") or (content_type and not is_text):
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


def log_request(request_id: str, uid: int | str, mapping_id: str, method: str, url: str,
                headers: dict[str, str], body: bytes = b"",
                body_bytes: int | None = None, content_type: str = "",
                content_encoding: str = "") -> None:
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
        record.update(_truncate(body, content_type, content_encoding))
    _write(record)


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
