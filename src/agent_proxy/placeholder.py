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
        if not isinstance(key, str) or not HEADER_TOKEN_RE.match(key):
            raise ValueError(f"非法 header 名: {key!r}")
        if not isinstance(value, str):
            raise ValueError(f"header 值必须为字符串: {key!r}")
        if len(value) > MAX_VALUE_LEN:
            raise ValueError(f"header 值超长: {key!r}")


def mask_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: f"${{PX:{key}}}" for key in headers}


def normalize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    return dict(headers or {})
