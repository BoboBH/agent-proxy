"""代理调用配置回显（设计 v3）：注册/更新响应与公共列表的 headers 字段不再回显
存储头的脱敏形态，而是给出**调用代理所需的 header 配置**——仅
`X-Proxy-Authorization: {{RUNTIME_TOKEN}}`。平台下发 agent 配置时把
`{{RUNTIME_TOKEN}}` 替换为运行时 token（如 `Bearer <user_id>`）；代理消费该头
完成鉴权后出站，再用存储的真实地址/凭据访问上游。真实 header 值只在
resolve/详情接口出现（owner 凭据查看）。"""
from __future__ import annotations

import re

# 运行时令牌占位符（平台替换层约定）；代理原样返回，不做替换
RUNTIME_TOKEN_PLACEHOLDER = "{{RUNTIME_TOKEN}}"


def proxy_call_headers(header_name: str = "Authorization") -> dict[str, str]:
    """返回全新的代理调用 header 配置（每次新 dict，防响应链共享可变状态）。

    header_name 跟随 PROXY_AUTH_HEADER 配置（默认 Authorization）——回显的调用
    配置与代理实际消费的认证头保持一致。"""
    return {(header_name or "Authorization").strip(): RUNTIME_TOKEN_PLACEHOLDER}


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
