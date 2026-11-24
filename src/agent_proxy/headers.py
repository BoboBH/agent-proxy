"""出站 header 重建（安全核心）与响应 header 过滤（设计 §8.1 第 1/3 条）。

出站 = 存储 upstream_headers 全量 + 协议白名单（Accept / Accept-Encoding /
Content-* / Content-Encoding / MCP 三头，从 caller 提取）；调用方其余 header（JWT /
占位 header / 浏览器指纹）一律不透传；hop-by-hop 双向剥离。响应 header 剥离
hop-by-hop 后原样回传，绝不含存储的真实 header。
出站 key 统一小写归一（HTTP 头名大小写不敏感；防同名不同大小写发重复头行）。
"""
from __future__ import annotations

import typing

# hop-by-hop（RFC 9110 §7.6.1 + 设计 §8.1：Connection/Keep-Alive/TE/Trailer/
# Transfer-Encoding/Upgrade；Proxy-* 前缀统一剥离）
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}

# 协议必要白名单：http body/Accept 透传必需 + MCP 会话/流/版本头（M3/M4 使用，白名单现在建全）。
# accept-encoding（M4 评审携带项，白名单决策记录）：调用方与上游的响应编码协商
# 透明（identity / gzip 原样传达）。与转发管线 aiter_raw 压缩字节透传组合一致：
# 调用方协商 identity 则上游不压缩、代理透传明文；调用方协商 gzip 且上游压缩则
# 压缩字节透传（响应头保真 → 头体一致）——代理两侧都不改协商结果。SSE 管线
# 上游真压缩了 event-stream 时由 gzip SSE 防御降级 plain 透传（见 mcp_sse）。
PROTOCOL_ALLOWED_HEADERS = {
    "accept", "accept-encoding", "content-type", "content-length", "content-encoding",
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

    出站 key 统一小写归一（评审修复）：存储 / caller / explicit 三源若同名不同
    大小写会并存为两个 key，经 httpx 发出重复头行；归一后同名必然覆盖为一行。
    content_type / content_length / content_encoding 为入站请求三个 body 相关头的
    显式值（None = 入站未携带），优先级高于 caller_headers 中的同名白名单项。
    """
    outbound: dict[str, str] = {k.lower(): v for k, v in (stored_headers or {}).items()
                                if not is_hop_by_hop(k)}
    caller = {k.lower(): v for k, v in (caller_headers or {}).items()
              if k.lower() in PROTOCOL_ALLOWED_HEADERS and not is_hop_by_hop(k)}
    explicit = {"content-type": content_type, "content-length": content_length,
                "content-encoding": content_encoding}
    for name, value in explicit.items():
        if value is not None:
            caller[name] = value
    outbound.update(caller)
    return outbound


def filter_response_headers(resp_headers: typing.Mapping[str, str]) -> dict[str, str]:
    """响应 header 剥离 hop-by-hop 后原样回传（含 Content-Type 等；绝不注入存储真实 header）。"""
    return {k: v for k, v in resp_headers.items() if not is_hop_by_hop(k)}
