"""出站 header 重建（设计 v2 透传模型）与响应 header 过滤（§8.1 修订）。

出站 = 存储 upstream_headers 全量打底 + **调用方 header 全量透传**（同名调用方
覆盖存储——skill 教传的 Authorization 等上游凭证头原样直达上游）+ forced 最高
优先（oauth 型映射注入的本人凭证，凭证托管语义不被调用方绕过）+ 协议显式值
（content-*，来自真实入站载荷，优先级高于调用方同名头）。

保留命名空间（绝不透传，与存储/调用方来源无关）：
- x-proxy-authorization：代理身份通道，已在鉴权层消费；
- cookie：防平台会话（ap_sess）泄漏给上游；上游 cookie 走存储 headers 配置；
- host：由 httpx 按转发目标 URL 派生，透传会破坏上游 vhost 路由。

hop-by-hop（RFC 9110 §7.6.1：Connection/Keep-Alive/TE/Trailer/Transfer-Encoding/
Upgrade + Proxy-* 前缀）双向剥离不变。

安全前提（设计文档 §8.1 v2 注记）：透传模型适用于**平台自家 agent（半可信内网
调用方）**；对公网不可信调用方，任意头透传会放大注入面，不适用。

出站 key 统一小写归一（防同名不同大小写发重复头行）。响应 header 剥离 hop-by-hop
后原样回传，绝不含存储的真实 header。
"""
from __future__ import annotations

import typing

# hop-by-hop + Proxy-* 前缀（注意：x-proxy-authorization 不匹配 proxy-* 前缀，
# 由下方保留名单独立剥离——两者语义不同，剥离动作必须各自成立）
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}

# 保留命名空间：代理身份（已消费）/ 平台会话防泄漏 / 上游 vhost 路由保护
RESERVED_OUTBOUND_HEADERS = {"x-proxy-authorization", "cookie", "host"}


def is_hop_by_hop(name: str) -> bool:
    lowered = name.lower()
    return lowered in HOP_BY_HOP_HEADERS or lowered.startswith("proxy-")


def build_outbound_headers(stored_headers: dict[str, str] | None,
                           caller_headers: typing.Mapping[str, str] | None,
                           content_type: str | None, content_length: str | None,
                           content_encoding: str | None,
                           forced: typing.Mapping[str, str] | None = None) -> dict[str, str]:
    """出站 header：存储打底 ← caller 全量透传（同名覆盖）← explicit 载荷头 ← forced 最高。

    优先级：forced（oauth 托管注入）> explicit（content-*，真实载荷）> caller > stored。
    content_type / content_length / content_encoding 为入站请求三个 body 相关头的
    显式值（None = 入站未携带）。出站 key 统一小写归一（多源同名不同大小写会经
    httpx 发出重复头行）。
    """
    outbound: dict[str, str] = {k.lower(): v for k, v in (stored_headers or {}).items()
                                if not is_hop_by_hop(k)
                                and k.lower() not in RESERVED_OUTBOUND_HEADERS}
    caller = {k.lower(): v for k, v in (caller_headers or {}).items()
              if not is_hop_by_hop(k) and k.lower() not in RESERVED_OUTBOUND_HEADERS}
    explicit = {"content-type": content_type, "content-length": content_length,
                "content-encoding": content_encoding}
    for name, value in explicit.items():
        if value is not None:
            caller[name] = value
    outbound.update(caller)
    if forced:
        outbound.update({k.lower(): v for k, v in forced.items()
                         if not is_hop_by_hop(k) and k.lower() not in RESERVED_OUTBOUND_HEADERS})
    return outbound


def filter_response_headers(resp_headers: typing.Mapping[str, str]) -> dict[str, str]:
    """响应 header 剥离 hop-by-hop 后原样回传（含 Content-Type 等；绝不注入存储真实 header）。"""
    return {k: v for k, v in resp_headers.items() if not is_hop_by_hop(k)}
