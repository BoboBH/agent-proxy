"""出站 header 重建（设计 v4：存储优先、缺省透传、认证头名可配置）与响应过滤。

合并优先级：**forced（oauth 托管注入）> explicit（content-*，真实载荷）>
存储 upstream_headers（映射配置的权威凭据）> 调用方透传**。
- 映射配了某 header → 存储值替换调用方同名头（托管语义）；
- 映射没配 → 调用方头原样透传（agent-email「直接使用 token」场景）。

认证头名可配置（PROXY_AUTH_HEADER，默认 Authorization）：
- 默认 Authorization：既作代理鉴权又可透传上游（统一 token 场景）；
- 配置为其他名字：该头纯代理私有，绝不透传（v2 分离模式经配置恢复）。

保留命名空间（来源无关，绝不透传）：cookie（防平台会话 ap_sess 泄漏）、host
（按转发目标派生，防 vhost 路由破坏）；hop-by-hop（Connection/Keep-Alive/TE/
Trailer/Transfer-Encoding/Upgrade + Proxy-* 前缀）双向剥离。

安全前提：调用方任意头透传适用于平台自家 agent（半可信内网调用方）；对公网
不可信调用方不适用。

出站 key 统一小写归一（防同名不同大小写发重复头行）。响应 header 剥离
hop-by-hop 后原样回传，绝不含存储的真实 header。
"""
from __future__ import annotations

import typing

# hop-by-hop + Proxy-* 前缀
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}

# 恒不透传（与认证头配置无关）：平台会话防泄漏 + 上游 vhost 路由保护
_FIXED_RESERVED = {"cookie", "host"}


def is_hop_by_hop(name: str) -> bool:
    lowered = name.lower()
    return lowered in HOP_BY_HOP_HEADERS or lowered.startswith("proxy-")


def build_outbound_headers(stored_headers: dict[str, str] | None,
                           caller_headers: typing.Mapping[str, str] | None,
                           content_type: str | None, content_length: str | None,
                           content_encoding: str | None,
                           forced: typing.Mapping[str, str] | None = None,
                           auth_header: str = "authorization") -> dict[str, str]:
    """出站 header：调用方打底 ← 存储覆盖（存储优先）← explicit ← forced 最高。

    auth_header：代理身份通道头名（settings.proxy_auth_header，小写比较）。默认
    authorization 可透传（统一 token）；其他名字进保留名单绝不透传。
    content_type / content_length / content_encoding 为入站请求三个 body 相关头的
    显式值（None = 入站未携带），优先级高于存储与调用方同名项。出站 key 统一小写。
    """
    auth_l = (auth_header or "authorization").strip().lower()
    reserved = set(_FIXED_RESERVED)
    if auth_l != "authorization":
        reserved.add(auth_l)

    def _clean(mapping: typing.Mapping[str, str] | None) -> dict[str, str]:
        return {k.lower(): v for k, v in (mapping or {}).items()
                if not is_hop_by_hop(k) and k.lower() not in reserved}

    final = _clean(caller_headers)          # 调用方打底
    final.update(_clean(stored_headers))    # 存储优先（映射配置权威）
    for name, value in (("content-type", content_type),
                        ("content-length", content_length),
                        ("content-encoding", content_encoding)):
        if value is not None:
            final[name] = value             # 真实载荷头
    if forced:
        final.update(_clean(forced))        # oauth 托管最高
    return final


def filter_response_headers(resp_headers: typing.Mapping[str, str]) -> dict[str, str]:
    """响应 header 剥离 hop-by-hop 后原样回传（含 Content-Type 等；绝不含存储真实 header）。"""
    return {k: v for k, v in resp_headers.items() if not is_hop_by_hop(k)}
