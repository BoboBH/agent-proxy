"""SSRF 防护：scheme 白名单 + DNS 解析拒绝私网/环回/链路本地/保留地址。"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UpstreamNotAllowed(ValueError):
    pass


def validate_upstream_url(url: str, allow_private: bool = False) -> str:
    """校验并返回规范化 URL（去尾斜杠）。非法抛 UpstreamNotAllowed。"""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UpstreamNotAllowed(f"不支持的 scheme: {parsed.scheme!r}（仅 http/https）")
    if not parsed.hostname:
        raise UpstreamNotAllowed("缺少 host")
    if not allow_private:
        for info in socket.getaddrinfo(parsed.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast):
                raise UpstreamNotAllowed(f"上游解析到受限地址: {ip}")
    return url.rstrip("/")
