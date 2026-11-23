"""SSRF 防护：scheme 白名单 + DNS 解析拒绝私网/环回/链路本地/保留地址。"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

SCHEMES = ("http", "https")


class UpstreamNotAllowed(ValueError):
    pass


def _check_scheme_host(parsed) -> None:
    """scheme 白名单 + host 非空，非法抛 UpstreamNotAllowed。"""
    if parsed.scheme not in SCHEMES:
        raise UpstreamNotAllowed(f"不支持的 scheme: {parsed.scheme!r}（仅 http/https）")
    if not parsed.hostname:
        raise UpstreamNotAllowed("缺少 host")


def _reject_restricted_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast):
        raise UpstreamNotAllowed(f"上游解析到受限地址: {ip}")


def _reject_restricted_infos(infos) -> None:
    """遍历 getaddrinfo 结果，命中受限地址即抛 UpstreamNotAllowed。"""
    for info in infos:
        _reject_restricted_ip(ipaddress.ip_address(info[4][0]))


def validate_upstream_url(url: str, allow_private: bool = False) -> str:
    """校验并返回规范化 URL（去尾斜杠）。非法抛 UpstreamNotAllowed。"""
    parsed = urlparse(url)
    _check_scheme_host(parsed)
    if not allow_private:
        try:
            infos = socket.getaddrinfo(parsed.hostname, None)
        except OSError as exc:
            raise UpstreamNotAllowed(f"上游域名解析失败: {parsed.hostname!r}") from exc
        _reject_restricted_infos(infos)
    return url.rstrip("/")


async def async_validate_upstream_url(url: str, allow_private: bool = False) -> str:
    """异步入口：地址检查委托事件循环 getaddrinfo，不阻塞并发。

    行为与 validate_upstream_url 一致（scheme 白名单/host 非空/受限地址拒绝/
    去尾斜杠）；解析失败（OSError/gaierror）统一包装为 UpstreamNotAllowed。
    """
    parsed = urlparse(url)
    _check_scheme_host(parsed)
    if not allow_private:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(parsed.hostname, None)
        except OSError as exc:
            raise UpstreamNotAllowed(f"上游域名解析失败: {parsed.hostname!r}") from exc
        _reject_restricted_infos(infos)
    return url.rstrip("/")
