import asyncio
import socket

import pytest

from app.services.ssrf import (
    UpstreamNotAllowed,
    async_validate_upstream_url,
    validate_upstream_url,
)


def test_strip_trailing_slash():
    assert validate_upstream_url("http://10.0.0.5/api/v1/", allow_private=True) == "http://10.0.0.5/api/v1"


def test_reject_non_http_scheme():
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("ftp://10.0.0.5", allow_private=True)


def test_reject_private_when_not_allowed():
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("http://127.0.0.1:6379", allow_private=False)


def test_allow_private_when_enabled():
    assert validate_upstream_url("http://127.0.0.1:6379", allow_private=True).endswith("6379")


def test_reject_missing_host():
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("http:///path", allow_private=True)


def _gai_result(ip: str):
    """getaddrinfo 风格返回，IP 字面量直接构造成元组，不触网。"""
    if ":" in ip:
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 0, 0, 0))]
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def test_allow_public_ip_when_resolved_public(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: _gai_result("8.8.8.8"))
    assert validate_upstream_url("http://api.example.com/v1", allow_private=False) == "http://api.example.com/v1"


def test_reject_ipv6_loopback(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port: _gai_result("::1"))
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("http://api.example.com", allow_private=False)


def test_gaierror_wrapped_not_allowed(monkeypatch):
    def _boom(host, port):
        raise socket.gaierror(11001, "getaddrinfo failed")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("http://no-such-host.invalid", allow_private=False)


async def test_async_gaierror_wrapped_not_allowed(monkeypatch):
    loop = asyncio.get_running_loop()

    async def _boom(host, port):
        raise socket.gaierror(11001, "getaddrinfo failed")

    monkeypatch.setattr(loop, "getaddrinfo", _boom)
    with pytest.raises(UpstreamNotAllowed):
        await async_validate_upstream_url("http://no-such-host.invalid", allow_private=False)


async def test_async_allows_public_ip(monkeypatch):
    loop = asyncio.get_running_loop()

    async def _fake(host, port):
        return _gai_result("8.8.8.8")

    monkeypatch.setattr(loop, "getaddrinfo", _fake)
    assert await async_validate_upstream_url("http://api.example.com/v1", allow_private=False) == "http://api.example.com/v1"
