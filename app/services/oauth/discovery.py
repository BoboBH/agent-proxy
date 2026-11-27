"""OAuth AS discovery（MCP 授权规范 / RFC 8414 + RFC 9728 链式探测，§14.3）。

探测顺序（upstream origin 起）：
1. GET {origin}/.well-known/oauth-protected-resource（RFC 9728）
   → authorization_servers[0]（缺省/空回退 origin 本身）；
2. GET {as_base}/.well-known/oauth-authorization-server（RFC 8414）
   → authorization_endpoint / token_endpoint / registration_endpoint /
   revocation_endpoint。

任一步非 200 / 网络失败 / 元数据缺关键字段 → DiscoveryError → 授权接口映射
502 OAUTH_CLIENT_SETUP_FAILED（§14.3：提示管理员改用手动配置）。

已知限制（明示接受，Task 7 记入债务节）：AS base 来自上游提供的元数据，代理不
对其做 SSRF 校验（upstream origin 本身已过注册期 SSRF 校验；元数据指向任意主机
属上游自身声明，与「跨源重定向属上游自身行为」同一信任模型）。
"""
from __future__ import annotations

from urllib.parse import urlparse

import httpx

DISCOVERY_TIMEOUT = 10.0


class DiscoveryError(Exception):
    """discovery 失败（网络 / 非 200 / 元数据缺失）。"""


def upstream_origin(upstream_url: str) -> str:
    parsed = urlparse(upstream_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def parse_protected_resource(payload, origin: str) -> str:
    """RFC 9728 → AS base（authorization_servers[0]；缺省/空/非 dict/非 http(s)
    scheme/urlparse 解析失败（如畸形 IPv6）回退 origin——畸形值不进入第二跳
    URL 构造）。"""
    servers = payload.get("authorization_servers") if isinstance(payload, dict) else None
    if isinstance(servers, list) and servers and isinstance(servers[0], str):
        candidate = servers[0].strip()
        try:
            scheme_ok = urlparse(candidate).scheme in ("http", "https")
        except ValueError:
            scheme_ok = False
        if candidate and scheme_ok:
            return candidate.rstrip("/")
    return origin.rstrip("/")


def parse_as_metadata(payload) -> dict:
    """RFC 8414 → 授权所需端点集；authorization/token 端点必须存在。"""
    if not isinstance(payload, dict):
        raise DiscoveryError("AS 元数据非 JSON object")
    out = {k: payload.get(k) for k in ("authorization_endpoint", "token_endpoint",
                                       "registration_endpoint", "revocation_endpoint")}
    if not out["authorization_endpoint"] or not out["token_endpoint"]:
        raise DiscoveryError("AS 元数据缺少 authorization_endpoint/token_endpoint")
    return out


async def _get_json(client: httpx.AsyncClient, url: str) -> dict:
    # InvalidURL 直继承 Exception（非 HTTPError）：畸形 URL（如元数据指向非法
    # host/port）在请求构造期抛出——不捕获会逃逸成 500 而非 502
    # OAUTH_CLIENT_SETUP_FAILED，故与 HTTPError 一并归一。
    try:
        resp = await client.get(url, timeout=DISCOVERY_TIMEOUT)
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        raise DiscoveryError(f"探测失败 {url}: {type(exc).__name__}") from exc
    if resp.status_code != 200:
        raise DiscoveryError(f"探测 {url} 非 200（status={resp.status_code}）")
    try:
        return resp.json()
    except ValueError as exc:
        raise DiscoveryError(f"探测 {url} 响应非 JSON") from exc


async def discover_authorization_server(client: httpx.AsyncClient,
                                        upstream_origin_value: str) -> dict:
    """两步探测（见模块 docstring）；失败抛 DiscoveryError。
    全局 http_client 为 follow_redirects=False（§8.1 第 7 条），discovery 不跟随
    重定向——well-known 必须直达。"""
    origin = upstream_origin_value.rstrip("/")
    protected = await _get_json(client, f"{origin}/.well-known/oauth-protected-resource")
    as_base = parse_protected_resource(protected, origin)
    return parse_as_metadata(
        await _get_json(client, f"{as_base}/.well-known/oauth-authorization-server"))
