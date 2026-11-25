"""端到端钉住（真实 TCP，echo 上游回显）：认证头换名 + 调用方 header 透传（设计 v2）。

- 代理身份只认 X-Proxy-Authorization（保留命名空间）；
- authorization 及其他任意调用方 header 原样透传上游（同名覆盖存储）；
- cookie 整头剥离；存储头在调用方未携带同名头时照常注入。
"""
from tests.utils import make_token

UPSTREAM = "http://127.0.0.1:9901/api/v1"


async def _register(client, stored_headers, user=888):
    resp = await client.post(
        "/api/v1/mappings",
        json={"type": "http", "upstream_url": UPSTREAM, "headers": stored_headers},
        headers={"X-Proxy-Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()["mapping_id"]


def _hdr(headers: dict, name: str) -> str | None:
    lowered = name.lower()
    return next((v for k, v in headers.items() if k.lower() == lowered), None)


async def test_caller_authorization_forwarded_and_overrides_stored(client):
    """skill 场景主钉：调用方按 skill 指引带的 Authorization: Token xxx 原样到上游，
    覆盖存储同名头；代理身份走 X-Proxy-Authorization 且绝不出站。"""
    mid = await _register(client, {"Authorization": "Bearer sk-stored-0000",
                                   "X-Store": "sv"})
    resp = await client.get(
        f"/p/{mid}/orders", headers={
            "X-Proxy-Authorization": f"Bearer {make_token(888)}",
            "Authorization": "Token skill-jwt-abcdef",
            "X-Custom": "cv", "User-Agent": "agent-skill/1.0"})
    assert resp.status_code == 200, resp.text
    sent = resp.json()["headers"]
    assert _hdr(sent, "authorization") == "Token skill-jwt-abcdef"   # 调用方胜出
    assert _hdr(sent, "x-store") == "sv"                             # 非同名存储头照常注入
    assert _hdr(sent, "x-custom") == "cv"                            # 任意头透传
    assert _hdr(sent, "user-agent") == "agent-skill/1.0"
    assert _hdr(sent, "x-proxy-authorization") is None               # 保留命名空间不出站


async def test_stored_authorization_injected_when_caller_omits(client):
    """调用方不带 Authorization → 存储值出站（公共映射共享凭据默认路径）。"""
    mid = await _register(client, {"Authorization": "Bearer sk-stored-0000"})
    resp = await client.get(f"/p/{mid}/orders",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 200, resp.text
    assert _hdr(resp.json()["headers"], "authorization") == "Bearer sk-stored-0000"


async def test_proxy_auth_header_shape_still_required(client):
    """管理面同样只认新头：旧 Authorization: Bearer 注册 → 401（通道已让位上游语义）。"""
    resp = await client.post(
        "/api/v1/mappings",
        json={"type": "http", "upstream_url": UPSTREAM, "headers": {}},
        headers={"Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 401
    assert resp.json()["code"] == "INVALID_TOKEN"


async def test_cookie_header_stripped_from_outbound(client):
    mid = await _register(client, {})
    resp = await client.get(
        f"/p/{mid}/orders", headers={
            "X-Proxy-Authorization": f"Bearer {make_token(888)}",
            "Cookie": "ap_sess=leak-me; sid=1"})
    assert resp.status_code == 200, resp.text
    sent = resp.json()["headers"]
    assert _hdr(sent, "cookie") is None
