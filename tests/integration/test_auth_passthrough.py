"""端到端钉住（真实 TCP，echo 上游回显）：默认认证头 Authorization + 出站
「存储优先、缺省透传」（设计 v4）。

- Authorization: Bearer <纯数字> = 代理身份（默认通道），同时**可透传上游**
  （统一 token 场景：映射未配同名头时原样直达）；
- 映射配了同名头 → 存储值替换调用方（托管语义）；
- cookie/host 恒不透传；X-Proxy-Authorization 在默认配置下只是普通头（透传），
  仅当 PROXY_AUTH_HEADER 切换为它时才成为代理私有保留头（单测矩阵已钉）。
"""
from tests.utils import make_token

UPSTREAM = "http://127.0.0.1:9901/api/v1"


async def _register(client, stored_headers, user=888):
    resp = await client.post(
        "/api/v1/mappings",
        json={"type": "http", "upstream_url": UPSTREAM, "headers": stored_headers},
        headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()["mapping_id"]


def _hdr(headers: dict, name: str) -> str | None:
    lowered = name.lower()
    return next((v for k, v in headers.items() if k.lower() == lowered), None)


async def test_stored_authorization_replaces_caller(client):
    """托管语义：映射配了 Authorization → 存储值替换调用方同名头；非同名存储头
    照常注入；任意调用方头透传。"""
    mid = await _register(client, {"Authorization": "Bearer sk-stored-0000",
                                   "X-Store": "sv"})
    resp = await client.get(
        f"/p/{mid}/orders", headers={
            "Authorization": f"Bearer {make_token(888)}",
            "X-Custom": "cv", "User-Agent": "agent-skill/1.0"})
    assert resp.status_code == 200, resp.text
    sent = resp.json()["headers"]
    assert _hdr(sent, "authorization") == "Bearer sk-stored-0000"   # 存储优先
    assert _hdr(sent, "x-store") == "sv"
    assert _hdr(sent, "x-custom") == "cv"
    assert _hdr(sent, "user-agent") == "agent-skill/1.0"


async def test_caller_authorization_passthrough_when_mapping_has_none(client):
    """统一 token 场景：映射未配 Authorization → 调用方的 Authorization 原样直达
    上游（agent-email「没有个人配置，直接使用 token」）。"""
    mid = await _register(client, {})
    resp = await client.get(
        f"/p/{mid}/orders", headers={
            "Authorization": "Token shared-jwt-abcdef",
            "X-Proxy-Authorization": "Bearer whatever"})
    assert resp.status_code == 200, resp.text
    sent = resp.json()["headers"]
    assert _hdr(sent, "authorization") == "Token shared-jwt-abcdef"  # 直达上游
    assert _hdr(sent, "x-proxy-authorization") == "Bearer whatever"  # 默认配置下普通头透传
    assert "stub." not in resp.text


async def test_cookie_and_host_not_forwarded(client):
    mid = await _register(client, {})
    resp = await client.get(
        f"/p/{mid}/orders", headers={
            "Authorization": f"Bearer {make_token(888)}",
            "Cookie": "ap_sess=leak-me; sid=1",
            "Host": "127.0.0.1:8800"})
    assert resp.status_code == 200, resp.text
    sent = resp.json()["headers"]
    assert _hdr(sent, "cookie") is None
    assert _hdr(sent, "host") != "127.0.0.1:8800"


async def test_register_via_default_channel_and_invalid_token_401(client):
    """默认 Authorization 注册成功；无效凭证 → 401 INVALID_TOKEN。"""
    resp = await client.post(
        "/api/v1/mappings",
        json={"type": "http", "upstream_url": UPSTREAM, "headers": {}},
        headers={"Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 201
    resp = await client.post(
        "/api/v1/mappings",
        json={"type": "http", "upstream_url": UPSTREAM, "headers": {}},
        headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401 and resp.json()["code"] == "INVALID_TOKEN"
