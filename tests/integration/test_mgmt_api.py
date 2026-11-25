import pytest

from tests.utils import make_token

BODY = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1",
        "headers": {"Authorization": "Bearer sk-real-key", "X-User-Id": "u-888"}}


async def _create(client, token_user=888, token_admin=False, **overrides):
    payload = {**BODY, **overrides}
    role = "admin" if token_admin else None
    return await client.post("/api/v1/mappings", json=payload,
                             headers={"X-Proxy-Authorization": f"Bearer {make_token(token_user, role)}"})


async def test_create_returns_masked_headers_and_proxy_url(client):
    resp = await _create(client)
    assert resp.status_code == 201
    data = resp.json()
    assert len(data["mapping_id"]) == 12
    assert data["proxy_url"] == f"http://testserver/p/{data['mapping_id']}"
    assert data["headers"] == {"Authorization": "${PX:Authorization}", "X-User-Id": "${PX:X-User-Id}"}
    assert "sk-real-key" not in resp.text and "u-888" not in data["headers"].values()
    assert data["visibility"] == "private" and data["status"] == "active"


async def test_create_mcp_proxy_url_includes_endpoint_path(client):
    resp = await _create(client, type="mcp", upstream_url="https://mcp.ex.com/sse")
    assert resp.json()["proxy_url"].endswith(f"/p/{resp.json()['mapping_id']}/sse")


async def test_create_public_requires_admin(client):
    resp = await _create(client, visibility="public")
    assert resp.status_code == 403 and resp.json()["code"] == "FORBIDDEN"
    resp = await _create(client, visibility="public", token_admin=True)
    assert resp.status_code == 201


async def test_create_invalid_header_name_400(client):
    resp = await _create(client, headers={"bad header": "v"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_create_invalid_scheme_400(client):
    resp = await _create(client, upstream_url="ftp://10.0.0.5")
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_list_only_mine_no_real_headers(client):
    await _create(client)  # u888
    resp = await client.get("/api/v1/mappings",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    items = resp.json()
    assert len(items) == 1
    assert items[0]["upstream_url"] == "http://10.0.0.5/api/v1"
    assert "headers" not in items[0]
    resp = await client.get("/api/v1/mappings",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(999)}"})
    assert resp.json() == []


async def test_detail_owner_only_real_headers(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 200
    assert resp.json()["headers"]["Authorization"] == "Bearer sk-real-key"
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(999)}"})
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_resolve_by_proxy_url_and_by_id(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    from urllib.parse import quote
    proxy_url = quote(created["proxy_url"], safe="")
    for value in (f"proxy_url={proxy_url}", f"proxy_url={mid}"):
        resp = await client.get(f"/api/v1/mappings/resolve?{value}",
                                headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
        assert resp.status_code == 200
        assert resp.json()["upstream_url"] == "http://10.0.0.5/api/v1"
        assert resp.json()["headers"]["Authorization"] == "Bearer sk-real-key"
    resp = await client.get("/api/v1/mappings/resolve?proxy_url=garbage",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 400
    resp = await client.get(f"/api/v1/mappings/resolve?proxy_url={mid}",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(999)}"})
    assert resp.status_code == 404


async def test_put_updates_and_returns_masked(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{mid}",
                            json={"upstream_url": "http://10.0.0.5/api/v2",
                                  "headers": {"Authorization": "Bearer sk-new-key"}},
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["proxy_url"] == f"http://testserver/p/{mid}"
    assert data["headers"] == {"Authorization": "${PX:Authorization}"}
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.json()["upstream_url"] == "http://10.0.0.5/api/v2"
    assert resp.json()["headers"]["Authorization"] == "Bearer sk-new-key"


async def _corrupt_row_headers(app, mapping_id: str) -> None:
    """直写 DB 行 headers 为不可解密文（模拟 MASTER_KEY 变更/行损坏）；PUT 路径
    直读 DB 行不经缓存，无需清缓存。"""
    from sqlalchemy import update
    from agent_proxy.models import ProxyMapping
    async with app.state.sessionmaker() as session:
        await session.execute(update(ProxyMapping)
                              .where(ProxyMapping.mapping_id == mapping_id)
                              .values(upstream_headers="gAAAAbroken-not-fernet"))
        await session.commit()


async def test_put_corrupt_headers_untouched_succeeds_and_disables(client, app):
    """评审 Important 1a：headers 密文损坏的映射，patch 未触及 headers（停用类
    应急处置）→ 更新照常生效（非 500/非 409），回显占位符降级空表 + WARN；
    真实值读取路径（详情）仍 fail-closed 404。"""
    mid = (await _create(client)).json()["mapping_id"]
    await _corrupt_row_headers(app, mid)
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"status": "disabled"},
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "disabled"
    assert data["headers"] == {}                       # 占位符降级（键名不可得，无明文产出）
    async with app.state.sessionmaker() as session:
        from sqlalchemy import select
        from agent_proxy.models import ProxyMapping
        row = (await session.execute(
            select(ProxyMapping).where(ProxyMapping.mapping_id == mid))).scalar_one()
        assert row.status == "disabled"
        assert row.upstream_headers == "gAAAAbroken-not-fernet"   # 损坏行未被触碰
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 404                     # 读取路径 fail-closed 不变


async def test_put_corrupt_headers_touched_409_not_500(client, app):
    """评审 Important 1a：patch 触及 headers → 显式 409 CREDENTIAL_CORRUPT（覆盖即
    无声销毁损坏现场；修复路径=恢复 MASTER_KEY 或 DELETE 重注册），非 500 且行原状。"""
    mid = (await _create(client)).json()["mapping_id"]
    await _corrupt_row_headers(app, mid)
    resp = await client.put(f"/api/v1/mappings/{mid}",
                            json={"headers": {"Authorization": "Bearer sk-new"},
                                  "status": "disabled"},
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 409
    assert resp.json()["code"] == "CREDENTIAL_CORRUPT"
    assert "DELETE" in resp.json()["message"]
    async with app.state.sessionmaker() as session:
        from sqlalchemy import select
        from agent_proxy.models import ProxyMapping
        row = (await session.execute(
            select(ProxyMapping).where(ProxyMapping.mapping_id == mid))).scalar_one()
        assert row.upstream_headers == "gAAAAbroken-not-fernet"   # 更新未执行（原子失败）
        assert row.status == "active"


async def test_put_non_owner_404(client):
    created = (await _create(client)).json()
    resp = await client.put(f"/api/v1/mappings/{created['mapping_id']}",
                            json={"status": "disabled"},
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(999)}"})
    assert resp.status_code == 404


async def test_delete_then_404(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.delete(f"/api/v1/mappings/{mid}",
                               headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 204
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 404
    resp = await client.delete(f"/api/v1/mappings/{mid}",
                               headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 404


async def test_disabled_mapping_detail_visible_but_flagged(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    await client.put(f"/api/v1/mappings/{mid}", json={"status": "disabled"},
                     headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 200 and resp.json()["status"] == "disabled"


async def test_unauthorized_401(client):
    resp = await client.post("/api/v1/mappings", json=BODY)
    assert resp.status_code == 401 and resp.json()["code"] == "INVALID_TOKEN"
    bad = {"X-Proxy-Authorization": "Bearer garbage"}  # 认证通道无效凭证 → 401
    resp = await client.get("/api/v1/mappings", headers=bad)
    assert resp.status_code == 401


async def test_list_page_size_over_limit_400(client):
    resp = await client.get("/api/v1/mappings?page_size=101",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_list_page_size_negative_400(client):
    resp = await client.get("/api/v1/mappings?page_size=-1",
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_resolve_rejects_foreign_netloc(client):
    """终审债务：带 netloc 的 proxy_url，host 必须等于 EXTERNAL_BASE 的 host。"""
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.get(
        f"/api/v1/mappings/resolve?proxy_url=http%3A%2F%2Fevil.example.com%2Fp%2F{mid}",
        headers={"X-Proxy-Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"
    # 本服务 host 正常回显（EXTERNAL_BASE=http://testserver，既有用例已覆盖 200）
