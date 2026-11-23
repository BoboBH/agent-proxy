import pytest

from tests.utils import make_token

BODY = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1",
        "headers": {"Authorization": "Bearer sk-real-key", "X-User-Id": "u888"}}


async def _create(client, token_user="u888", token_admin=False, **overrides):
    payload = {**BODY, **overrides}
    role = "admin" if token_admin else None
    return await client.post("/api/v1/mappings", json=payload,
                             headers={"Authorization": f"Bearer {make_token(token_user, role)}"})


async def test_create_returns_masked_headers_and_proxy_url(client):
    resp = await _create(client)
    assert resp.status_code == 201
    data = resp.json()
    assert len(data["mapping_id"]) == 12
    assert data["proxy_url"] == f"http://testserver/p/{data['mapping_id']}"
    assert data["headers"] == {"Authorization": "${PX:Authorization}", "X-User-Id": "${PX:X-User-Id}"}
    assert "sk-real-key" not in resp.text and "u888" not in data["headers"].values()
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
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    items = resp.json()
    assert len(items) == 1
    assert items[0]["upstream_url"] == "http://10.0.0.5/api/v1"
    assert "headers" not in items[0]
    resp = await client.get("/api/v1/mappings",
                            headers={"Authorization": f"Bearer {make_token('u999')}"})
    assert resp.json() == []


async def test_detail_owner_only_real_headers(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    assert resp.json()["headers"]["Authorization"] == "Bearer sk-real-key"
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u999')}"})
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_resolve_by_proxy_url_and_by_id(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    from urllib.parse import quote
    proxy_url = quote(created["proxy_url"], safe="")
    for value in (f"proxy_url={proxy_url}", f"proxy_url={mid}"):
        resp = await client.get(f"/api/v1/mappings/resolve?{value}",
                                headers={"Authorization": f"Bearer {make_token('u888')}"})
        assert resp.status_code == 200
        assert resp.json()["upstream_url"] == "http://10.0.0.5/api/v1"
        assert resp.json()["headers"]["Authorization"] == "Bearer sk-real-key"
    resp = await client.get("/api/v1/mappings/resolve?proxy_url=garbage",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 400
    resp = await client.get(f"/api/v1/mappings/resolve?proxy_url={mid}",
                            headers={"Authorization": f"Bearer {make_token('u999')}"})
    assert resp.status_code == 404


async def test_put_updates_and_returns_masked(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{mid}",
                            json={"upstream_url": "http://10.0.0.5/api/v2",
                                  "headers": {"Authorization": "Bearer sk-new-key"}},
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["proxy_url"] == f"http://testserver/p/{mid}"
    assert data["headers"] == {"Authorization": "${PX:Authorization}"}
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.json()["upstream_url"] == "http://10.0.0.5/api/v2"
    assert resp.json()["headers"]["Authorization"] == "Bearer sk-new-key"


async def test_put_non_owner_404(client):
    created = (await _create(client)).json()
    resp = await client.put(f"/api/v1/mappings/{created['mapping_id']}",
                            json={"status": "disabled"},
                            headers={"Authorization": f"Bearer {make_token('u999')}"})
    assert resp.status_code == 404


async def test_delete_then_404(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    resp = await client.delete(f"/api/v1/mappings/{mid}",
                               headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 204
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 404
    resp = await client.delete(f"/api/v1/mappings/{mid}",
                               headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 404


async def test_disabled_mapping_detail_visible_but_flagged(client):
    created = (await _create(client)).json()
    mid = created["mapping_id"]
    await client.put(f"/api/v1/mappings/{mid}", json={"status": "disabled"},
                     headers={"Authorization": f"Bearer {make_token('u888')}"})
    resp = await client.get(f"/api/v1/mappings/{mid}",
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200 and resp.json()["status"] == "disabled"


async def test_unauthorized_401(client):
    resp = await client.post("/api/v1/mappings", json=BODY)
    assert resp.status_code == 401 and resp.json()["code"] == "INVALID_TOKEN"
    bad = {"Authorization": "Bearer garbage"}
    resp = await client.get("/api/v1/mappings", headers=bad)
    assert resp.status_code == 401
