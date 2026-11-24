"""M6 公共映射管理矩阵 + 手动 OAuth client 配置接口（§14.2 / §14.3 / §6.5）。

- auth_mode=oauth 仅 public（创建/更新两侧 400；public 仍仅 admin，403 先判）；
- §14.2 矩阵：public 的详情 / resolve / test 任意 admin 可见，非注册者普通用户 404；
  public 改删任意 admin 可操作；
- client 配置仅 admin；client_secret 强制加密落库（§14.6）；
- authorize_url / token_url 过 SSRF 校验（scheme/http host 必填）。
"""
from sqlalchemy import select

from agent_proxy.models import OAuthClient
from tests.utils import make_token

ADMIN = {"Authorization": f"Bearer {make_token('uadmin', 'admin')}"}
ADMIN2 = {"Authorization": f"Bearer {make_token('uadmin2', 'admin')}"}
USER = {"Authorization": f"Bearer {make_token('u888')}"}

CLIENT_BODY = {"client_id": "manual-cl", "client_secret": "manual-cs-123456",
               "token_auth": "client_secret_post",
               "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
               "token_url": "http://127.0.0.1:9904/oauth/token", "scopes": "read"}


async def _create(client, headers=ADMIN, **overrides):
    payload = {"type": "http", "visibility": "public", "auth_mode": "oauth",
               "upstream_url": "http://10.0.0.5/api/v1", "headers": {}, **overrides}
    resp = await client.post("/api/v1/mappings", json=payload, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _put_client(client, mid, headers=ADMIN, body=None):
    return await client.put(f"/api/v1/builtin-mappings/{mid}/client",
                            json=body or CLIENT_BODY, headers=headers)


async def test_create_public_oauth_admin_only_and_echoed(client):
    body = {"type": "http", "visibility": "public", "auth_mode": "oauth",
            "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}
    resp = await client.post("/api/v1/mappings", json=body, headers=USER)
    assert resp.status_code == 403 and resp.json()["code"] == "FORBIDDEN"  # 403 先判
    resp = await client.post("/api/v1/mappings", json=body, headers=ADMIN)
    assert resp.status_code == 201
    assert resp.json()["auth_mode"] == "oauth"           # RegisteredOut 增 auth_mode


async def test_create_private_oauth_rejected_400(client):
    resp = await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "private", "auth_mode": "oauth",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}, headers=ADMIN)
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"
    assert "oauth" in resp.json()["message"]


async def test_update_flip_oauth_public_to_private_400_and_static_ok(client):
    created = await _create(client)
    mid = created["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"visibility": "private"},
                            headers=ADMIN)
    assert resp.status_code == 400                       # oauth 映射不可转 private
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"auth_mode": "static"},
                            headers=ADMIN)
    assert resp.status_code == 200 and resp.json()["auth_mode"] == "static"
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"visibility": "private"},
                            headers=ADMIN)
    assert resp.status_code == 200                       # static 后可转 private


async def test_put_client_requires_admin(client):
    mid = (await _create(client))["mapping_id"]
    resp = await _put_client(client, mid, headers=USER)
    assert resp.status_code == 403 and resp.json()["code"] == "FORBIDDEN"


async def test_put_and_get_client_masked(client, app):
    mid = (await _create(client))["mapping_id"]
    resp = await _put_client(client, mid)
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["client_id"] == "manual-cl" and out["source"] == "manual"
    assert out["client_secret_configured"] is True
    assert "manual-cs-123456" not in resp.text           # secret 永不回显
    resp = await client.get(f"/api/v1/builtin-mappings/{mid}/client", headers=ADMIN)
    assert resp.status_code == 200 and resp.json() == out
    # 落库密文面（§14.6 强制加密）
    async with app.state.sessionmaker() as session:
        row = (await session.execute(
            select(OAuthClient).where(OAuthClient.mapping_id == mid))).scalar_one()
    assert row.client_secret.startswith("gAAAA")
    assert "manual-cs-123456" not in row.client_secret


async def test_put_client_replaces_existing_row(client, app):
    mid = (await _create(client))["mapping_id"]
    await _put_client(client, mid)
    resp = await _put_client(client, mid, body={**CLIENT_BODY, "client_id": "manual-cl2",
                                                "client_secret": None})
    assert resp.status_code == 200
    assert resp.json()["client_id"] == "manual-cl2"
    assert resp.json()["client_secret_configured"] is False
    async with app.state.sessionmaker() as session:
        rows = (await session.execute(
            select(OAuthClient).where(OAuthClient.mapping_id == mid))).scalars().all()
    assert len(rows) == 1                                # uk_mapping upsert，不堆行


async def test_put_client_on_static_mapping_400(client):
    mid = (await _create(client, auth_mode="static"))["mapping_id"]
    resp = await _put_client(client, mid)
    assert resp.status_code == 400 and resp.json()["code"] == "OAUTH_NOT_APPLICABLE"


async def test_builtin_endpoints_hide_private_and_missing(client):
    private = (await _create(client, visibility="private", auth_mode="static",
                             headers=ADMIN))["mapping_id"]
    for path, method in ((f"/api/v1/builtin-mappings/{private}/client", "PUT"),
                         (f"/api/v1/builtin-mappings/{private}/client", "GET")):
        resp = await client.request(method, path, json=CLIENT_BODY, headers=ADMIN)
        assert resp.status_code == 404                   # 非 public 一律 404（隐藏存在性）
    resp = await client.get("/api/v1/builtin-mappings/aaaaaaaaaaaa/client", headers=ADMIN)
    assert resp.status_code == 404


async def test_get_client_before_config_404(client):
    mid = (await _create(client))["mapping_id"]
    resp = await client.get(f"/api/v1/builtin-mappings/{mid}/client", headers=ADMIN)
    assert resp.status_code == 404 and resp.json()["code"] == "OAUTH_CLIENT_NOT_CONFIGURED"


async def test_put_client_bad_scheme_400(client):
    mid = (await _create(client))["mapping_id"]
    resp = await _put_client(client, mid, body={**CLIENT_BODY,
                                                "authorize_url": "ftp://127.0.0.1/x"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_public_detail_resolve_test_admin_bypass(client):
    """§14.2：public 详情/resolve 回显仅 admin（任意 admin，不限注册者）；
    非注册者普通用户 404；test 同一旁路。"""
    mid = (await _create(client))["mapping_id"]
    resp = await client.get(f"/api/v1/mappings/{mid}", headers=ADMIN2)
    assert resp.status_code == 200                       # 任意 admin 可见
    resp = await client.get(f"/api/v1/mappings/{mid}", headers=USER)
    assert resp.status_code == 404                       # 普通用户隐藏
    from urllib.parse import quote
    resp = await client.get(f"/api/v1/mappings/resolve?proxy_url={quote(mid)}",
                            headers=ADMIN2)
    assert resp.status_code == 200
    resp = await client.post(f"/api/v1/mappings/{mid}/test", headers=ADMIN2)
    assert resp.status_code == 200                       # 不可达上游 → ok=false 但 HTTP 200
    assert resp.json()["ok"] is False


async def test_public_update_delete_by_any_admin(client):
    mid = (await _create(client))["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"name": "renamed"},
                            headers=ADMIN2)
    assert resp.status_code == 200 and resp.json()["name"] == "renamed"
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"name": "x"}, headers=USER)
    assert resp.status_code == 404                       # 非注册者普通用户 404 不变
    resp = await client.delete(f"/api/v1/mappings/{mid}", headers=ADMIN2)
    assert resp.status_code == 204
