"""M6 公共映射管理矩阵 + 手动 OAuth client 配置接口（§14.2 / §14.3 / §6.5）。

- auth_mode=oauth 仅 public（创建/更新两侧 400；public 仍仅 admin，403 先判）；
- §14.2 矩阵：public 的详情 / resolve / test 任意 admin 可见，非注册者普通用户 404；
  public 改删任意 admin 可操作；admin_override 仅 public——他人私有映射一律 404；
- client 配置仅 admin；client_secret 强制加密落库（§14.6）；
- authorize_url / token_url 过 SSRF 校验（scheme/http host 必填），存储规范化返回值；
- 删除映射连带清理 OAuth client/credential 行（§14.6 最小暴露面）。
"""
from urllib.parse import quote

from sqlalchemy import select

from agent_proxy.models import OAuthClient, OAuthCredential
from agent_proxy.oauth.credential import (encrypt_text, load_credential,
                                          save_credential)
from tests.utils import make_token

ADMIN = {"Authorization": f"Bearer {make_token('uadmin', 'admin')}"}
ADMIN2 = {"Authorization": f"Bearer {make_token('uadmin2', 'admin')}"}
USER = {"Authorization": f"Bearer {make_token('u888')}"}
MASTER = "test-master-key"

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


async def test_private_mapping_other_admin_detail_resolve_404(client):
    """admin_override 仅 public（§14.2 边界钉住）：另一个 admin 对他人私有映射
    无详情/resolve 旁路——404 隐藏存在性，与普通用户一致（防 services 回归）。"""
    private = (await _create(client, visibility="private",
                             auth_mode="static"))["mapping_id"]
    resp = await client.get(f"/api/v1/mappings/{private}", headers=ADMIN2)
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"
    resp = await client.get(f"/api/v1/mappings/resolve?proxy_url={quote(private)}",
                            headers=ADMIN2)
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_private_mapping_other_admin_put_delete_404(client):
    """同上边界：他人私有映射的改/删，另一 admin 亦 404（public 旁路不越界到 private）。"""
    private = (await _create(client, visibility="private",
                             auth_mode="static"))["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{private}", json={"name": "x"},
                            headers=ADMIN2)
    assert resp.status_code == 404
    resp = await client.delete(f"/api/v1/mappings/{private}", headers=ADMIN2)
    assert resp.status_code == 404


async def test_get_client_requires_admin(client):
    """GET /builtin-mappings/{id}/client 与 PUT 同一 admin 门（§14.2）。"""
    mid = (await _create(client))["mapping_id"]
    resp = await client.get(f"/api/v1/builtin-mappings/{mid}/client", headers=USER)
    assert resp.status_code == 403 and resp.json()["code"] == "FORBIDDEN"


async def test_put_client_stores_ssrf_normalized_urls(client, app):
    """SSRF 校验器规范化返回值（去尾斜杠）落库——与 create/update 上游 URL 行为
    一致，消除尾斜杠不对称（重定向_uri 拼接/比对均依赖规范化形态）。"""
    mid = (await _create(client))["mapping_id"]
    resp = await _put_client(client, mid, body={
        **CLIENT_BODY,
        "authorize_url": "http://127.0.0.1:9904/oauth/authorize/",
        "token_url": "http://127.0.0.1:9904/oauth/token/"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["authorize_url"] == "http://127.0.0.1:9904/oauth/authorize"
    assert resp.json()["token_url"] == "http://127.0.0.1:9904/oauth/token"
    async with app.state.sessionmaker() as session:
        row = (await session.execute(
            select(OAuthClient).where(OAuthClient.mapping_id == mid))).scalar_one()
    assert row.authorize_url == "http://127.0.0.1:9904/oauth/authorize"
    assert row.token_url == "http://127.0.0.1:9904/oauth/token"


async def test_delete_mapping_cascades_oauth_rows(client, app):
    """删除映射连带清理 proxy_oauth_client / proxy_oauth_credential 行（§14.6：
    加密 secret/token 随宿主映射删除，行含用户 token 前清理成本最低），
    cred 缓存一并失效（删除后不可再读到凭证）。"""
    mid = (await _create(client))["mapping_id"]
    resp = await _put_client(client, mid)
    assert resp.status_code == 200
    async with app.state.sessionmaker() as session:
        await save_credential(session, app.state.redis, mid, "u888",
                              access_token_ct=encrypt_text("at-cascade-123456", MASTER),
                              refresh_token_ct=None, expires_at=None, scope="read",
                              master_key=MASTER)
    resp = await client.delete(f"/api/v1/mappings/{mid}", headers=ADMIN)
    assert resp.status_code == 204
    async with app.state.sessionmaker() as session:
        assert (await session.execute(select(OAuthClient).where(
            OAuthClient.mapping_id == mid))).scalar_one_or_none() is None
        assert (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid))).scalars().all() == []
        assert await load_credential(session, app.state.redis, mid, "u888") is None
