"""授权绑定全流程（ASGI client 走代理面，浏览器角色经真实 TCP 访问 9904）：
authorize（state+PKCE 入 Redis / 白名单校验）→ AS 302 → callback（一次性 state、
code+verifier 换 token、强制加密落库）→ binding 状态机 unbound→authorizing→bound；
内置列表 + binding 查询 + 回调失败分支。"""
import httpx
from sqlalchemy import select
from urllib.parse import urlparse, parse_qs

from agent_proxy.models import OAuthClient, OAuthCredential
from agent_proxy.oauth.client import state_key
from agent_proxy.oauth.credential import decrypt_text
from tests.integration.mock_oauth_as import as_state
from tests.utils import make_token

ADMIN = {"Authorization": f"Bearer {make_token(100, 'admin')}"}
U888 = {"Authorization": f"Bearer {make_token(888)}"}
U999 = {"Authorization": f"Bearer {make_token(999)}"}
FRONT = "http://testserver/console"
MASTER = "test-master-key"

CLIENT_BODY = {"client_id": "manual-cl", "client_secret": "manual-cs-123456",
               "token_auth": "client_secret_post",
               "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
               "token_url": "http://127.0.0.1:9904/oauth/token", "scopes": "read"}


async def _create_oauth(client, type_="http", upstream="http://127.0.0.1:9901/api/v1"):
    resp = await client.post("/api/v1/mappings", json={
        "type": type_, "visibility": "public", "auth_mode": "oauth",
        "upstream_url": upstream, "headers": {}}, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()["mapping_id"]


async def _setup(client, type_="http", upstream="http://127.0.0.1:9901/api/v1"):
    mid = await _create_oauth(client, type_, upstream)
    resp = await client.put(f"/api/v1/builtin-mappings/{mid}/client",
                            json=CLIENT_BODY, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return mid


async def _authorize(client, mid, headers=U888, front=FRONT):
    return await client.post(f"/api/v1/builtin-mappings/{mid}/authorize",
                             json={"front_redirect": front}, headers=headers)


async def _browser_get(authz_url: str):
    """浏览器角色：真实 TCP 访问 mock AS 9904，返回其 302（不跟随）。"""
    async with httpx.AsyncClient() as browser:
        return await browser.get(authz_url, follow_redirects=False)


def _path_of(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


async def _bind(client, mid, headers=U888):
    """完整绑定：返回 (callback_resp, authorization_url)。"""
    r = await _authorize(client, mid, headers)
    assert r.status_code == 200, r.text
    authz_url = r.json()["authorization_url"]
    redir = await _browser_get(authz_url)
    assert redir.status_code == 302, redir.text
    cb = await client.get(_path_of(redir.headers["location"]), follow_redirects=False)
    return cb, authz_url


async def test_full_manual_flow_success_redirect_and_encrypted_storage(client, app):
    mid = await _setup(client)
    cb, _ = await _bind(client, mid)
    assert cb.status_code == 302
    assert cb.headers["location"] == f"{FRONT}?binding=success"
    # 状态机收敛 bound + expires_at 回告（页面轮询面）
    b = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.status_code == 200
    body = b.json()
    assert body["binding"] == "bound" and body["auth_mode"] == "oauth"
    assert body["expires_at"] and body["scope"] == "read"
    # 落库密文面（§14.6 强制加密）+ 解密等于 mock AS 签发值
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid))).scalar_one()
    assert row.uid == 888 and row.access_token.startswith("gAAAA")
    assert "at-" not in row.access_token                  # 明文不落库
    assert decrypt_text(row.access_token, MASTER) == as_state["issued"][-1]["access_token"]
    assert row.refresh_token.startswith("gAAAA")
    # 回调审计身份来自 state（无 JWT）
    assert row.scope == "read"


async def test_binding_authorizing_then_bound(client):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    assert r.status_code == 200 and "authorization_url" in r.json()
    b = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "authorizing"          # state 存续期间
    b999 = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U999)
    assert b999.json()["binding"] == "unbound"           # 绑定按 uid 隔离
    cb, _ = await _bind(client, mid)
    assert cb.status_code == 302
    b = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "bound"


async def test_authorization_url_shape_and_state_in_redis(client, app):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    url = r.json()["authorization_url"]
    parsed = parse_qs(urlparse(url).query)
    assert parsed["client_id"] == ["manual-cl"]
    assert parsed["response_type"] == ["code"]
    assert parsed["code_challenge_method"] == ["S256"]
    assert parsed["scope"] == ["read"]
    redirect_uri = parsed["redirect_uri"][0]
    assert redirect_uri == f"http://testserver/oauth/callback/{mid}"   # 精确值（§14.6）
    state = parsed["state"][0]
    key = state_key(state)
    ttl = await app.state.redis.ttl(key)
    assert 0 < ttl <= 600                                # OAUTH_STATE_TTL
    import json as jsonlib
    payload = jsonlib.loads(await app.state.redis.get(key))
    assert payload["uid"] == 888 and payload["mapping_id"] == mid
    assert len(payload["code_verifier"]) == 43
    assert payload["front_redirect"] == FRONT


async def test_rebind_upserts_single_credential_row(client, app):
    mid = await _setup(client)
    cb1, _ = await _bind(client, mid)
    first_token = as_state["issued"][-1]["access_token"]
    cb2, _ = await _bind(client, mid)                    # 重复授权
    assert cb2.headers["location"] == f"{FRONT}?binding=success"
    async with app.state.sessionmaker() as session:
        rows = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid))).scalars().all()
    assert len(rows) == 1                                # uk(mapping_id, uid) upsert
    assert decrypt_text(rows[0].access_token, MASTER) != first_token


async def test_builtin_list_items_binding_and_masked_headers(client):
    static_mid = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "static",
        "upstream_url": "http://10.0.0.5/api/v1",
        "headers": {"Authorization": "Bearer sk-shared-12345678"}}, headers=ADMIN)).json()["mapping_id"]
    oauth_mid = await _setup(client)
    await _bind(client, oauth_mid)                       # u888 绑定
    resp = await client.get("/api/v1/builtin-mappings", headers=U888)
    assert resp.status_code == 200
    items = {x["mapping_id"]: x for x in resp.json()}
    assert static_mid in items and oauth_mid in items
    assert items[static_mid]["binding"] is None          # static 无绑定语义
    assert items[static_mid]["headers"] == {"Authorization": "${PX:Authorization}"}
    assert "sk-shared-12345678" not in resp.text         # 占位符，真实值不出
    assert items[oauth_mid]["binding"] == "bound"
    assert items[oauth_mid]["proxy_url"].startswith("http://testserver/p/")
    resp999 = await client.get("/api/v1/builtin-mappings", headers=U999)
    items999 = {x["mapping_id"]: x for x in resp999.json()}
    assert items999[oauth_mid]["binding"] == "unbound"   # 按调用者视角


async def test_state_replay_rejected_400(client):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    redir = await _browser_get(r.json()["authorization_url"])
    callback = _path_of(redir.headers["location"])
    first = await client.get(callback, follow_redirects=False)
    assert first.status_code == 302
    second = await client.get(callback, follow_redirects=False)
    assert second.status_code == 400                     # state 一次性（重放拒绝）
    assert second.json()["code"] == "OAUTH_STATE_INVALID"


async def test_forged_state_400(client):
    mid = await _setup(client)
    resp = await client.get(f"/oauth/callback/{mid}?code=cd-x&state={'f' * 32}",
                            follow_redirects=False)
    assert resp.status_code == 400 and resp.json()["code"] == "OAUTH_STATE_INVALID"


async def test_state_mapping_mismatch_400(client):
    mid_a = await _setup(client)
    mid_b = await _setup(client)
    r = await _authorize(client, mid_a)
    redir = await _browser_get(r.json()["authorization_url"])
    forged = _path_of(redir.headers["location"]).replace(f"/{mid_a}?", f"/{mid_b}?")
    resp = await client.get(forged, follow_redirects=False)
    assert resp.status_code == 400                       # state 与回调路径不匹配
    assert resp.json()["code"] == "OAUTH_STATE_INVALID"


async def test_callback_as_error_redirects_failed(client, app):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    state = parse_qs(urlparse(r.json()["authorization_url"]).query)["state"][0]
    resp = await client.get(f"/oauth/callback/{mid}?error=access_denied&state={state}",
                            follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == f"{FRONT}?binding=failed&reason=access_denied"
    # AS 拒绝授权不落凭证
    from agent_proxy.oauth.credential import load_credential
    async with app.state.sessionmaker() as session:
        assert await load_credential(session, app.state.redis, mid, 888) is None


async def test_callback_missing_code_redirects_failed(client):
    mid = await _setup(client)
    r = await _authorize(client, mid)
    state = parse_qs(urlparse(r.json()["authorization_url"]).query)["state"][0]
    resp = await client.get(f"/oauth/callback/{mid}?state={state}",
                            follow_redirects=False)
    assert resp.status_code == 302
    assert "binding=failed&reason=missing_code" in resp.headers["location"]


async def test_callback_as_error_reason_urlencoded(client):
    """Task 4 评审携带批：AS error 为 AS 可控字符串，回跳 reason 必须 urlencode
    ——特殊字符经编码后作为 reason 值整体回跳，不得注入为独立 query 参数。"""
    mid = await _setup(client)
    r = await _authorize(client, mid)
    state = parse_qs(urlparse(r.json()["authorization_url"]).query)["state"][0]
    resp = await client.get(
        f"/oauth/callback/{mid}?error=access%20denied%26evil%3D1%23frag&state={state}",
        follow_redirects=False)
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    # 解码后为 AS 原值；裸拼接会拆出 evil=1 独立参数且 #frag 丢失进 fragment
    assert query == {"binding": ["failed"], "reason": ["access denied&evil=1#frag"]}


async def test_callback_bogus_code_token_exchange_failed_no_credential(client, app):
    """Task 4 评审携带批：code 换 token 失败分支（伪造 code → AS 400）→
    302 binding=failed&reason=token_exchange，且不落任何凭证行。"""
    mid = await _setup(client)
    r = await _authorize(client, mid)
    state = parse_qs(urlparse(r.json()["authorization_url"]).query)["state"][0]
    resp = await client.get(f"/oauth/callback/{mid}?code=cd-bogus-forged&state={state}",
                            follow_redirects=False)
    assert resp.status_code == 302
    assert "binding=failed&reason=token_exchange" in resp.headers["location"]
    from agent_proxy.oauth.credential import load_credential
    async with app.state.sessionmaker() as session:
        assert await load_credential(session, app.state.redis, mid, 888) is None


async def test_full_flow_client_secret_basic(client, app):
    """Task 4 评审携带批：client_secret_basic 形态端到端——token 请求走 HTTP Basic
    （RFC 6749 §2.3.1），mock AS 按 Basic 解码校验，绑定成功落库。"""
    mid = await _create_oauth(client)
    resp = await client.put(f"/api/v1/builtin-mappings/{mid}/client",
                            json={**CLIENT_BODY, "token_auth": "client_secret_basic"},
                            headers=ADMIN)
    assert resp.status_code == 200, resp.text
    assert resp.json()["token_auth"] == "client_secret_basic"
    cb, _ = await _bind(client, mid)
    assert cb.status_code == 302
    assert cb.headers["location"] == f"{FRONT}?binding=success"
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthClient).where(
            OAuthClient.mapping_id == mid))).scalar_one()
    assert row.token_auth == "client_secret_basic"       # basic 形态落库
    b = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "bound"


async def test_front_redirect_whitelist_400(client):
    mid = await _setup(client)
    for bad in ("http://evil.example.com/cb", "http://testserver:8080/cb",
                "javascript:alert(1)", "/relative",
                "http://testserver/cb\r\nX-Inj: 1"):     # CRLF 注入（Task 4 评审携带批）
        resp = await _authorize(client, mid, front=bad)
        assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_authorize_on_static_public_400(client):
    mid = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "static",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}},
        headers=ADMIN)).json()["mapping_id"]
    resp = await _authorize(client, mid)
    assert resp.status_code == 400 and resp.json()["code"] == "OAUTH_NOT_APPLICABLE"
    resp = await client.get(f"/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert resp.status_code == 400 and resp.json()["code"] == "OAUTH_NOT_APPLICABLE"


async def test_authorize_without_client_dcr_setup_failed(client):
    """Task 5 迁移：无 client 行不再 400 NOT_CONFIGURED——先走 DCR（§14.3）；
    上游 9901 无 well-known → 502 OAUTH_CLIENT_SETUP_FAILED。"""
    mid = await _create_oauth(client, upstream="http://127.0.0.1:9901/api/v1")
    resp = await _authorize(client, mid)
    assert resp.status_code == 502
    assert resp.json()["code"] == "OAUTH_CLIENT_SETUP_FAILED"


async def test_authorize_private_or_missing_404(client):
    private = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "private",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}},
        headers=ADMIN)).json()["mapping_id"]
    resp = await _authorize(client, private)
    assert resp.status_code == 404                       # 非 public 隐藏存在性
    resp = await _authorize(client, "aaaaaaaaaaaa")
    assert resp.status_code == 404
