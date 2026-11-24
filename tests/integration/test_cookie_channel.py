"""既有 API 的 Cookie 通道兼容（M7，§15.1「既有 API 兼容零破坏」）：同一
get_current_identity 下 /api/v1 以纯 Cookie 会话访问（页面 fetch 场景）；
Bearer 通道与优先级零破坏。"""
from agent_proxy.auth import Identity
from agent_proxy.sso.session import SESSION_COOKIE, create_session, destroy_session
from tests.utils import make_token

BODY = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1",
        "headers": {"Authorization": "Bearer sk-real-key"}}


async def test_mgmt_create_list_with_cookie_session_only(client, app):
    sid = await create_session(app.state.redis, Identity(user_id="u888", user_name="张三"), 600)
    r = await client.post("/api/v1/mappings", json=BODY, cookies={SESSION_COOKIE: sid})
    assert r.status_code == 201 and r.json()["mapping_id"]
    r = await client.get("/api/v1/mappings", cookies={SESSION_COOKIE: sid})
    assert r.status_code == 200 and len(r.json()) == 1
    assert r.json()[0]["upstream_url"] == BODY["upstream_url"]


async def test_bearer_takes_precedence_over_cookie_in_api(client, app):
    r = await client.post("/api/v1/mappings", json=BODY,
                          headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert r.status_code == 201
    sid = await create_session(app.state.redis, Identity(user_id="u999"), 600)
    r = await client.get("/api/v1/mappings",
                         headers={"Authorization": f"Bearer {make_token('u888')}"},
                         cookies={SESSION_COOKIE: sid})
    # Bearer（u888）优先于 Cookie（u999）：返回 u888 的 1 条而非 u999 的空列表
    assert r.status_code == 200 and len(r.json()) == 1


async def test_destroyed_session_cookie_401(client, app):
    sid = await create_session(app.state.redis, Identity(user_id="u888"), 600)
    await destroy_session(app.state.redis, sid)
    r = await client.get("/api/v1/mappings", cookies={SESSION_COOKIE: sid})
    assert r.status_code == 401 and r.json()["code"] == "INVALID_TOKEN"


async def test_missing_credentials_401_unchanged(client):
    r = await client.get("/api/v1/mappings")
    assert r.status_code == 401 and r.json()["code"] == "INVALID_TOKEN"


async def test_cookie_channel_public_visibility_guard(client, app):
    """Cookie 通道下权限矩阵照旧生效（页面不做越权捷径的 API 侧兜底）。"""
    sid = await create_session(app.state.redis, Identity(user_id="u888"), 600)
    r = await client.post("/api/v1/mappings", json={**BODY, "visibility": "public"},
                          cookies={SESSION_COOKIE: sid})
    assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"
