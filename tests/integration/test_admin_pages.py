"""管理页面路由集成（M7，§15.1）：入口 302、stub 登录页、callback 建会话
（Set-Cookie 属性 + Redis 键）、模板身份注入与 admin 视图隔离、开放重定向防护、
退出登录。页面 fetch 的业务流（Cookie 通道走 /api/v1）见 test_admin_browser_flow.py。"""
import json
from urllib.parse import quote

from agent_proxy.auth import Identity
from agent_proxy.sso.session import SESSION_COOKIE, create_session, session_key
from tests.utils import make_token

ADMIN = "/admin"


async def test_admin_without_session_redirects_to_login(client):
    r = await client.get(ADMIN)
    assert r.status_code == 302
    assert r.headers["location"] == "/admin/login?return_to=%2Fadmin"
    assert r.headers.get("set-cookie") is None       # 未登录不落任何 Cookie


async def test_stub_login_page_renders_with_callback_form(client):
    r = await client.get("/admin/login?return_to=%2Fadmin")
    assert r.status_code == 200
    assert 'action="/admin/auth/callback"' in r.text
    assert 'name="return_to"' in r.text
    assert 'id="user_id"' in r.text
    assert '<option value="admin">' in r.text        # 角色选择（admin 即管理员）


async def test_callback_builds_session_and_cookie_attributes(client, app):
    """§15.1 时序 4-6：exchange → 会话入 Redis → Set-Cookie（HttpOnly+SameSite=Lax；
    Secure 由 SESSION_COOKIE_SECURE 配置，测试环境 http 下为 false）→ 302 /admin。"""
    r = await client.get(f"/admin/auth/callback?ticket={make_token('u888', user_name='张三')}")
    assert r.status_code == 302 and r.headers["location"] == "/admin"
    set_cookie = r.headers["set-cookie"]
    assert f"{SESSION_COOKIE}=" in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=lax" in set_cookie.lower()
    assert "max-age=28800" in set_cookie.lower()     # ADMIN_SESSION_TTL 默认值
    assert "secure" not in set_cookie.lower()        # SESSION_COOKIE_SECURE=false（测试环境）
    raw = await app.state.redis.get(session_key(r.cookies[SESSION_COOKIE]))
    assert raw and json.loads(raw)["user_id"] == "u888"   # 服务端会话已入 Redis


async def test_callback_session_ttl_uses_admin_session_ttl(client, app):
    r = await client.get(f"/admin/auth/callback?ticket={make_token('u1')}")
    ttl = await app.state.redis.ttl(session_key(r.cookies[SESSION_COOKIE]))
    assert 0 < ttl <= app.state.settings.admin_session_ttl
    assert ttl > 8000                                # 非「秒级误传」形态


async def test_callback_pure_digit_ticket_becomes_identity(client, app):
    """stub 简化（评审指令）：纯数字票据直接作 user_id（StubVerifier 在 JWT 解析前
    短路）——登录页「输入数字即身份」的服务端面；会话照常建立。"""
    r = await client.get("/admin/auth/callback?ticket=12345")
    assert r.status_code == 302 and r.headers["location"] == "/admin"
    raw = await app.state.redis.get(session_key(r.cookies[SESSION_COOKIE]))
    assert raw and json.loads(raw)["user_id"] == "12345"


async def test_admin_renders_with_session_and_identity_context(client, app):
    sid = await create_session(app.state.redis,
                               Identity(user_id="u888", user_name="张三"), 600)
    r = await client.get(ADMIN, headers={"Cookie": f"{SESSION_COOKIE}={sid}"})
    assert r.status_code == 200
    assert "张三" in r.text                          # 身份上下文由模板注入（§15.1）
    assert "公共映射管理" not in r.text              # 非 admin 视图隔离
    assert 'data-view="public"' not in r.text


async def test_admin_context_admin_role_shows_public_view(client, app):
    sid = await create_session(app.state.redis,
                               Identity(user_id="boss", user_name="管理员", role="admin"), 600)
    r = await client.get(ADMIN, headers={"Cookie": f"{SESSION_COOKIE}={sid}"})
    assert r.status_code == 200
    assert "公共映射管理" in r.text and 'data-view="public"' in r.text


async def test_callback_invalid_ticket_redirects_login_without_session(client, app):
    r = await client.get(f"/admin/auth/callback?ticket=stub.bad!!.sig&return_to=%2Fadmin")
    assert r.status_code == 302
    assert r.headers["location"].startswith("/admin/login?")
    assert "invalid_ticket" in r.headers["location"]
    assert r.headers.get("set-cookie") is None       # 不落会话
    keys = [k async for k in app.state.redis.scan_iter("ap:sess:*")]
    assert keys == []                                # Redis 无会话残留


async def test_callback_return_to_open_redirect_neutralized(client):
    """return_to 仅站内相对路径（/ 开头且非 //）：绝对地址 / 协议相对地址一律回 /admin。"""
    for bad in ("//evil.com", "https://evil.com/x", "javascript:alert(1)"):
        r = await client.get(
            f"/admin/auth/callback?ticket={make_token('u1')}&return_to={quote(bad, safe='')}")
        assert r.status_code == 302
        assert r.headers["location"] == "/admin"


async def test_logout_deletes_server_session_and_cookie(client, app):
    sid = await create_session(app.state.redis, Identity(user_id="u888"), 600)
    r = await client.post("/admin/logout", headers={"Cookie": f"{SESSION_COOKIE}={sid}"})
    assert r.status_code == 302
    assert r.headers["location"].startswith("/admin/login")
    assert await app.state.redis.get(session_key(sid)) is None   # 服务端会话已删（§15.1）
    assert "max-age=0" in r.headers["set-cookie"].lower()        # 清浏览器 Cookie
    assert (await client.get(ADMIN,
                             headers={"Cookie": f"{SESSION_COOKIE}={sid}"})).status_code == 302
