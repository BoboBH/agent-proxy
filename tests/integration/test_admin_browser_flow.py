"""浏览器式全流程（M7 §16 验收「浏览器经 stub 登录完成全部页面操作」的自动化面）。

httpx Client 自带 Cookie Jar 模拟浏览器：GET /admin 302 → 登录页可渲染 → 构造
stub 票据（与登录页 JS 同构）→ callback Set-Cookie → 后续请求自动携带 → 经
Cookie 通道完成我的映射（注册/resolve/test/删除）、内置 MCP 列表、（admin）公共
映射 CRUD + OAuth client 手动配置、退出登录；非 admin 视图隔离与 API 侧 403 兜底
（页面不做越权捷径的两层钉住）；真实 TCP 冒烟（9910：页面路由 + Cookie 通道注册）。
"""
import httpx
from httpx import ASGITransport, AsyncClient

from app.services.sso.session import SESSION_COOKIE
from tests.utils import make_token

BASE = "http://testserver"
PROXY = "http://127.0.0.1:9910"
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)

HTTP_BODY = {"type": "http", "upstream_url": "http://127.0.0.1:9901/api/v1",
             "headers": {"Authorization": "Bearer sk-real-1234567890"}}


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url=BASE)


async def _browser_login(c: AsyncClient, user_id: int, role: str | None = None) -> None:
    """复刻登录页表单行为：入口 302 → 登录页可渲染 → 票据 callback → 会话 Cookie 入 jar。"""
    r = await c.get("/admin")
    assert r.status_code == 302 and r.headers["location"].startswith("/admin/login")
    page = await c.get(r.headers["location"])
    assert page.status_code == 200 and 'action="/admin/auth/callback"' in page.text
    r = await c.get("/admin/auth/callback",
                    params={"ticket": make_token(user_id, role), "return_to": "/admin"})
    assert r.status_code == 302 and r.headers["location"] == "/admin"
    assert c.cookies.get(SESSION_COOKIE), "会话 Cookie 未入 jar"


async def test_full_browser_flow_admin_as_admin(app):
    async with _client(app) as c:
        await _browser_login(c, 100, role="org_member")
        assert (await c.get("/admin")).status_code == 200

        # 我的映射：注册（占位符响应）→ resolve 回显 → test（echo 9901 连通判定）→ 删除
        r = await c.post("/api/v1/mappings", json=HTTP_BODY)
        assert r.status_code == 201
        mid = r.json()["mapping_id"]
        assert r.json()["headers"] == {"Authorization": "{{RUNTIME_TOKEN}}"}
        r = await c.get("/api/v1/mappings/resolve", params={"proxy_url": mid})
        assert r.json()["headers"]["Authorization"] == "Bearer sk-real-1234567890"
        r = await c.post(f"/api/v1/mappings/{mid}/test")
        assert r.status_code == 200 and r.json()["ok"] is True

        # 内置 MCP 列表（Cookie 通道；空库为空列表）
        # （计划原稿缺陷修复：`await c.get(...).json()` 优先级即 `await (c.get(...).json())`，
        # 对 coroutine 取 .json() 必 AttributeError——await 表达式需加括号）
        assert (await c.get("/api/v1/builtin-mappings")).json() == []

        # 公共映射管理（admin）：创建 public+oauth → 手动 client → 查看配置 → 删除
        r = await c.post("/api/v1/mappings",
                         json={**HTTP_BODY, "visibility": "public", "auth_mode": "oauth",
                               "name": "公共测试"})
        assert r.status_code == 201
        pub = r.json()["mapping_id"]
        r = await c.put(f"/api/v1/builtin-mappings/{pub}/client", json={
            "client_id": "manual-cl", "client_secret": "manual-cs-123456",
            "token_auth": "client_secret_post",
            "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
            "token_url": "http://127.0.0.1:9904/oauth/token"})
        assert r.status_code == 200 and r.json()["source"] == "manual"
        r = await c.get(f"/api/v1/builtin-mappings/{pub}/client")
        assert r.status_code == 200 and r.json()["client_secret_configured"] is True
        assert (await c.delete(f"/api/v1/mappings/{mid}")).status_code == 204

        # 退出登录：会话删除 → /admin 回到 302 登录（Cookie 已失效）
        assert (await c.post("/admin/logout")).status_code == 302
        assert (await c.get("/admin")).status_code == 302


async def test_non_admin_view_isolated_and_api_privilege_enforced(app):
    """§15.1「admin 视图权限隔离」+「页面不做越权捷径」两层钉住：
    页面入口隐藏（模板不含 public 视图）+ 直接打 API 仍被既有矩阵拦（403）。"""
    async with _client(app) as c:
        r = await c.post("/api/v1/mappings", json={**HTTP_BODY, "visibility": "public"},
                         headers={"Authorization": f"Bearer {make_token(100, role='org_member')}"})
        assert r.status_code == 201
        pub = r.json()["mapping_id"]
        await _browser_login(c, 888)
        page = await c.get("/admin")
        assert page.status_code == 200
        assert "公共映射管理" not in page.text            # 视图隔离（模板入口隐藏）
        assert 'data-view="public"' not in page.text
        # 页面不做越权捷径：绕过页面直接打 API 同样被既有矩阵拦下
        r = await c.post("/api/v1/mappings", json={**HTTP_BODY, "visibility": "public"})
        assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"
        r = await c.put(f"/api/v1/builtin-mappings/{pub}/client", json={
            "client_id": "x",
            "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
            "token_url": "http://127.0.0.1:9904/oauth/token"})
        assert r.status_code == 403
        # 内置映射列表任意有效身份可见（§14.2），但 client 配置查询仅 admin
        assert (await c.get("/api/v1/builtin-mappings")).status_code == 200
        assert (await c.get(f"/api/v1/builtin-mappings/{pub}/client")).status_code == 403


async def test_real_tcp_admin_page_and_cookie_channel(real_proxy_app):
    """真实 TCP（9910）：页面路由可达 + stub 登录 → Cookie 通道注册映射 → 页面渲染
    → 退出登录后会话失效（SESSION_COOKIE_SECURE=false 下纯 http 可携带 Cookie）。"""
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/admin", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"].startswith("/admin/login")
        r = await c.get(f"{PROXY}/admin/auth/callback",
                        params={"ticket": make_token(888)}, follow_redirects=False)
        assert r.status_code == 302
        assert c.cookies.get(SESSION_COOKIE)
        r = await c.post(f"{PROXY}/api/v1/mappings", json=HTTP_BODY)
        assert r.status_code == 201
        r = await c.get(f"{PROXY}/admin")
        assert r.status_code == 200 and "我的映射" in r.text
        r = await c.post(f"{PROXY}/admin/logout", follow_redirects=False)
        assert r.status_code == 302
        assert (await c.get(f"{PROXY}/admin")).status_code == 302      # 会话已删
