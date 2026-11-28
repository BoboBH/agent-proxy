"""管理页 token 登录集成测试（v4.3：third_party 验签凭据换会话 + org/role 门禁）。

- 验签服务经 httpx.MockTransport 注入（不出网）；
- 有效凭据 → 200 + Set-Cookie 会话 + /admin 页面 200（身份生效）；
- 无效凭据 → 401 JSON；验签服务不可用 → 503 JSON；
- stub 模式 → 400（token 登录仅 third_party 提供）；
- 管理面（/load）仅 org_id=7 且 user_type=org_member（ADMIN_USER_TYPE 配置值）可用（v4.3 双匹配）。
"""
import httpx
import pytest

from app.main import create_app
from app.services.auth import ThirdPartyVerifier

BETA = "https://bapal.9m-tec.com/alphapal/api/ai-service"
BASE_OK = {"valid": True, "user_id": 5364, "username": "someone@example.com",
           "real_name": "张三", "status": "active", "token_kind": "access",
           "org_id": 7, "user_type": "org_member"}
WRONG_ORG_BODY = {**BASE_OK, "org_id": 5}   # org 不匹配（同 user_type）→ 非 admin


def _app(monkeypatch, handler):
    # 显式构造 Settings（不经 get_settings()）——绝不污染全局 lru_cache：
    # 一旦把 monkeypatch 环境下的 Settings 缓存进全局，后续文件的测试会读到
    # 被毒化的配置（third_party/bapal），全线失败（本次联合运行实测）。
    from app.env import BASE_DIR, Settings
    settings = Settings(_env_file=BASE_DIR / ".env", token_verify_impl="third_party",
                        verify_api_base=BETA, log_dir="logs-test")
    from app.routers import admin as admin_mod
    monkeypatch.setattr(admin_mod, "_build_login_verifier",
                        lambda s: ThirdPartyVerifier(settings.verify_api_base,
                                                     transport=httpx.MockTransport(handler)))
    return create_app(settings)


def _ok_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=BASE_OK)


async def test_token_login_success_sets_session(monkeypatch):
    app = _app(monkeypatch, _ok_handler)
    from httpx import ASGITransport, AsyncClient
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://testserver") as c:
            r = await c.post("/admin/auth/token-login",
                             json={"token": "Token abc.def.sig"})
            assert r.status_code == 200, r.text
            assert r.json()["ok"] is True and r.json()["user_id"] == 5364
            assert "ap_sess" in r.cookies

            # 会话生效：携带 Cookie 访问 /admin 页面 200（admin 身份可见全部视图）
            page = await c.get("/admin")
            assert page.status_code == 200
            assert "实时负载" in page.text           # admin 身份可见负载入口

            # 退出登录后 Cookie 失效
            await c.post("/admin/logout")
            page2 = await c.get("/admin", follow_redirects=False)
            assert page2.status_code == 302


async def test_token_login_invalid_credential_401(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"msg": "令牌已过期"})

    app = _app(monkeypatch, handler)
    from httpx import ASGITransport, AsyncClient
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://testserver") as c:
            r = await c.post("/admin/auth/token-login", json={"token": "Token expired"})
            assert r.status_code == 401
            assert r.json()["code"] == "INVALID_TOKEN"
            assert "令牌已过期" in r.json()["message"]


async def test_token_login_verify_service_unavailable_503(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    app = _app(monkeypatch, handler)
    from httpx import ASGITransport, AsyncClient
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://testserver") as c:
            r = await c.post("/admin/auth/token-login", json={"token": "Token x"})
            assert r.status_code == 503
            assert r.json()["code"] == "AUTH_SERVICE_UNAVAILABLE"


async def test_token_login_unavailable_in_stub_mode():
    from app.env import BASE_DIR, Settings
    from app.main import create_app
    settings = Settings(_env_file=BASE_DIR / ".env", token_verify_impl="stub",
                        log_dir="logs-test")
    from httpx import ASGITransport, AsyncClient
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        async with AsyncClient(transport=ASGITransport(app=application),
                               base_url="http://testserver") as c:
            r = await c.post("/admin/auth/token-login", json={"token": "Token abc"})
            assert r.status_code == 400
            assert r.json()["code"] == "INVALID_PARAM"


async def test_non_admin_org_cannot_access_load(monkeypatch):
    """v4.3 双匹配：org_id≠7 或 user_type≠admin 的会话访问 /load → 403。"""
    from httpx import ASGITransport, AsyncClient
    app = _app(monkeypatch, lambda request: httpx.Response(
        200, json={**BASE_OK, "user_type": "org_member", "org_id": 5}))
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://testserver") as c:
            login = await c.post("/admin/auth/token-login",
                                 json={"token": "Token abc.def.sig"})
            assert login.status_code == 200
            r = await c.get("/api/v1/mappings/load")
            assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"


async def test_org7_admin_can_access_load(monkeypatch):
    from httpx import ASGITransport, AsyncClient
    app = _app(monkeypatch, _ok_handler)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://testserver") as c:
            login = await c.post("/admin/auth/token-login",
                                 json={"token": "Token abc.def.sig"})
            assert login.status_code == 200
            r = await c.get("/api/v1/mappings/load")
            assert r.status_code == 200
            assert "mappings" in r.json()
