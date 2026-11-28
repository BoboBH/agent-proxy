"""Web 管理页面（M7，设计 §15.1）：本服务托管，Jinja2 + 原生 JS fetch，无前端构建链。

路由（tags=["admin"]；middleware.route_name 已把 /admin* 归 route=admin——M1 预留，
ap_requests_total{route="admin"} 由既有中间件自动生效，§15.2）：
- GET  /admin                页面入口：会话有效 → 渲染 index（身份注入模板上下文，
                             is_admin 决定「公共映射管理」入口显隐；权限边界仍在 API，
                             页面不做越权捷径）；无会话 → 302 LoginProvider.login_url
- GET  /admin/login          stub 假登录页（LOGIN_IMPL=stub）：选择用户/角色，浏览器侧
                             按 StubVerifier 同格式构造票据提交 callback；company_sso
                             接入后 login_url 指向外部登录地址，本页自然旁路
- GET  /admin/auth/callback  承接回跳（§15.1 时序 4-6）：exchange(ticket) → Identity →
                             服务端会话入 Redis ap:sess:{sid}（TTL=ADMIN_SESSION_TTL）→
                             Set-Cookie ap_sess（HttpOnly+SameSite=Lax，Secure 由
                             SESSION_COOKIE_SECURE 配置）→ 302 return_to（仅站内路径）；
                             票据无效 → 302 回登录页（error=invalid_ticket，不落会话，
                             页面不显示原始 JSON 错误）
- POST /admin/logout         退出登录（§15.1「退出登录删除会话」）：删 Redis 会话
                             （Cookie 中的 sid 随即失效、重放无效）+ 清 Cookie → 302 登录页

页面 API 全部走既有 /api/v1 接口（同源 fetch 默认携带 Cookie，get_current_identity
Cookie 回退通道，§15.1「既有 API 兼容零破坏」）；页面本身不写任何业务数据。
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.services.auth import (Identity, ThirdPartyVerifier, TokenInvalidError,
                               TokenServiceError)
from app.env import Settings, get_settings
from app.services.sso.login import get_login_provider
from app.services.sso.session import SESSION_COOKIE, create_session, destroy_session, get_session
from app.routers.deps import get_current_identity, is_admin

router = APIRouter(tags=["admin"])
# 模板随源码目录就位（app/admin/，无运行时配置项，Path(__file__) 定位）
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "admin"))


def _safe_return_to(return_to: str) -> str:
    """仅接受站内相对路径，防开放重定向；其余一律归一 /admin。

    - 反斜杠归一后再判（评审修复）：WHATWG 相对态把 \\ 视同 /，`/\\evil.com` 是
      协议相对地址，仅拒 `//` 挡不住——归一 `\\`→`/` 后即落 `//` 形态被拒；
    - 含 CR/LF 拒收（CRLF 头注入面在入口掐掉，不交给下游转义兜底）；
    - 组装 Location 前由调用方 quote(safe="/?=&")，成功/错误分支一致——不依赖
      Starlette 版本相关的 RedirectResponse 再编码行为。
    （沿用 M6 front_redirect 评审结论：跳转目标必须是服务端可判定的白名单形态。）"""
    normalized = return_to.replace("\\", "/")
    if "\r" in normalized or "\n" in normalized:
        return "/admin"
    if normalized.startswith("/") and not normalized.startswith("//"):
        return normalized
    return "/admin"


async def _page_identity(request: Request) -> Identity | None:
    """页面身份：仅会话 Cookie（页面为浏览器场景，不消费 Bearer——HTML 入口的
    Bearer 无意义且会干扰「未登录 → 302 登录」的判定）。"""
    return await get_session(request.app.state.redis,
                             request.cookies.get(SESSION_COOKIE, ""))


def _set_session_cookie(response: RedirectResponse, settings: Settings, sid: str) -> None:
    response.set_cookie(SESSION_COOKIE, sid, max_age=settings.admin_session_ttl,
                        path="/", httponly=True, samesite="lax",
                        secure=settings.session_cookie_secure)


@router.get("/admin")
async def admin_index(request: Request, settings: Settings = Depends(get_settings)):
    identity = await _page_identity(request)
    if identity is None:
        return RedirectResponse(get_login_provider().login_url("/admin"), status_code=302)
    request.state.user_id = identity.user_id                       # 审计身份（middleware 行）
    request.state.user_name = identity.user_name or ""
    request.state.audit_action = "view_admin_page"
    return templates.TemplateResponse(request, "index.html", {
        "user_name": identity.user_name or str(identity.user_id),
        # is_admin 仅决定入口显隐；越权请求仍由 /api/v1 既有权限矩阵兜底（403/404）
        "is_admin": is_admin(identity, settings.admin_user_type, settings.admin_org_id),
    })


@router.get("/admin/login")
async def admin_login(request: Request, return_to: str = "/admin", error: str = ""):
    request.state.audit_action = "view_login_page"
    settings = get_settings()
    return templates.TemplateResponse(request, "login.html", {
        "return_to": _safe_return_to(return_to), "error": error,
        # token 登录仅 third_party 验签模式提供（凭据交 ai-service verify_token 校验）
        "token_login_enabled": settings.token_verify_impl == "third_party"})


class TokenLoginIn(BaseModel):
    """POST /admin/auth/token-login 请求体：粘贴第三方验签体系签发的凭据
    （形如 `Token eyJ...` / `Bearer eyJ...`，scheme 原样透传给验签接口）。"""
    token: str = Field(min_length=1, max_length=4096)


def _build_login_verifier(settings: Settings) -> ThirdPartyVerifier:
    """token 登录的验签器工厂（测试经 monkeypatch 注入 MockTransport）。"""
    return ThirdPartyVerifier(settings.verify_api_base)


@router.post("/admin/auth/token-login")
async def token_login(request: Request, body: TokenLoginIn,
                      settings: Settings = Depends(get_settings)):
    """token 登录（v4.3，仅 third_party 验签模式）：粘贴 ai-service 签发的凭据 →
    verify_token 校验 → Identity → 服务端会话 → Set-Cookie → 200 JSON。

    与公司 SSO 回跳互斥点：SSO 是浏览器重定向流（票据在 URL），token 登录是
    本地粘贴流（凭据在 body）——两者只产生会话，页面权限矩阵完全一致。
    失败统一 401 JSON（浏览器表单 fetch 显示 message）；验签服务不可用 → 503。
    """
    if settings.token_verify_impl != "third_party":
        return JSONResponse(status_code=400,
                            content={"code": "INVALID_PARAM",
                                     "message": "token 登录仅 third_party 验签模式可用"})
    try:
        identity = await _build_login_verifier(settings).verify_credential(body.token.strip())
    except TokenInvalidError as exc:
        request.state.audit_action = "login_token_failed"
        return JSONResponse(status_code=401,
                            content={"code": exc.code, "message": exc.message})
    except TokenServiceError as exc:
        request.state.audit_action = "login_token_failed"
        return JSONResponse(status_code=exc.status,
                            content={"code": exc.code, "message": exc.message})
    sid = await create_session(request.app.state.redis, identity,
                               settings.admin_session_ttl)
    resp = JSONResponse(content={"ok": True, "user_id": identity.user_id,
                                 "role": identity.role})
    resp.set_cookie(SESSION_COOKIE, sid, max_age=settings.admin_session_ttl,
                    httponly=True, samesite="lax",
                    secure=settings.session_cookie_secure, path="/")
    return resp


@router.get("/admin/auth/callback")
async def admin_auth_callback(request: Request, settings: Settings = Depends(get_settings),
                              ticket: str = "", return_to: str = "/admin"):
    """§15.1 时序 4-6：票据换身份 → 建服务端会话 → Set-Cookie → 302 回页面。
    票据无效不落会话，302 回登录页带 error=invalid_ticket（浏览器友好，排障靠
    服务端日志）；return_to 先过 _safe_return_to，组装 Location 前 quote（防
    CRLF 头注入——M6 front_redirect 评审同款结论）。"""
    try:
        identity = await get_login_provider().exchange(ticket)
    except TokenInvalidError:
        back = quote(f"/admin/login?error=invalid_ticket&return_to="
                     f"{_safe_return_to(return_to)}", safe="/?=&")
        return RedirectResponse(back, status_code=302)
    sid = await create_session(request.app.state.redis, identity,
                               settings.admin_session_ttl)
    request.state.user_id = identity.user_id
    request.state.user_name = identity.user_name or ""
    request.state.audit_action = "admin_login"
    # Location 组装前 quote（与错误分支一致）：防 CRLF/控制字符落头（评审修复，
    # 不依赖 Starlette 版本相关的 RedirectResponse 再编码行为）
    response = RedirectResponse(quote(_safe_return_to(return_to), safe="/?=&"),
                                status_code=302)
    _set_session_cookie(response, settings, sid)
    return response


@router.post("/admin/logout")
async def admin_logout(request: Request, settings: Settings = Depends(get_settings)):
    """退出登录：服务端会话删除后 Cookie 中的 sid 立即失效（重放无效），再清
    浏览器 Cookie → 302 登录页。POST（状态变更不走 GET 链接）。"""
    sid = request.cookies.get(SESSION_COOKIE, "")
    if sid:
        await destroy_session(request.app.state.redis, sid)
    request.state.audit_action = "admin_logout"
    response = RedirectResponse(get_login_provider().login_url("/admin"), status_code=302)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
