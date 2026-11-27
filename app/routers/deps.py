"""FastAPI 依赖。"""
from __future__ import annotations

from fastapi import Request

from app.services.auth import Identity, TokenInvalidError, build_verifier
from app.env import get_settings
from app.services.sso.session import SESSION_COOKIE, get_session


async def get_db(request: Request):
    async with request.app.state.sessionmaker() as session:
        yield session


_verifier = None


def _get_verifier():
    global _verifier
    if _verifier is None:
        _verifier = build_verifier(get_settings().token_verify_impl)
    return _verifier


async def get_current_identity(request: Request) -> Identity:
    """身份双通道（设计 v2 换名 + §15.1「会话与鉴权兼容」）：

    - 身份通道 = **X-Proxy-Authorization: Bearer <token>**（保留命名空间）：
      `Authorization` 已让位上游语义（skill 教传的上游凭证头原样透传，设计 v2），
      代理绝不再消费它；携带本头 Bearer 而校验失败 → 401，**不回退** Cookie——
      失效凭证被静默回退掩盖 = 已撤销用户凭残留会话放行；
    - 无本头 → Cookie 会话回退（管理页面场景，服务端会话 ap:sess:{sid}）；
      else 分支语义（评审钉住沿袭）：**仅 Bearer 触发「失败不回退」**——Bearer 是
      明确的凭证出示，失效必须 401；其他 scheme（如 Basic）不构成凭证出示，
      不遮蔽页面/工具场景的 Cookie 通道；
    - 两通道均未命中 → 401 INVALID_TOKEN（错误码表零变更）。
    """
    settings = get_settings()
    header_name = (settings.proxy_auth_header or "Authorization").strip()
    header = request.headers.get(header_name, "")
    lowered = header.strip().lower()
    if lowered.startswith("bearer ") or lowered.startswith("token "):
        # 凭证出示（设计 v4.1）：完整头值交给 verifier——third_party 原样透传验签
        # （接口支持 Bearer/Token 两种 scheme）；失败必 401 不回退 Cookie
        identity = await _get_verifier().verify_credential(header.strip())
    else:
        identity = await _session_identity(request)
        if identity is None:
            raise TokenInvalidError(f"缺少 {header_name}: Bearer token 或登录会话")
    request.state.user_id = identity.user_id
    request.state.user_name = identity.user_name or ""
    return identity


async def _session_identity(request: Request) -> Identity | None:
    """Cookie 通道：ap_sess → ap:sess:{sid} → Identity；无 Cookie / 会话不存在 /
    过期（Redis TTL 惰性删除）/ 载荷非法 → None（上层按未登录 401 处理）。"""
    sid = request.cookies.get(SESSION_COOKIE, "")
    if not sid:
        return None
    return await get_session(request.app.state.redis, sid)


def is_admin(identity: Identity, admin_role: str) -> bool:
    return identity.role == admin_role
