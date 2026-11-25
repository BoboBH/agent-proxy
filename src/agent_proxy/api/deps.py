"""FastAPI 依赖。"""
from __future__ import annotations

from fastapi import Request

from ..auth import Identity, TokenInvalidError, build_verifier
from ..config import get_settings
from ..sso.session import SESSION_COOKIE, get_session


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
    """身份双通道（M7，设计 §15.1「会话与鉴权兼容」）：

    - Bearer 优先：Agent / API 场景语义不变；携带 Bearer 而校验失败 → 401，
      **不回退** Cookie——失效凭证被静默回退掩盖 = 已撤销用户凭残留会话放行；
    - 无 Bearer → Cookie 会话回退（管理页面场景，服务端会话 ap:sess:{sid}）；
      else 分支语义（评审钉住）：**仅 Bearer 触发「失败不回退」**——Bearer 是
      明确的凭证出示，失效必须 401；其他 scheme（如 Basic）不构成凭证出示，
      不遮蔽 Cookie 通道（带 Basic 头 + 有效会话照常放行，
      test_basic_scheme_with_valid_cookie_uses_session_identity）；
    - 两通道均未命中 → 401 INVALID_TOKEN（既有 401 面同码，仅 message 更新，
      设计 §10 错误码表零变更）。
    """
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        identity = await _get_verifier().verify(header[7:].strip())
    else:
        identity = await _session_identity(request)
        if identity is None:
            raise TokenInvalidError("缺少 Authorization: Bearer token 或登录会话")
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
