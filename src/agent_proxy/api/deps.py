"""FastAPI 依赖。"""
from __future__ import annotations

from fastapi import Request

from ..auth import Identity, TokenInvalidError, build_verifier
from ..config import get_settings


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
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise TokenInvalidError("缺少 Authorization: Bearer token")
    identity = await _get_verifier().verify(header[7:].strip())
    request.state.uid = identity.user_id
    request.state.user_name = identity.user_name or ""
    return identity


def is_admin(identity: Identity, admin_role: str) -> bool:
    return identity.role == admin_role
