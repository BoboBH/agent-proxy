"""服务端会话（设计 §15.1「会话与鉴权兼容」）：Redis ap:sess:{sid} 存 Identity，
Cookie 仅存不透明 sid。

- TTL 创建时定（ADMIN_SESSION_TTL，默认 28800s），Redis 惰性过期；不做滑动续期
  （登出即删；续期策略为 M8+ 债务）；
- 载荷仅 Identity 三字段 JSON——不含任何凭证/敏感值；
- sid = secrets.token_hex(16)（128bit 随机，与 OAuth state 同强度）；
- 读取失败（Redis 异常）按未登录处理（WARN），不 500——页面场景宁可回登录页。
"""
from __future__ import annotations

import json
import logging
import secrets

from ..auth import Identity

log = logging.getLogger("agent_proxy")

SESSION_COOKIE = "ap_sess"
SESSION_KEY_PREFIX = "ap:sess:"


def session_key(sid: str) -> str:
    return f"{SESSION_KEY_PREFIX}{sid}"


def new_sid() -> str:
    return secrets.token_hex(16)


def encode_identity(identity: Identity) -> str:
    return json.dumps({"user_id": identity.user_id,
                       "user_name": identity.user_name,
                       "role": identity.role}, ensure_ascii=False)


def decode_identity(raw: str | bytes) -> Identity | None:
    """载荷非法（坏 JSON / 缺 user_id / user_id 非 str）→ None（按未登录处理，
    不抛——会话数据损坏不该变成 500）。"""
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("user_id"), str):
        return None
    return Identity(user_id=payload["user_id"],
                    user_name=payload.get("user_name"), role=payload.get("role"))


async def create_session(r, identity: Identity, ttl: int) -> str:
    """写入会话并返回 sid（TTL 由调用方传：admin_auth_callback 传
    settings.admin_session_ttl）。"""
    sid = new_sid()
    await r.set(session_key(sid), encode_identity(identity), ex=ttl)
    return sid


async def get_session(r, sid: str) -> Identity | None:
    """sid → Identity；无 sid / 键不存在（过期或已登出）/ 载荷非法 / Redis 异常
    → None（上层按未登录处理）。"""
    if not sid:
        return None
    try:
        raw = await r.get(session_key(sid))
    except Exception as exc:
        log.warning("会话读取失败，按未登录处理: %s", exc)
        return None
    if raw is None:
        return None
    return decode_identity(raw)


async def destroy_session(r, sid: str) -> None:
    """退出登录：删除服务端会话（Cookie 中的 sid 随即失效，重放无效）；幂等。"""
    try:
        await r.delete(session_key(sid))
    except Exception as exc:
        log.warning("会话删除失败: %s", exc)
