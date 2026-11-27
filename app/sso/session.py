"""服务端会话（设计 §15.1「会话与鉴权兼容」）：Redis ap:sess:{sid} 存 Identity，
Cookie 仅存不透明 sid。

- TTL 创建时定（ADMIN_SESSION_TTL，默认 28800s），Redis 惰性过期；不做滑动续期
  （登出即删；续期策略为 M8+ 债务）；
- 载荷仅 Identity 三字段 JSON——不含任何凭证/敏感值；
- sid = secrets.token_hex(16)（128bit 随机，与 OAuth state 同强度）；Cookie 是
  攻击者可控输入，get/destroy 对非「32 位小写 hex」的 sid 一律短路（None / no-op），
  不触达 Redis——防键空间注入；
- 读取失败（Redis 异常）按未登录处理（WARN），不 500——页面场景宁可回登录页。
"""
from __future__ import annotations

import json
import logging
import re
import secrets

from app.auth import Identity

log = logging.getLogger("agent_proxy")

SESSION_COOKIE = "ap_sess"
SESSION_KEY_PREFIX = "ap:sess:"

_SID_PATTERN = re.compile(r"[0-9a-f]{32}")


def _valid_sid(sid: str) -> bool:
    """sid 仅接受 new_sid() 的产物形态：32 位小写 hex（128bit）。

    用 fullmatch 而非 ``^...$`` + match（Task 2 评审加固）：``$`` 在尾部换行前
    也匹配，``match`` 形态会放行 ``"a"*32 + "\\n"``——fullmatch 严格全串匹配，
    无锚点歧义。"""
    return bool(_SID_PATTERN.fullmatch(sid))


def session_key(sid: str) -> str:
    return f"{SESSION_KEY_PREFIX}{sid}"


def new_sid() -> str:
    return secrets.token_hex(16)


def encode_identity(identity: Identity) -> str:
    return json.dumps({"user_id": identity.user_id,
                       "user_name": identity.user_name,
                       "role": identity.role}, ensure_ascii=False)


def decode_identity(raw: str | bytes) -> Identity | None:
    """载荷非法（坏 JSON / 非对象 / 缺或非 int 的 user_id / user_name-role 类型不符）
    → None（按未登录处理，不抛——会话数据损坏不该变成 500）。
    user_id 必须 int（收尾批次整数化；bool 不是 int 身份）。旧 str 形态载荷
    （升级前写入的会话）同样拒收 → 按未登录处理，重新登录即得新形态。"""
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    user_id = payload.get("user_id")
    user_name = payload.get("user_name")
    role = payload.get("role")
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        return None                                   # 缺 / 非 int（含 str 残留）一律拒收
    if user_name is not None and not isinstance(user_name, str):
        return None
    if role is not None and not isinstance(role, str):
        return None
    return Identity(user_id=user_id, user_name=user_name, role=role)


async def create_session(r, identity: Identity, ttl: int) -> str:
    """写入会话并返回 sid（TTL 由调用方传：admin_auth_callback 传
    settings.admin_session_ttl）。"""
    sid = new_sid()
    await r.set(session_key(sid), encode_identity(identity), ex=ttl)
    return sid


async def get_session(r, sid: str) -> Identity | None:
    """sid → Identity；无 sid / sid 形态非法（非 32 位小写 hex，直接短路不触达
    Redis）/ 键不存在（过期或已登出）/ 载荷非法 / Redis 异常 → None（上层按
    未登录处理）。"""
    if not _valid_sid(sid):
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
    """退出登录：删除服务端会话（Cookie 中的 sid 随即失效，重放无效）；幂等。
    sid 形态非法直接 no-op（无该键可删，且不触达 Redis）。"""
    if not _valid_sid(sid):
        return
    try:
        await r.delete(session_key(sid))
    except Exception as exc:
        log.warning("会话删除失败: %s", exc)
