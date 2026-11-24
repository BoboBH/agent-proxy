"""OAuth 凭证层（设计 §5.3 / §14.5 / §14.6）：强制加密存取、cred 缓存、刷新与注入。

安全底线：
- access/refresh token 落库一律 Fernet(MASTER_KEY) 密文，不受 ENCRYPT_AT_REST 开关影响；
- Redis cred 缓存（ap:cred:*，TTL 60s）存同一密文形态，读取方按需解密——缓存命中也过
  Fernet（成本可忽略），换取 Redis 侧不落明文；
- token 明文不入任何日志（本模块日志只记 mapping_id/uid/异常类型名）。

刷新（§14.5，Task 6 交付）：expires_at - 60s 内即视为过期 → refresh_token 换新；
Redis 锁 ap:lock:refresh:{mapping_id}:{uid}（SET NX EX 30）防并发刷新。

兼容性注记（实测钉死）：本地/测试 Redis 为 3.0.504，无 GETDEL 命令——凡需
"原子取删"语义一律用 MULTI 事务管道（pipeline(transaction=True)），不得改写为
getdel（生产 Redis 6.2+ 虽支持，本地 3.0 会直接报 unknown command）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..errors import AppError
from ..models import OAuthCredential

log = logging.getLogger("agent_proxy")

# 过期提前量（§14.5：expires_at - 60s 过期即 refresh）
REFRESH_SKEW_SECONDS = 60
# 刷新互斥锁 TTL（§5.3：ap:lock:refresh 30s）
REFRESH_LOCK_TTL = 30

_fernet_cache: dict[str, Fernet] = {}


def _fernet(master_key: str) -> Fernet:
    if not master_key:
        # fail-closed：无密钥宁可拒绝加密，绝不落明文（§14.6）
        raise AppError(500, "INTERNAL_ERROR", "MASTER_KEY 未配置，无法加解密 OAuth 凭证")
    f = _fernet_cache.get(master_key)
    if f is None:
        derived = base64.urlsafe_b64encode(
            hashlib.sha256(master_key.encode("utf-8")).digest())
        f = Fernet(derived)
        _fernet_cache[master_key] = f
    return f


def encrypt_text(plaintext: str, master_key: str) -> str:
    return _fernet(master_key).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(ciphertext: str, master_key: str) -> str:
    try:
        return _fernet(master_key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeEncodeError) as exc:
        raise AppError(500, "INTERNAL_ERROR",
                       "OAuth 凭证解密失败（MASTER_KEY 变更？需重新授权）") from exc


def cred_cache_key(mapping_id: str, uid: str) -> str:
    return f"ap:cred:{mapping_id}:{uid}"


def refresh_lock_key(mapping_id: str, uid: str) -> str:
    return f"ap:lock:refresh:{mapping_id}:{uid}"


def _utcnow() -> datetime:
    """aware UTC 当前时间（datetime.utcnow() 已弃用，Python 3.12 起告警）。"""
    return datetime.now(timezone.utc)


def _as_aware_utc(dt: datetime) -> datetime:
    """naive 视为 UTC（DB DateTime 列回读形态；写侧 wall time 同为 UTC）→ aware。"""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def is_expired(expires_at: datetime | None, now: datetime | None = None,
               skew: int = REFRESH_SKEW_SECONDS) -> bool:
    """§14.5：expires_at - skew <= now 视为过期；None 视为永不过期（AS 未下发
    expires_in）。时间统一 aware UTC（写读两侧均本模块 _utcnow；DB 回读的 naive
    值按 UTC 语义归一后比较）。"""
    if expires_at is None:
        return False
    current = _as_aware_utc(now) if now is not None else _utcnow()
    return _as_aware_utc(expires_at) <= current + timedelta(seconds=skew)


def expires_at_from(expires_in) -> datetime | None:
    """AS 响应 expires_in（秒）→ aware UTC expires_at（落库时 MySQL DATETIME 按
    wall time 存 UTC，回读 naive 经 _as_aware_utc 归一，语义闭环）；
    缺失/非法/非正数 → None。"""
    try:
        seconds = int(expires_in)
    except (TypeError, ValueError):
        return None
    return _utcnow() + timedelta(seconds=seconds) if seconds > 0 else None


def _row_to_cred(row: OAuthCredential) -> dict:
    return {"access_token": row.access_token, "refresh_token": row.refresh_token,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "scope": row.scope, "status": row.status}


async def _cache_get(r, mapping_id: str, uid: str) -> dict | None:
    try:
        raw = await r.get(cred_cache_key(mapping_id, uid))
    except Exception as exc:
        log.warning("cred 缓存读取失败，回源 MySQL: %s", exc)
        return None
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


async def _cache_put(r, mapping_id: str, uid: str, cred: dict, ttl: int = 60) -> None:
    try:
        await r.set(cred_cache_key(mapping_id, uid),
                    json.dumps(cred, ensure_ascii=False), ex=ttl)
    except Exception as exc:
        log.warning("cred 缓存写入失败: %s", exc)


async def invalidate_credential(r, mapping_id: str, uid: str) -> None:
    """绑定 / 解绑 / 刷新后失效 cred 缓存（§5.3：绑定 / 解绑 / 刷新时失效）。"""
    try:
        await r.delete(cred_cache_key(mapping_id, uid))
    except Exception as exc:
        log.warning("cred 缓存删除失败: %s", exc)


async def load_credential(session: AsyncSession, r, mapping_id: str, uid: str) -> dict | None:
    """缓存优先的凭证读取（密文形态，§5.3 cache-aside）；未绑定返回 None。"""
    cached = await _cache_get(r, mapping_id, uid)
    if cached is not None:
        return cached
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.uid == uid)
    )).scalar_one_or_none()
    if row is None:
        return None
    cred = _row_to_cred(row)
    await _cache_put(r, mapping_id, uid, cred)
    return cred


async def save_credential(session: AsyncSession, r, mapping_id: str, uid: str, *,
                          access_token_ct: str, refresh_token_ct: str | None,
                          expires_at: datetime | None, scope: str | None,
                          master_key: str) -> None:
    """uk(mapping_id, uid) upsert：重复授权覆盖旧凭证并复位 active（§14.4 状态机
    invalid → 重新授权 → bound）。密文由调用方以 encrypt_text 产出后传入。

    并发竞态：两个请求同 (mapping_id, uid) 同时授权，双方 SELECT 均无行 → 双
    INSERT → 一侧 commit 撞 uk IntegrityError（若不捕获会 500）——回滚后按 uk
    重读重试为 UPDATE（覆盖并发方已提交行），达成真原子 upsert 语义。"""
    new_values = {"access_token": access_token_ct, "refresh_token": refresh_token_ct,
                  "expires_at": expires_at, "scope": scope, "status": "active"}
    for attempt in range(2):
        row = (await session.execute(
            select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                          OAuthCredential.uid == uid)
        )).scalar_one_or_none()
        if row is not None:
            for k, v in new_values.items():
                setattr(row, k, v)
            await session.commit()
            break
        row = OAuthCredential(mapping_id=mapping_id, uid=uid, **new_values)
        session.add(row)
        try:
            await session.commit()
            break
        except IntegrityError:
            # 另一并发请求已插入同 uk 并提交：回滚后第二轮循环按 uk 重试为 UPDATE；
            # 第二轮再撞 uk（理论上不可达）则原样抛出。
            await session.rollback()
            if attempt == 1:
                raise
    await invalidate_credential(r, mapping_id, uid)


async def mark_credential_invalid(session: AsyncSession, r, mapping_id: str,
                                  uid: str) -> None:
    """刷新失败 → invalid（§14.4：invalid 后调用一律 401，页面引导重新授权）。"""
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.uid == uid)
    )).scalar_one_or_none()
    if row is not None and row.status != "invalid":
        row.status = "invalid"
        await session.commit()
    await invalidate_credential(r, mapping_id, uid)


async def delete_credential(session: AsyncSession, r, mapping_id: str, uid: str) -> bool:
    """解绑：删除本地凭证（revoke 由 api 层在删除前取 token 后 best-effort 调用）。
    行已不存在（重复解绑/并发删除）时同样失效 cred 缓存——过期缓存比消失的行
    更危险（缓存残留 → 已解绑用户仍被注入旧 token）。"""
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.uid == uid)
    )).scalar_one_or_none()
    if row is None:
        await invalidate_credential(r, mapping_id, uid)
        return False
    await session.delete(row)
    await session.commit()
    await invalidate_credential(r, mapping_id, uid)
    return True


# ---------- 授权进行中索引（authorizing 态判定，设计 §14.4 / §5.3 最小增量键） ----------


def authz_index_key(mapping_id: str, uid: str) -> str:
    return f"ap:oauth:authz:{mapping_id}:{uid}"


async def set_authz_index(r, mapping_id: str, uid: str, state: str, ttl: int) -> None:
    """authorize 写入（state 存续期索引，binding 查询据此判 authorizing）；
    callback 成功 / 解绑时删除。"""
    try:
        await r.set(authz_index_key(mapping_id, uid), state, ex=ttl)
    except Exception as exc:
        log.warning("authz 索引写入失败: %s", exc)


async def get_authz_index(r, mapping_id: str, uid: str) -> str | None:
    try:
        return await r.get(authz_index_key(mapping_id, uid))
    except Exception as exc:
        log.warning("authz 索引读取失败: %s", exc)
        return None


async def drop_authz_index(r, mapping_id: str, uid: str) -> None:
    try:
        await r.delete(authz_index_key(mapping_id, uid))
    except Exception as exc:
        log.warning("authz 索引删除失败: %s", exc)


async def get_binding_status(session: AsyncSession, r, mapping_id: str, uid: str) -> str:
    """绑定状态机（§14.4）：unbound → authorizing（state 存续期间）→ bound(active)
    → invalid（refresh 失败 / 提供方吊销）。判定顺序：凭证行 → authz 索引 → unbound。"""
    cred = await load_credential(session, r, mapping_id, uid)
    if cred is not None:
        return "bound" if cred.get("status") == "active" else "invalid"
    if await get_authz_index(r, mapping_id, uid) is not None:
        return "authorizing"
    return "unbound"
