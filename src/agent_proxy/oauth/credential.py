"""OAuth 凭证层（设计 §5.3 / §14.5 / §14.6）：强制加密存取、cred 缓存、刷新与注入。

安全底线：
- access/refresh token 落库一律 Fernet(MASTER_KEY) 密文（M6 强制；收尾批次起
  upstream_headers 同标准，ENCRYPT_AT_REST 可选开关已废止）；
- Redis cred 缓存（ap:cred:*，TTL 60s）存同一密文形态，读取方按需解密——缓存命中也过
  Fernet（成本可忽略），换取 Redis 侧不落明文；
- token 明文不入任何日志（本模块日志只记 mapping_id/user_id/异常类型名）。

刷新（§14.5）：expires_at - 60s 内即视为过期 → refresh_token 换新；
Redis 锁 ap:lock:refresh:{mapping_id}:{user_id}（SET NX EX 30）防并发刷新，释放带
属主校验（Lua compare-and-delete，锁值 == 持锁 request_id 才删）。失败分级
（评审 Important 2）：AS 业务拒绝（400/401/403）→ status=invalid 引导重新授权；
瞬时失败（网络 / discovery / token 端点 5xx·429 / 响应畸形）→ 凭证原状保留，
本请求 401、下轮重试。

兼容性注记（实测钉死）：本地/测试 Redis 为 3.0.504，无 GETDEL 命令——凡需
"原子取删"语义一律用 MULTI 事务管道（pipeline(transaction=True)），不得改写为
getdel（生产 Redis 6.2+ 虽支持，本地 3.0 会直接报 unknown command）。
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import metrics
from ..errors import AppError
from ..models import OAuthCredential

log = logging.getLogger("agent_proxy")

# 过期提前量（§14.5：expires_at - 60s 过期即 refresh）
REFRESH_SKEW_SECONDS = 60
# 刷新互斥锁 TTL（§5.3：ap:lock:refresh 30s）
REFRESH_LOCK_TTL = 30

# 未抢到锁时等待他人刷新完成的上限（覆盖慢 token 端点）；0.1s 轮询 cred 缓存
REFRESH_WAIT_SECONDS = 8.0
_WAIT_POLL_INTERVAL = 0.1

# 审计 logger（刷新事件入审计，§14.6；与 middleware 的 per-request 审计同一 logger，
# action=oauth_refresh 区分，request_id 复用当前请求以便关联）
audit_log = logging.getLogger("agent_proxy.audit")

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


def cred_cache_key(mapping_id: str, user_id: int) -> str:
    return f"ap:cred:{mapping_id}:{user_id}"


def refresh_lock_key(mapping_id: str, user_id: int) -> str:
    return f"ap:lock:refresh:{mapping_id}:{user_id}"


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


async def _cache_get(r, mapping_id: str, user_id: int) -> dict | None:
    try:
        raw = await r.get(cred_cache_key(mapping_id, user_id))
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


async def _cache_put(r, mapping_id: str, user_id: int, cred: dict, ttl: int = 60) -> None:
    try:
        await r.set(cred_cache_key(mapping_id, user_id),
                    json.dumps(cred, ensure_ascii=False), ex=ttl)
    except Exception as exc:
        log.warning("cred 缓存写入失败: %s", exc)


async def invalidate_credential(r, mapping_id: str, user_id: int) -> None:
    """绑定 / 解绑 / 刷新后失效 cred 缓存（§5.3：绑定 / 解绑 / 刷新时失效）。"""
    try:
        await r.delete(cred_cache_key(mapping_id, user_id))
    except Exception as exc:
        log.warning("cred 缓存删除失败: %s", exc)


async def load_credential(session: AsyncSession, r, mapping_id: str, user_id: int) -> dict | None:
    """缓存优先的凭证读取（密文形态，§5.3 cache-aside）；未绑定返回 None。"""
    cached = await _cache_get(r, mapping_id, user_id)
    if cached is not None:
        return cached
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.user_id == user_id)
    )).scalar_one_or_none()
    if row is None:
        return None
    cred = _row_to_cred(row)
    await _cache_put(r, mapping_id, user_id, cred)
    return cred


async def save_credential(session: AsyncSession, r, mapping_id: str, user_id: int, *,
                          access_token_ct: str, refresh_token_ct: str | None,
                          expires_at: datetime | None, scope: str | None,
                          master_key: str) -> None:
    """uk(mapping_id, user_id) upsert：重复授权覆盖旧凭证并复位 active（§14.4 状态机
    invalid → 重新授权 → bound）。密文由调用方以 encrypt_text 产出后传入。

    并发竞态：两个请求同 (mapping_id, user_id) 同时授权，双方 SELECT 均无行 → 双
    INSERT → 一侧 commit 撞 uk IntegrityError（若不捕获会 500）——回滚后按 uk
    重读重试为 UPDATE（覆盖并发方已提交行），达成真原子 upsert 语义。"""
    new_values = {"access_token": access_token_ct, "refresh_token": refresh_token_ct,
                  "expires_at": expires_at, "scope": scope, "status": "active"}
    for attempt in range(2):
        row = (await session.execute(
            select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                          OAuthCredential.user_id == user_id)
        )).scalar_one_or_none()
        if row is not None:
            for k, v in new_values.items():
                setattr(row, k, v)
            await session.commit()
            break
        row = OAuthCredential(mapping_id=mapping_id, user_id=user_id, **new_values)
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
    await invalidate_credential(r, mapping_id, user_id)


async def mark_credential_invalid(session: AsyncSession, r, mapping_id: str,
                                  user_id: int) -> None:
    """AS 业务性拒绝刷新后标记 invalid（§14.4：invalid 后调用一律 401，页面引导
    重新授权）；瞬时失败不走本函数——凭证原状保留（评审 Important 2 分级）。"""
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.user_id == user_id)
    )).scalar_one_or_none()
    if row is not None and row.status != "invalid":
        row.status = "invalid"
        await session.commit()
    await invalidate_credential(r, mapping_id, user_id)


async def delete_credential(session: AsyncSession, r, mapping_id: str, user_id: int) -> bool:
    """解绑：删除本地凭证（revoke 由 api 层在删除前取 token 后 best-effort 调用）。
    行已不存在（重复解绑/并发删除）时同样失效 cred 缓存——过期缓存比消失的行
    更危险（缓存残留 → 已解绑用户仍被注入旧 token）。"""
    row = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                      OAuthCredential.user_id == user_id)
    )).scalar_one_or_none()
    if row is None:
        await invalidate_credential(r, mapping_id, user_id)
        return False
    await session.delete(row)
    await session.commit()
    await invalidate_credential(r, mapping_id, user_id)
    return True


# ---------- 授权进行中索引（authorizing 态判定，设计 §14.4 / §5.3 最小增量键） ----------


def authz_index_key(mapping_id: str, user_id: int) -> str:
    return f"ap:oauth:authz:{mapping_id}:{user_id}"


async def set_authz_index(r, mapping_id: str, user_id: int, state: str, ttl: int) -> None:
    """authorize 写入（state 存续期索引，binding 查询据此判 authorizing）；
    callback 成功 / 解绑时删除。"""
    try:
        await r.set(authz_index_key(mapping_id, user_id), state, ex=ttl)
    except Exception as exc:
        log.warning("authz 索引写入失败: %s", exc)


async def get_authz_index(r, mapping_id: str, user_id: int) -> str | None:
    try:
        return await r.get(authz_index_key(mapping_id, user_id))
    except Exception as exc:
        log.warning("authz 索引读取失败: %s", exc)
        return None


async def drop_authz_index(r, mapping_id: str, user_id: int) -> None:
    try:
        await r.delete(authz_index_key(mapping_id, user_id))
    except Exception as exc:
        log.warning("authz 索引删除失败: %s", exc)


async def get_binding_status(session: AsyncSession, r, mapping_id: str, user_id: int) -> str:
    """绑定状态机（§14.4）：unbound → authorizing（state 存续期间）→ bound(active)
    → invalid（refresh 失败 / 提供方吊销）。判定顺序：凭证行 → authz 索引 → unbound。"""
    cred = await load_credential(session, r, mapping_id, user_id)
    if cred is not None:
        return "bound" if cred.get("status") == "active" else "invalid"
    if await get_authz_index(r, mapping_id, user_id) is not None:
        return "authorizing"
    return "unbound"


# ---------- 调用时凭证获取与刷新（§14.5） ----------


def binding_required(mapping_id: str) -> AppError:
    """§10：401 OAUTH_BINDING_REQUIRED，body 附授权引导信息。"""
    return AppError(401, "OAUTH_BINDING_REQUIRED",
                    f"未完成 OAuth 授权绑定或凭证已失效：请先 POST "
                    f"/api/v1/builtin-mappings/{mapping_id}/authorize 完成授权后重试")


def _parse_expires(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


async def get_callable_credential(session: AsyncSession, r, app_state,
                                  mapping_data: dict, user_id: int, master_key: str,
                                  request_id: str = "") -> str:
    """调用时凭证获取（§14.5）：无 / invalid → 401 OAUTH_BINDING_REQUIRED；
    expires_at - 60s 内 → 刷新（Redis 锁防并发）→ 返回新 access；刷新失败分级：
    AS 业务拒绝（400/401/403）→ status=invalid → 401 引导重新授权；瞬时失败
    （网络 / discovery / 5xx / 响应畸形）→ 凭证原状保留 → 本请求 401、下轮重试
    （评审 Important 2）。proxy 注入与 builtin test 共用本入口。"""
    mapping_id = mapping_data["mapping_id"]
    cred = await load_credential(session, r, mapping_id, user_id)
    if cred is None or cred.get("status") != "active":
        raise binding_required(mapping_id)
    if not is_expired(_parse_expires(cred.get("expires_at"))):
        try:
            return decrypt_text(cred["access_token"], master_key)
        except AppError as exc:
            # 密文不可解（MASTER_KEY 变更 / 行损坏）→ 401 重授权引导而非 500
            # （评审 Minor c；fail-closed 语义不变，仅错误面收敛到 OAuth 引导）
            raise binding_required(mapping_id) from exc
    refreshed = await refresh_credential(session, r, app_state, mapping_data, user_id,
                                         master_key, request_id)
    if refreshed is None:
        raise binding_required(mapping_id)
    return refreshed


# 刷新锁释放属主校验（终审遗留 1）：Lua compare-and-delete——锁值 == 持锁 token
# 才删。无条件 DEL 的缺陷：持锁超过 30s TTL（慢 token 端点）后锁已过期，继任者
# 可重取新锁，原持有者完成刷新后的无条件 DEL 会删掉继任者的锁 → 第三方并发刷新
# 失防（重复刷新）。Redis 3.0 支持 EVAL（2.6+），脚本原子性由 Redis 单线程保证。
_RELEASE_LOCK_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


async def release_refresh_lock(r, mapping_id: str, user_id: int, token: str) -> bool:
    """属主校验释放刷新锁：仅当锁值仍为 token（获取锁时写入的 request_id）才删除；
    锁已过期且被继任者重取（值不同）→ 不动锁返回 False（继任者的锁由继任者自己
    的 finally 释放）。脚本执行失败仅 WARN——锁 30s TTL 兜底自愈。"""
    try:
        return bool(await r.eval(_RELEASE_LOCK_LUA, 1,
                                 refresh_lock_key(mapping_id, user_id), token))
    except Exception as exc:
        log.warning("刷新锁释放失败（TTL 自愈兜底）: %s", exc)
        return False


async def refresh_credential(session: AsyncSession, r, app_state, mapping_data: dict,
                             user_id: int, master_key: str,
                             request_id: str = "") -> str | None:
    """刷新互斥（§14.5）：抢锁成功者执行 refresh_token 换新（落库 + 失效缓存）；
    未抢到锁者轮询 cred（上限 8s）等他人刷新结果。锁 ap:lock:refresh:{mapping}:{user_id}
    SET NX EX 30（§5.3；Redis 3.0 支持 SET NX EX），锁值 = request_id，释放经
    Lua compare-and-delete 属主校验（防超 TTL 后误删继任者新锁）。
    返回新 access 或 None（→401）。"""
    mapping_id = mapping_data["mapping_id"]
    lock_key = refresh_lock_key(mapping_id, user_id)
    # 无 request_id 的调用方回退随机值（评审 Minor 2）：常量回退会让多个匿名持有者
    # 共享同一锁值 → 一方释放误删他方锁，部分击穿属主校验
    lock_token = request_id or uuid.uuid4().hex
    try:
        acquired = await r.set(lock_key, lock_token, nx=True,
                               ex=REFRESH_LOCK_TTL)
    except Exception as exc:
        log.warning("刷新锁获取失败（按未抢到处理）: %s", exc)
        acquired = None
    if not acquired:
        return await _wait_for_others_refresh(session, r, mapping_id, user_id, master_key)
    try:
        return await _do_refresh(session, r, app_state, mapping_data, user_id,
                                 master_key, request_id)
    finally:
        await release_refresh_lock(r, mapping_id, user_id, lock_token)


async def _wait_for_others_refresh(session: AsyncSession, r, mapping_id: str,
                                   user_id: int, master_key: str) -> str | None:
    """锁被他人持有时轮询 cred：拿到非过期的 active token 即用；他人刷新失败
    （invalid）→ None；等待超时 → None（该请求 401，下一请求重试刷新）。"""
    deadline = time.monotonic() + REFRESH_WAIT_SECONDS
    while time.monotonic() < deadline:
        await asyncio.sleep(_WAIT_POLL_INTERVAL)
        # 结束本 session 的 REPEATABLE READ 快照（首个 query——load_mapping——开的
        # 事务）：不回滚则后续 SELECT 永远读到请求起点前的旧凭证，等不到他人
        # 已提交的刷新结果（实测 6 并发 5 路轮询超时 401）。等待路径无未决写，
        # rollback 纯粹是快照复位；下一轮 execute 自动开新事务新快照。
        await session.rollback()
        cred = await load_credential(session, r, mapping_id, user_id)
        if cred is not None and cred.get("status") != "active":
            return None
        if cred is not None and not is_expired(_parse_expires(cred.get("expires_at"))):
            return decrypt_text(cred["access_token"], master_key)
    return None


class _RefreshRejected(Exception):
    """AS 业务性拒绝（refresh_token 已失效/客户端认证失败）——凭证确定性不可用，
    标 invalid 引导重新授权（评审 Important 2 分级之一）。"""


class _RefreshFailed(Exception):
    """非破坏性失败（网络 / discovery / token 端点 5xx·429 / 响应畸形）——凭证
    保持原状，本请求 401，下一请求原样重试（评审 Important 2 分级之二：
    well-known 超时 / 5xx 抖动属提供方瞬时故障，标 invalid 会强迫用户重新授权）。"""


async def _do_refresh(session: AsyncSession, r, app_state, mapping_data: dict,
                      user_id: int, master_key: str, request_id: str = "") -> str | None:
    """持锁刷新：refresh_token 换新 → upsert 落库 + 失效缓存 + metrics/审计。
    失败分级（评审 Important 2）：AS 业务拒绝（400/401/403）→ invalid +
    metrics {action="fail"}；网络/discovery/5xx/响应畸形 → 凭证原状保留
    （不 destroy）+ metrics {action="transient"}（终审遗留 5：与业务拒绝分拆，
    避免混计误导告警阈值）——两态均审计 ok=false → 本请求 401。"""
    from .client import build_token_request, load_client_row, _row_to_client
    from .discovery import DiscoveryError, discover_authorization_server, upstream_origin

    mapping_id = mapping_data["mapping_id"]
    cred = await load_credential(session, r, mapping_id, user_id)
    if cred is None or not cred.get("refresh_token"):
        # 无 refresh_token：凭证注定无法续期 → invalid（页面引导重新授权）
        await mark_credential_invalid(session, r, mapping_id, user_id)
        metrics.oauth_actions_total.labels(action="fail").inc()
        return None
    try:
        # client 行解密入 try（评审 Critical）：manual 行 client_secret 密文不可解
        # （MASTER_KEY 变更 / 行损坏）+ 凭证已过期（刷新分支不先解 access）时，
        # 原在 try 外解密 → AppError(500) 穿透，违背 get_callable_credential
        # 「密文不可解 → 401 引导而非 500」底线。按不清行处理：401 引导，
        # admin 重新 PUT client / 重配 MASTER_KEY 后原凭证仍可用。
        row = await load_client_row(session, mapping_id)
        client = _row_to_client(row, master_key) if row is not None else None
        token_url = client.get("token_url") if client else None
        if not token_url:
            # dcr 行两列留空（§5.3）：刷新时实时 discovery 取 token 端点
            meta = await discover_authorization_server(
                app_state.http_client, upstream_origin(mapping_data["upstream_url"]))
            token_url = meta["token_endpoint"]
        headers, form = build_token_request(
            client["token_auth"] if client else "client_secret_post",
            client_id=client["client_id"] if client else "",
            client_secret=client.get("client_secret") if client else None,
            extra={"grant_type": "refresh_token",
                   "refresh_token": decrypt_text(cred["refresh_token"], master_key)})
        resp = await app_state.http_client.post(token_url, data=form,
                                                headers=headers, timeout=15.0)
        if resp.status_code in (400, 401, 403):
            # AS 明确拒绝：invalid_grant / invalid_client——refresh_token 已不可用
            raise _RefreshRejected(f"status={resp.status_code}")
        if resp.status_code != 200:
            # 404/429/5xx 等：端点瞬时不可用或限流——凭证保持原状，下轮重试
            raise _RefreshFailed(f"status={resp.status_code}")
        tokens = resp.json()
        if not isinstance(tokens, dict):
            # 200 但响应非 JSON object（数组/字符串）——提供方契约异常，不破坏凭证
            raise _RefreshFailed("响应非 JSON object")
        access = tokens.get("access_token")
        if not access:
            raise _RefreshFailed("响应缺少 access_token")
    except _RefreshRejected as exc:
        await mark_credential_invalid(session, r, mapping_id, user_id)
        metrics.oauth_actions_total.labels(action="fail").inc()
        # 日志只记 mapping/user_id/异常类型——token 不入任何日志（§14.6）
        log.warning("OAuth 刷新被 AS 拒绝 (%s/%s): %s", mapping_id, user_id, type(exc).__name__)
        _audit_refresh(request_id, mapping_id, user_id, ok=False)
        return None
    except (httpx.HTTPError, ValueError, DiscoveryError, AppError,
            _RefreshFailed) as exc:
        # 非破坏性：凭证原状保留（AppError=密文不可解/加密配置异常——凭证行或
        # client 行，同不清行——配置恢复后原凭证仍可用），本请求经 binding_required
        # 401 重授权引导；metrics 计 transient（终审遗留 5：瞬时失败与业务拒绝分拆）
        metrics.oauth_actions_total.labels(action="transient").inc()
        log.warning("OAuth 刷新瞬时失败 (%s/%s): %s", mapping_id, user_id, type(exc).__name__)
        _audit_refresh(request_id, mapping_id, user_id, ok=False)
        return None
    expires_at = expires_at_from(tokens.get("expires_in"))
    if tokens.get("refresh_token"):
        refresh_ct = encrypt_text(tokens["refresh_token"], master_key)   # AS 轮换则存新值
    else:
        refresh_ct = cred.get("refresh_token")           # 未轮换：保留原密文
    await save_credential(session, r, mapping_id, user_id,
                          access_token_ct=encrypt_text(access, master_key),
                          refresh_token_ct=refresh_ct, expires_at=expires_at,
                          scope=(tokens.get("scope") or cred.get("scope")),
                          master_key=master_key)
    metrics.oauth_actions_total.labels(action="refresh").inc()
    _audit_refresh(request_id, mapping_id, user_id, ok=True)
    return access


def _audit_refresh(request_id: str, mapping_id: str, user_id: int, ok: bool) -> None:
    """刷新入审计日志（§14.6）：复用当前请求 request_id 与中间件请求行关联；
    action=oauth_refresh 区分（测试按 action 过滤；无请求上下文时 request_id 空串）。"""
    audit_log.info(json.dumps({
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
        "request_id": request_id, "user_id": user_id, "user_name": "",
        "action": "oauth_refresh", "mapping_id": mapping_id, "method": "", "path": "",
        "status": 200 if ok else 401, "duration_ms": 0, "bytes_in": 0, "bytes_out": 0,
        "client_ip": "",
    }, ensure_ascii=False))
