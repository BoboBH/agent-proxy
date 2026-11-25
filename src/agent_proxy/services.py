"""应用服务层：映射 CRUD、cache-aside 加载、归属校验。管理、回显、转发共用。

敏感面（收尾批次强制加密）：upstream_headers 落库/Redis 缓存一律 Fernet(MASTER_KEY)
密文（复用 oauth.credential 的 encrypt_text/decrypt_text，SHA256(MASTER_KEY) 派生）；
读取方（转发/详情/test）经 load_mapping 解密为明文 dict。损坏密文 fail-closed：
解密失败 WARN + 按映射不可用（None → 404 语义），绝不返回部分明文。
owner_uid / OAuth user_id 为 int（收尾批次整数化，列 BIGINT，整链 int 比较）。"""
from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from . import cache, mapping_id as mid_module, placeholder
from .config import Settings
from .errors import AppError
from .models import OAuthClient, OAuthCredential, ProxyMapping
from .oauth.credential import decrypt_text, encrypt_text, invalidate_credential
from .ssrf import async_validate_upstream_url

log = logging.getLogger("agent_proxy")


def encrypt_headers(headers: dict[str, str], master_key: str) -> str:
    """明文 headers dict → Fernet 密文字符串（落库 / Redis 缓存统一形态）。"""
    return encrypt_text(json.dumps(headers, ensure_ascii=False), master_key)


def plain_headers(stored_ct: str | None, master_key: str) -> dict[str, str]:
    """密文 → 明文 dict；损坏密文（不可解 / 非 JSON object / 非 str 形态——如迁移前
    旧明文缓存残留）抛 AppError——由调用方按 fail-closed 语义处理（读取路径转
    「映射不可用」，不返回部分明文）。"""
    if stored_ct is None or stored_ct == "":
        return {}
    if not isinstance(stored_ct, str):
        # 旧明文缓存残留（迁移窗口）/畸形形态：同 fail-closed，绝不当作明文使用
        raise AppError(500, "INTERNAL_ERROR", "映射 headers 存储形态非法（非密文串）")
    try:
        raw = decrypt_text(stored_ct, master_key)
    except AppError as exc:
        # decrypt_text 文案是 OAuth 凭证语境（Minor 评审）：headers 路径重抛带上下文
        raise AppError(500, "INTERNAL_ERROR",
                       "映射 headers 解密失败（MASTER_KEY 变更？请恢复密钥或联系管理员）") from exc
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise AppError(500, "INTERNAL_ERROR", "映射 headers 密文载荷非法") from exc
    if not isinstance(data, dict):
        raise AppError(500, "INTERNAL_ERROR", "映射 headers 密文载荷非法")
    return data


def row_to_dict(row: ProxyMapping, master_key: str) -> dict:
    """行 → dict（明文 headers 形态，管理输出/详情语义；缓存形态见 _row_cache_dict）。
    密文损坏时抛 AppError（详情/resolve 经 load_mapping 已 fail-closed 404；PUT 触及
    headers 的守卫转 409 CREDENTIAL_CORRUPT，见 update_mapping）。"""
    return _row_dict(row, master_key, corrupt_ok=False)


def row_to_dict_degraded_headers(row: ProxyMapping, master_key: str) -> dict:
    """PUT 未触及 headers 的回显专用：旧密文损坏**不阻塞更新生效**（停用/改名等
    照常），占位符键名不可得 → 降级空表 + WARN（不产生明文，真实值读取路径仍 404）。"""
    return _row_dict(row, master_key, corrupt_ok=True)


def _row_dict(row: ProxyMapping, master_key: str, *, corrupt_ok: bool) -> dict:
    headers: dict[str, str] = {}
    if row.upstream_headers:
        try:
            headers = plain_headers(row.upstream_headers, master_key)
        except AppError as exc:
            if not corrupt_ok:
                raise
            # 降级回显路径（row_to_dict_degraded_headers）：docstring 承诺「降级空表
            # + WARN」——占位符键名不可得且不产出明文，落 WARN 供运维感知损坏面
            log.warning("映射 headers 密文损坏，回显降级空表（真实值读取仍 fail-closed）: "
                        "mapping_id=%s err=%s", row.mapping_id, type(exc).__name__)
            headers = {}
    return {
        "id": row.id, "mapping_id": row.mapping_id, "owner_uid": row.owner_uid,
        "name": row.name, "type": row.type, "visibility": row.visibility,
        "auth_mode": row.auth_mode, "upstream_url": row.upstream_url,
        "upstream_headers": headers,
        "test_request": row.test_request,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _row_cache_dict(row: ProxyMapping) -> dict:
    """行 → dict（密文缓存形态）：headers 保持密文字符串原样（Redis 侧不落明文），
    其余字段与 row_to_dict 一致（owner_uid int 由 ORM 映射）。"""
    return {
        "id": row.id, "mapping_id": row.mapping_id, "owner_uid": row.owner_uid,
        "name": row.name, "type": row.type, "visibility": row.visibility,
        "auth_mode": row.auth_mode, "upstream_url": row.upstream_url,
        "upstream_headers": row.upstream_headers or "", "test_request": row.test_request,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _decrypt_or_none(data: dict, master_key: str) -> dict | None:
    """缓存/回源形态（密文 headers）→ 明文形态；解密失败 WARN + None（fail-closed，
    调用方 404「映射不存在」语义；trace/audit 侧字段不变）。"""
    try:
        return {**data, "upstream_headers": plain_headers(data["upstream_headers"], master_key)}
    except AppError as exc:
        log.warning("映射 headers 解密失败，按映射不可用处理: mapping_id=%s err=%s",
                    data.get("mapping_id"), type(exc).__name__)
        return None


def build_proxy_url(settings: Settings, mapping_id: str, upstream_url: str, type_: str) -> str:
    """proxy_url = EXTERNAL_BASE/p/{id}[ + mcp 端点路径]。"""
    prefix = f"{settings.external_base.rstrip('/')}/p/{mapping_id}"
    if type_ == "mcp":
        prefix += urlparse(upstream_url).path.rstrip("/")
    return prefix


async def load_mapping(session: AsyncSession, r, mapping_id: str, ttl: int,
                       master_key: str) -> dict | None:
    """cache-aside：Redis → MySQL 回填。Redis 缓存存密文形态（headers 密文字符串，
    与 ap:cred:* 先例一致）；返回给调用方的恒为解密后的明文 dict 或 None。
    损坏密文（缓存命中或回源）→ WARN + None（视为映射不可用，404 语义），且：
    - 缓存侧坏键（旧明文残留/损坏密文）即时失效 → 下一请求回源自愈，不粘性 404；
    - 回源解密失败的行**不落缓存**（坏行不扩散；修复后自动恢复）。"""
    cached = await cache.get_mapping(r, mapping_id)
    if cached is not None:
        plain = _decrypt_or_none(cached, master_key)
        if plain is None:
            await cache.invalidate(r, mapping_id)
        return plain
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id)
    )).scalar_one_or_none()
    if row is None:
        return None
    data = _row_cache_dict(row)
    plain = _decrypt_or_none(data, master_key)
    if plain is None:
        return None
    await cache.set_mapping(r, mapping_id, data, ttl)
    return plain


async def get_owned(session: AsyncSession, r, mapping_id: str, user_id: int, ttl: int,
                    master_key: str, admin_override: bool = False) -> dict | None:
    """加载并校验归属；非注册者返回 None（404 隐藏存在性）。
    M6（§14.2）：admin_override 时 public 映射对任意 admin 可见（详情/resolve/test）。"""
    data = await load_mapping(session, r, mapping_id, ttl, master_key)
    if data is None:
        return None
    if data["owner_uid"] == user_id:
        return data
    if admin_override and data["visibility"] == "public":
        return data
    return None


async def create_mapping(session: AsyncSession, r, settings: Settings, owner_uid: int, *,
                         type_: str, name: str | None, visibility: str,
                         upstream_url: str, headers: dict[str, str],
                         test_request: dict | None,
                         auth_mode: str = "static") -> ProxyMapping:
    placeholder.validate_headers(headers)
    # M6（§14.2）：auth_mode=oauth 仅允许 public（public 本身的 admin 限制由 api 层 403 先判）
    if auth_mode == "oauth" and visibility != "public":
        raise ValueError("auth_mode=oauth 仅允许 public 映射")
    url = await async_validate_upstream_url(upstream_url, settings.ssrf_allow_private)
    headers_ct = encrypt_headers(headers, settings.master_key)  # 强制加密（无密钥 fail-closed 500）
    for attempt in range(5):
        mapping_id = mid_module.new_mapping_id()
        row = ProxyMapping(mapping_id=mapping_id, owner_uid=owner_uid, name=name,
                           type=type_, visibility=visibility, auth_mode=auth_mode,
                           upstream_url=url, upstream_headers=headers_ct,
                           test_request=test_request, status="active")
        session.add(row)
        try:
            await session.commit()
            break
        except IntegrityError:
            await session.rollback()
            if attempt == 4:
                raise AppError(500, "INTERNAL_ERROR", "mapping_id 生成冲突，请重试")
    await session.refresh(row)  # 回填 server_default（created_at/updated_at），避免脱管后过期属性报错
    await cache.invalidate(r, row.mapping_id)
    return row


async def list_mappings(session: AsyncSession, owner_uid: int, limit: int,
                        offset: int) -> list[ProxyMapping]:
    result = await session.execute(
        select(ProxyMapping).where(ProxyMapping.owner_uid == owner_uid)
        .order_by(ProxyMapping.id.desc()).offset(offset).limit(limit))
    return list(result.scalars().all())


async def update_mapping(session: AsyncSession, r, settings: Settings, mapping_id: str,
                         owner_uid: int, *, admin_override: bool = False,
                         **patch: Any) -> dict | None:
    """更新；返回 row_to_dict（明文 headers）或 None（不存在/无权限）。
    M6（§14.2）：admin_override 时任意 admin 可改 public 映射；
    auth_mode 变更后仍须满足 oauth⇒public（违规 ValueError → api 层 400）。

    损坏密文语义一致性（评审 Important 1）：旧 headers 密文不可解时——
    - patch 未触及 headers（status/name/... 停用类更新）→ 照常更新生效，回显占位符
      降级空表 + WARN（不阻塞应急处置，也绝不产出明文）；
    - patch 触及 headers → 更新前显式 409 CREDENTIAL_CORRUPT（覆盖即无声销毁损坏
      现场，owner/admin 须知悉旧凭据已不可恢复；修复路径=恢复密钥或 DELETE 重注册）。"""
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id)
    )).scalar_one_or_none()
    if row is None:
        return None
    if row.owner_uid != owner_uid and not (admin_override and row.visibility == "public"):
        return None
    headers_patched = patch.get("headers") is not None
    new_visibility = patch.get("visibility") or row.visibility
    new_auth_mode = patch.get("auth_mode") or row.auth_mode
    if new_auth_mode == "oauth" and new_visibility != "public":
        raise ValueError("auth_mode=oauth 仅允许 public 映射")
    if headers_patched:
        placeholder.validate_headers(patch["headers"])
        if row.upstream_headers:
            try:
                plain_headers(row.upstream_headers, settings.master_key)
            except AppError as exc:
                raise AppError(409, "CREDENTIAL_CORRUPT",
                               "映射 headers 密文不可解（MASTER_KEY 变更或行损坏）："
                               "本次更新未执行；如需保留配置请先恢复 MASTER_KEY，"
                               "否则仅可 DELETE 后重新注册或联系管理员") from exc
        row.upstream_headers = encrypt_headers(patch["headers"], settings.master_key)
    if patch.get("upstream_url"):
        row.upstream_url = await async_validate_upstream_url(
            patch["upstream_url"], settings.ssrf_allow_private)
    for field in ("name", "visibility", "test_request", "status", "auth_mode"):
        if patch.get(field) is not None:
            setattr(row, field, patch[field])
    await session.commit()
    await session.refresh(row)  # 回填 server 端 updated_at，避免 row_to_dict 触发异步下不支持的懒加载
    await cache.invalidate(r, mapping_id)
    if headers_patched:
        # 新密文本请求刚写入（同 key 可解），回显必成功
        return row_to_dict(row, settings.master_key)
    return row_to_dict_degraded_headers(row, settings.master_key)


async def delete_mapping(session: AsyncSession, r, mapping_id: str, owner_uid: int,
                         admin_override: bool = False) -> bool:
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id)
    )).scalar_one_or_none()
    if row is None:
        return False
    if row.owner_uid != owner_uid and not (admin_override and row.visibility == "public"):
        return False
    # M6（§14.6）：连带清理 OAuth client/credential 行——加密 client_secret 与用户
    # token 随宿主映射删除（映射没了绑定/客户端配置即无意义，行含密文越早清越安全）；
    # 先按行内 user_id 失效各自 cred 缓存，再同批删行（避免删行后无法反查 user_id）。
    client_rows = (await session.execute(
        select(OAuthClient).where(OAuthClient.mapping_id == mapping_id))).scalars().all()
    cred_rows = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id)
    )).scalars().all()
    for cred_row in cred_rows:
        await invalidate_credential(r, mapping_id, cred_row.user_id)
    for client_row in client_rows:
        await session.delete(client_row)
    for cred_row in cred_rows:
        await session.delete(cred_row)
    await session.delete(row)
    await session.commit()
    await cache.invalidate(r, mapping_id)
    return True
