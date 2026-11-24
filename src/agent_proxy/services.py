"""应用服务层：映射 CRUD、cache-aside 加载、归属校验。管理、回显、转发共用。"""
from __future__ import annotations

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
from .oauth.credential import invalidate_credential
from .ssrf import async_validate_upstream_url

log = logging.getLogger("agent_proxy")


def row_to_dict(row: ProxyMapping) -> dict:
    return {
        "id": row.id, "mapping_id": row.mapping_id, "owner_uid": row.owner_uid,
        "name": row.name, "type": row.type, "visibility": row.visibility,
        "auth_mode": row.auth_mode, "upstream_url": row.upstream_url,
        "upstream_headers": row.upstream_headers or {}, "test_request": row.test_request,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def build_proxy_url(settings: Settings, mapping_id: str, upstream_url: str, type_: str) -> str:
    """proxy_url = EXTERNAL_BASE/p/{id}[ + mcp 端点路径]。"""
    prefix = f"{settings.external_base.rstrip('/')}/p/{mapping_id}"
    if type_ == "mcp":
        prefix += urlparse(upstream_url).path.rstrip("/")
    return prefix


async def load_mapping(session: AsyncSession, r, mapping_id: str, ttl: int) -> dict | None:
    """cache-aside：Redis → MySQL 回填。返回记录 dict 或 None。"""
    cached = await cache.get_mapping(r, mapping_id)
    if cached is not None:
        return cached
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id)
    )).scalar_one_or_none()
    if row is None:
        return None
    data = row_to_dict(row)
    await cache.set_mapping(r, mapping_id, data, ttl)
    return data


async def get_owned(session: AsyncSession, r, mapping_id: str, uid: str, ttl: int,
                    admin_override: bool = False) -> dict | None:
    """加载并校验归属；非注册者返回 None（404 隐藏存在性）。
    M6（§14.2）：admin_override 时 public 映射对任意 admin 可见（详情/resolve/test）。"""
    data = await load_mapping(session, r, mapping_id, ttl)
    if data is None:
        return None
    if data["owner_uid"] == uid:
        return data
    if admin_override and data["visibility"] == "public":
        return data
    return None


async def create_mapping(session: AsyncSession, r, settings: Settings, owner_uid: str, *,
                         type_: str, name: str | None, visibility: str,
                         upstream_url: str, headers: dict[str, str],
                         test_request: dict | None,
                         auth_mode: str = "static") -> ProxyMapping:
    placeholder.validate_headers(headers)
    # M6（§14.2）：auth_mode=oauth 仅允许 public（public 本身的 admin 限制由 api 层 403 先判）
    if auth_mode == "oauth" and visibility != "public":
        raise ValueError("auth_mode=oauth 仅允许 public 映射")
    url = await async_validate_upstream_url(upstream_url, settings.ssrf_allow_private)
    for attempt in range(5):
        mapping_id = mid_module.new_mapping_id()
        row = ProxyMapping(mapping_id=mapping_id, owner_uid=owner_uid, name=name,
                           type=type_, visibility=visibility, auth_mode=auth_mode,
                           upstream_url=url, upstream_headers=headers,
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


async def list_mappings(session: AsyncSession, owner_uid: str, limit: int, offset: int) -> list[ProxyMapping]:
    result = await session.execute(
        select(ProxyMapping).where(ProxyMapping.owner_uid == owner_uid)
        .order_by(ProxyMapping.id.desc()).offset(offset).limit(limit))
    return list(result.scalars().all())


async def update_mapping(session: AsyncSession, r, settings: Settings, mapping_id: str,
                         owner_uid: str, *, admin_override: bool = False,
                         **patch: Any) -> dict | None:
    """更新；返回 row_to_dict 或 None（不存在/无权限）。
    M6（§14.2）：admin_override 时任意 admin 可改 public 映射；
    auth_mode 变更后仍须满足 oauth⇒public（违规 ValueError → api 层 400）。"""
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id)
    )).scalar_one_or_none()
    if row is None:
        return None
    if row.owner_uid != owner_uid and not (admin_override and row.visibility == "public"):
        return None
    new_visibility = patch.get("visibility") or row.visibility
    new_auth_mode = patch.get("auth_mode") or row.auth_mode
    if new_auth_mode == "oauth" and new_visibility != "public":
        raise ValueError("auth_mode=oauth 仅允许 public 映射")
    if patch.get("headers") is not None:
        placeholder.validate_headers(patch["headers"])
        row.upstream_headers = patch["headers"]
    if patch.get("upstream_url"):
        row.upstream_url = await async_validate_upstream_url(
            patch["upstream_url"], settings.ssrf_allow_private)
    for field in ("name", "visibility", "test_request", "status", "auth_mode"):
        if patch.get(field) is not None:
            setattr(row, field, patch[field])
    await session.commit()
    await session.refresh(row)  # 回填 server 端 updated_at，避免 row_to_dict 触发异步下不支持的懒加载
    await cache.invalidate(r, mapping_id)
    return row_to_dict(row)


async def delete_mapping(session: AsyncSession, r, mapping_id: str, owner_uid: str,
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
    # 先按行内 uid 失效各自 cred 缓存，再同批删行（避免删行后无法反查 uid）。
    client_rows = (await session.execute(
        select(OAuthClient).where(OAuthClient.mapping_id == mapping_id))).scalars().all()
    cred_rows = (await session.execute(
        select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id)
    )).scalars().all()
    for cred_row in cred_rows:
        await invalidate_credential(r, mapping_id, cred_row.uid)
    for client_row in client_rows:
        await session.delete(client_row)
    for cred_row in cred_rows:
        await session.delete(cred_row)
    await session.delete(row)
    await session.commit()
    await cache.invalidate(r, mapping_id)
    return True
