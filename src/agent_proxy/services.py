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
from .models import ProxyMapping
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


async def get_owned(session: AsyncSession, r, mapping_id: str, uid: str, ttl: int) -> dict | None:
    """加载并校验归属；非注册者返回 None（404 隐藏存在性）。"""
    data = await load_mapping(session, r, mapping_id, ttl)
    if data is None or data["owner_uid"] != uid:
        return None
    return data


async def create_mapping(session: AsyncSession, r, settings: Settings, owner_uid: str, *,
                         type_: str, name: str | None, visibility: str,
                         upstream_url: str, headers: dict[str, str],
                         test_request: dict | None) -> ProxyMapping:
    placeholder.validate_headers(headers)
    url = await async_validate_upstream_url(upstream_url, settings.ssrf_allow_private)
    for attempt in range(5):
        mapping_id = mid_module.new_mapping_id()
        row = ProxyMapping(mapping_id=mapping_id, owner_uid=owner_uid, name=name,
                           type=type_, visibility=visibility, auth_mode="static",
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
                         owner_uid: str, **patch: Any) -> dict | None:
    """按 owner 定位并更新；返回 row_to_dict 或 None（不存在/非本人）。"""
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id,
                                   ProxyMapping.owner_uid == owner_uid)
    )).scalar_one_or_none()
    if row is None:
        return None
    if patch.get("headers") is not None:
        placeholder.validate_headers(patch["headers"])
        row.upstream_headers = patch["headers"]
    if patch.get("upstream_url"):
        row.upstream_url = await async_validate_upstream_url(
            patch["upstream_url"], settings.ssrf_allow_private)
    for field in ("name", "visibility", "test_request", "status"):
        if patch.get(field) is not None:
            setattr(row, field, patch[field])
    await session.commit()
    await session.refresh(row)  # 回填 server 端 updated_at，避免 row_to_dict 触发异步下不支持的懒加载
    await cache.invalidate(r, mapping_id)
    return row_to_dict(row)


async def delete_mapping(session: AsyncSession, r, mapping_id: str, owner_uid: str) -> bool:
    row = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.mapping_id == mapping_id,
                                   ProxyMapping.owner_uid == owner_uid)
    )).scalar_one_or_none()
    if row is None:
        return False
    await session.delete(row)
    await session.commit()
    await cache.invalidate(r, mapping_id)
    return True
