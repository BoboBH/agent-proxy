"""Redis cache-aside（Task 9 填充读写逻辑）。"""
from __future__ import annotations

import json
import logging

import redis.asyncio as redis_async

log = logging.getLogger("agent_proxy")


def build_redis(redis_url: str):
    return redis_async.from_url(redis_url, socket_timeout=5)


def _cache_key(mapping_id: str) -> str:
    return f"ap:mapping:{mapping_id}"


async def get_mapping(r, mapping_id: str) -> dict | None:
    try:
        raw = await r.get(_cache_key(mapping_id))
    except Exception as exc:
        log.warning("redis get 失败，回源 MySQL: %s", exc)
        return None
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError as exc:
        # 坏 JSON 视为未命中，load_mapping 回源 MySQL 回填覆盖坏键（自愈），避免粘性 500
        log.warning("缓存载荷非法 JSON，回源 MySQL 自愈: mapping_id=%s err=%s", mapping_id, exc)
        return None
    if not isinstance(data, dict):
        log.warning("缓存载荷非 dict，回源 MySQL 自愈: mapping_id=%s", mapping_id)
        return None
    return data


async def set_mapping(r, mapping_id: str, data: dict, ttl: int) -> None:
    try:
        await r.set(_cache_key(mapping_id), json.dumps(data, ensure_ascii=False), ex=ttl)
    except Exception as exc:
        log.warning("redis set 失败: %s", exc)


async def invalidate(r, mapping_id: str) -> None:
    try:
        await r.delete(_cache_key(mapping_id))
    except Exception as exc:
        log.warning("redis del 失败: %s", exc)
