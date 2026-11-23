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
    return json.loads(raw) if raw is not None else None


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
