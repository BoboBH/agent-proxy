"""Redis cache-aside（Task 9 填充读写逻辑）。"""
from __future__ import annotations

import redis.asyncio as redis_async


def build_redis(redis_url: str):
    return redis_async.from_url(redis_url, socket_timeout=5)
