"""实时负载统计（管理页「实时负载」视图，设计 §15 扩展，v4.3）。

- count_5m：Redis `INCR ap:load:{mapping_id}` + `EXPIRE 300` 滑动计数——窗口为
  「最近一次命中后的 300s」；键在 Redis（跨实例共享，多容器部署后聚合可见）；
- 记录失败不阻断转发（Redis 异常 WARN 忽略——负载视图是锦上添花，转发可用性优先）；
- 基数：键随窗口自动过期（无流量 300s 后消失），不违反 §15.2 低基数原则
  （这是独立于 /metrics 的管理面数据，不进 Prometheus）。
"""
from __future__ import annotations

import logging

log = logging.getLogger("agent_proxy")

PREFIX = "ap:load:"
WINDOW_SECONDS = 300


async def record_hit(r, mapping_id: str) -> None:
    """代理转发命中即计数（INCR + EXPIRE 一个 pipeline，单 RTT）。"""
    try:
        pipe = r.pipeline()
        pipe.incr(PREFIX + mapping_id)
        pipe.expire(PREFIX + mapping_id, WINDOW_SECONDS)
        await pipe.execute()
    except Exception as exc:
        log.warning("负载计数写入失败（不影响转发）: %s", exc)


async def snapshot_counts(r) -> dict[str, int]:
    """读取当前窗口内全部映射计数 {mapping_id: count}；Redis 异常 → 空表（空态）。"""
    out: dict[str, int] = {}
    try:
        async for key in r.scan_iter(match=PREFIX + "*", count=100):
            k = key.decode() if isinstance(key, (bytes, bytearray)) else str(key)
            raw = await r.get(key)
            if raw is None:
                continue
            try:
                out[k[len(PREFIX):]] = int(raw)
            except ValueError:
                continue
    except Exception as exc:
        log.warning("负载快照读取失败: %s", exc)
    return out
