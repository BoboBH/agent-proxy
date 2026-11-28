"""按映射并发上限（设计 v4.2）：慢上游隔离。

每个 mapping_id 一把 asyncio.Semaphore（进程内，懒创建）：/p/ 转发在发起上游
调用前先取映射闸门，映射内并发达上限后，**该映射自己的**超额请求等待
`timeout` 秒仍拿不到 → 503 PROXY_BUSY（错误码沿用全局池语义，message 标明
按映射）——其他映射完全不受影响（全局连接池不再被单一慢映射占满）。

闸门生命周期与上游连接严格对齐：
- 代理 handler 取得 Guard 后交给转发管线；
- 管线在「上游连接真正关闭」的 finally（响应流结束 / 客户端断开 / 错误路径）
  调 Guard.release()——幂等，流式期间持续持有（含 SSE 长连接）。

进程内注册表：上限值由 MAPPING_MAX_CONCURRENCY 全局配置，映射重启后重建
（进程重启即重置，不做持久化）。
"""
from __future__ import annotations

import asyncio

from app.services.errors import AppError

_semaphores: dict[str, asyncio.Semaphore] = {}
# 在途并发计数（管理页「实时负载」视图）：acquire_guard 成功 +1、Guard.release -1；
# 进程内视图（多实例部署时各实例独立，文档注明）
_inflight: dict[str, int] = {}


def semaphore_for(mapping_id: str, limit: int) -> asyncio.Semaphore:
    """取映射专属信号量（懒创建；同映射同进程复用同一把）。"""
    sem = _semaphores.get(mapping_id)
    if sem is None:
        sem = asyncio.Semaphore(limit)
        _semaphores[mapping_id] = sem
    return sem


def track_begin(mapping_id: str) -> None:
    """在途 +1（代理转发开始）。"""
    _inflight[mapping_id] = _inflight.get(mapping_id, 0) + 1


def track_end(mapping_id: str) -> None:
    """在途 -1（响应流结束 / 客户端断开 / 错误路径——调用方 finally 保证配对）。"""
    n = _inflight.get(mapping_id)
    if n is None:
        return
    if n <= 1:
        _inflight.pop(mapping_id, None)
    else:
        _inflight[mapping_id] = n - 1


def inflight_all() -> dict[str, int]:
    """在途并发快照 {mapping_id: count}（调用方副本，防遍历期间变更）。"""
    return dict(_inflight)


class Guard:
    """已取得的映射并发额度；release() 幂等（管线多点释放安全）。"""

    __slots__ = ("_sem", "_mapping_id", "_released")

    def __init__(self, sem: asyncio.Semaphore, mapping_id: str) -> None:
        self._sem = sem
        self._mapping_id = mapping_id
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._sem.release()
            track_end(self._mapping_id)


async def acquire_guard(mapping_id: str, limit: int,
                        timeout: float) -> Guard:
    """取映射并发额度（在途 +1）；等待超过 timeout 仍拿不到 → 503 PROXY_BUSY。"""
    sem = semaphore_for(mapping_id, limit)
    try:
        await asyncio.wait_for(sem.acquire(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise AppError(503, "PROXY_BUSY",
                       f"该映射并发已达上限（{limit}），请稍后重试") from exc
    track_begin(mapping_id)
    return Guard(sem, mapping_id)
