"""按映射并发上限（设计 v4.2）单测：每映射独立闸门 + 幂等释放 + 超时 503。"""
import asyncio

import pytest

from app.services.concurrency import (Guard, acquire_guard, inflight_all,
                                      semaphore_for, track_begin, track_end)
from app.services.errors import AppError


def test_semaphore_for_same_mapping_same_instance():
    s1 = semaphore_for("m1", 10)
    s2 = semaphore_for("m1", 10)
    assert s1 is s2


def test_semaphore_for_different_mapping_different_instance():
    assert semaphore_for("m1", 10) is not semaphore_for("m2", 10)


async def test_guard_release_idempotent():
    sem = asyncio.Semaphore(1)
    await sem.acquire()
    guard = Guard(sem, "uc-guard-map")
    guard.release()
    guard.release()                    # 二次释放不抛错、不超额
    assert sem._value == 1             # 仅释放一次


async def test_acquire_timeout_raises_proxy_busy():
    """映射并发达上限 → 等待超时 → 503 PROXY_BUSY（错误码沿用，message 标明按映射）。"""
    g1 = await acquire_guard("uc-timeout-map", 1, timeout=1)   # 占满该映射额度
    with pytest.raises(AppError) as excinfo:
        await acquire_guard("uc-timeout-map", 1, timeout=0.05)
    assert (excinfo.value.status, excinfo.value.code) == (503, "PROXY_BUSY")
    assert "并发" in excinfo.value.message
    g1.release()


async def test_acquire_and_release_roundtrip():
    guard = await acquire_guard("uc-roundtrip-map", 1, timeout=1)
    with pytest.raises(AppError):
        await acquire_guard("uc-roundtrip-map", 1, timeout=0.05)   # 已占满
    guard.release()
    g2 = await acquire_guard("uc-roundtrip-map", 1, timeout=1)     # 释放后可再取
    g2.release()


def test_inflight_tracking_begin_end_and_snapshot():
    """在途并发计数：begin +1 / end -1 / 归零后键消失；快照返回副本。"""
    from app.services import concurrency

    concurrency.track_begin("if-map")
    concurrency.track_begin("if-map")
    assert concurrency.inflight_all() == {"if-map": 2}
    concurrency.track_end("if-map")
    assert concurrency.inflight_all() == {"if-map": 1}
    concurrency.track_end("if-map")
    concurrency.track_end("if-map")            # 过度释放安全（键不存在即忽略）
    assert concurrency.inflight_all() == {}
    snap = concurrency.inflight_all()
    snap["x"] = 1
    assert concurrency.inflight_all() == {}    # 快照是副本
