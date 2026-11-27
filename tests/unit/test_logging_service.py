import logging
import os
import time

import pytest


@pytest.fixture(autouse=True)
def _logging_hygiene():
    """每个测试结束后复位全局日志状态，避免 _registry / logger handlers 跨测试污染。"""
    yield
    import app.services.logging_service as ls

    from app.services.logging_service import shutdown_logging

    shutdown_logging()
    for name in ("agent_proxy", "agent_proxy.audit", "agent_proxy.trace"):
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
    ls._registry.clear()
    logging.getLogger("rotate-test").handlers = []


def test_rotate_on_size(tmp_path):
    from app.services.logging_service import DailySizeRotatingHandler

    base = str(tmp_path / "t.log")
    handler = DailySizeRotatingHandler(base, max_bytes=100, keep_days=7)
    logger = logging.getLogger("rotate-test")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)  # 不设级别时 effective=WARNING，info 根本到不了 handler
    for _ in range(50):
        logger.info("x" * 20)
    files = list(tmp_path.glob("t.log.*"))
    assert len(files) >= 2, "超过 max_bytes 应已滚动出多个文件"
    assert len({f.name for f in files}) == len(files), "同日滚动生成的文件名不应重复"
    handler.close()


def test_same_day_reopen_appends_same_file(tmp_path, monkeypatch):
    """后缀按天（2026-11-27）：同日重启不另起新文件——同名文件 append 续写，
    一天的日志收敛在单个文件里（旧实现后缀精确到秒，每次重启散落一个新文件）。
    monkeypatch datetime.now 为同日相隔 5s 的两个时刻——确定性钉死旧实现
    「同日不同秒即散落新文件」的路径（直接两次实写可能落同一秒，断言会碰巧通过）。"""
    from datetime import datetime

    from app.services import logging_service as ls
    from app.services.logging_service import DailySizeRotatingHandler

    base = str(tmp_path / "t.log")
    clock = {"now": datetime(2026, 11, 27, 10, 0, 0)}

    class _FakeDatetime:
        @classmethod
        def now(cls):
            return clock["now"]

        # _cleanup 的 mtime cutoff 用，透传真实现
        fromtimestamp = datetime.fromtimestamp

    monkeypatch.setattr(ls, "datetime", _FakeDatetime)

    def _write_once(tag):
        handler = DailySizeRotatingHandler(base, max_bytes=10 * 1024 * 1024, keep_days=7)
        logger = logging.getLogger("rotate-test")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
        logger.info(tag)
        handler.close()

    _write_once("first-run")
    assert len(list(tmp_path.glob("t.log.*"))) == 1
    clock["now"] = datetime(2026, 11, 27, 10, 0, 5)  # 同日 +5s（旧实现会散落新文件）
    _write_once("second-run")
    files = list(tmp_path.glob("t.log.*"))
    assert len(files) == 1, "同日重启应复用同一日期后缀文件，而非新建"
    content = files[0].read_text(encoding="utf-8")
    assert "first-run" in content and "second-run" in content, "同日两次运行应合并续写"


def test_cleanup_expired_by_mtime(tmp_path):
    from app.services.logging_service import DailySizeRotatingHandler

    base = str(tmp_path / "t.log")
    handler = DailySizeRotatingHandler(base, max_bytes=10 * 1024 * 1024, keep_days=7)
    old = tmp_path / "t.log.20200101"  # 新格式（按天）
    old.write_text("old", encoding="utf-8")
    legacy = tmp_path / "t.log.20200101_123456"  # 旧格式（精确到秒，历史存量）同样纳入清理
    legacy.write_text("legacy", encoding="utf-8")
    past = time.time() - 8 * 86400
    os.utime(old, (past, past))
    os.utime(legacy, (past, past))
    handler._open_new()  # 触发一次清理
    assert not old.exists(), "超过保留期(7天)的旧文件应被删除"
    assert not legacy.exists(), "历史秒级后缀文件也应被正常清理"
    handler.close()


def test_setup_logging_creates_three_files(tmp_path):
    from app.services.logging_service import setup_logging

    setup_logging(str(tmp_path), "INFO")
    import app.services.logging_service as ls

    assert any("agent-proxy.log" in p for p in ls._registry)
    assert any("audit.log" in p for p in ls._registry)
    assert any("trace.log" in p for p in ls._registry)
    assert logging.getLogger("agent_proxy.audit").handlers
    assert logging.getLogger("agent_proxy.trace").handlers


def test_trace_queue_end_to_end(tmp_path):
    from app.services.logging_service import flush_trace, setup_logging

    setup_logging(str(tmp_path), "INFO")
    logging.getLogger("agent_proxy.trace").info('{"k":1}')
    flush_trace()
    content = "".join(
        p.read_text(encoding="utf-8") for p in sorted(tmp_path.glob("trace.log.*"))
    )
    assert '{"k":1}' in content, "flush 后 trace.log 应包含写入的行"


def test_setup_logging_idempotent(tmp_path):
    import app.services.logging_service as ls

    from app.services.logging_service import DailySizeRotatingHandler, setup_logging

    def own(logger):
        # pytest>=9 会给 propagate=False 的 logger 挂自己的捕获 handler，只统计本模块的
        return [
            h
            for h in logger.handlers
            if isinstance(h, (DailySizeRotatingHandler, logging.handlers.QueueHandler))
        ]

    setup_logging(str(tmp_path), "INFO")
    setup_logging(str(tmp_path), "INFO")
    assert len(own(logging.getLogger("agent_proxy"))) == 1
    assert len(own(logging.getLogger("agent_proxy.audit"))) == 1
    assert len(own(logging.getLogger("agent_proxy.trace"))) == 1
    assert len(ls._registry) == 3, "每个日志路径应只注册一个 handler"


def test_shutdown_then_setup_recovers(tmp_path):
    import app.services.logging_service as ls

    from app.services.logging_service import flush_trace, setup_logging, shutdown_logging

    setup_logging(str(tmp_path), "INFO")
    shutdown_logging()
    assert not ls._registry
    new_dir = tmp_path / "new"
    setup_logging(str(new_dir), "INFO")
    logging.getLogger("agent_proxy.trace").info('{"after":1}')
    flush_trace()
    files = list(new_dir.glob("trace.log.*"))
    assert files and any('{"after":1}' in f.read_text(encoding="utf-8") for f in files), \
        "shutdown 后重新 setup 到新目录应完全生效"
    shutdown_logging()


def test_flush_trace_second_drain_catches_in_window_enqueue(tmp_path, monkeypatch):
    """M2 遗留债务 1：第一次排空后、第二次排空前入队的记录不丢。

    受控注入：把 time.sleep 替换为「注入一条迟到记录」的实现——该调用恰好落在
    flush_trace 两次排空之间（确定性复现竞态窗口），单次 flush_trace 即应捕获。
    """
    import json as jsonlib

    from app.services import logging_service as ls
    from app.services.logging_service import setup_logging

    setup_logging(str(tmp_path), "INFO")
    produced = {"done": False}
    original_sleep = ls.time.sleep

    def _sleep_then_inject(seconds):
        original_sleep(seconds)  # 必须调原实现（time.sleep 已被替换，直接调会无限递归）
        if not produced["done"]:
            produced["done"] = True
            logging.getLogger("agent_proxy.trace").info(jsonlib.dumps({"phase": "in-window"}))

    monkeypatch.setattr(ls.time, "sleep", _sleep_then_inject)
    logging.getLogger("agent_proxy.trace").info(jsonlib.dumps({"phase": "early"}))
    ls.flush_trace()
    content = "".join(
        p.read_text(encoding="utf-8") for p in sorted(tmp_path.glob("trace.log.*")))
    assert '"phase": "early"' in content
    assert '"phase": "in-window"' in content, "两次排空之间入队的记录应被第二次排空捕获"
