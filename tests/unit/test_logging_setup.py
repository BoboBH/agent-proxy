import logging
import os
import time

import pytest


@pytest.fixture(autouse=True)
def _logging_hygiene():
    """每个测试结束后复位全局日志状态，避免 _registry / logger handlers 跨测试污染。"""
    yield
    import agent_proxy.logging_setup as ls

    from agent_proxy.logging_setup import shutdown_logging

    shutdown_logging()
    for name in ("agent_proxy", "agent_proxy.audit", "agent_proxy.trace"):
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
    ls._registry.clear()
    logging.getLogger("rotate-test").handlers = []


def test_rotate_on_size(tmp_path):
    from agent_proxy.logging_setup import DailySizeRotatingHandler

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
    assert len({f.name for f in files}) == len(files), "同秒滚动生成的文件名不应重复"
    handler.close()


def test_cleanup_expired_by_mtime(tmp_path):
    from agent_proxy.logging_setup import DailySizeRotatingHandler

    base = str(tmp_path / "t.log")
    handler = DailySizeRotatingHandler(base, max_bytes=10 * 1024 * 1024, keep_days=7)
    old = tmp_path / "t.log.20200101_000000"
    old.write_text("old", encoding="utf-8")
    past = time.time() - 8 * 86400
    os.utime(old, (past, past))
    handler._open_new()  # 触发一次清理
    assert not old.exists(), "超过保留期(7天)的旧文件应被删除"
    handler.close()


def test_setup_logging_creates_three_files(tmp_path):
    from agent_proxy.logging_setup import setup_logging

    setup_logging(str(tmp_path), "INFO")
    import agent_proxy.logging_setup as ls

    assert any("agent-proxy.log" in p for p in ls._registry)
    assert any("audit.log" in p for p in ls._registry)
    assert any("trace.log" in p for p in ls._registry)
    assert logging.getLogger("agent_proxy.audit").handlers
    assert logging.getLogger("agent_proxy.trace").handlers


def test_trace_queue_end_to_end(tmp_path):
    from agent_proxy.logging_setup import flush_trace, setup_logging

    setup_logging(str(tmp_path), "INFO")
    logging.getLogger("agent_proxy.trace").info('{"k":1}')
    flush_trace()
    content = "".join(
        p.read_text(encoding="utf-8") for p in sorted(tmp_path.glob("trace.log.*"))
    )
    assert '{"k":1}' in content, "flush 后 trace.log 应包含写入的行"


def test_setup_logging_idempotent(tmp_path):
    import agent_proxy.logging_setup as ls

    from agent_proxy.logging_setup import DailySizeRotatingHandler, setup_logging

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
    import agent_proxy.logging_setup as ls

    from agent_proxy.logging_setup import flush_trace, setup_logging, shutdown_logging

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

    from agent_proxy import logging_setup as ls
    from agent_proxy.logging_setup import setup_logging

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
