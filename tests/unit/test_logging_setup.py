import logging
import os
import time


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
