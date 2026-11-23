"""集成目录独占夹具：建测试库 + 每测试后清库清缓存（仅作用于 integration，避免污染单元测试）。"""
import asyncio
import threading

import pymysql
import pytest
import pytest_asyncio
import shutil
import uvicorn

from tests.integration.mock_upstream import build_echo_app


@pytest.fixture(scope="session", autouse=True)
def _clean_test_logs():
    """会话开始清空集成测试日志目录：audit handler 持续 append，不清则审计测试读到上次运行的旧行（非密封）。"""
    shutil.rmtree("logs-test", ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def _recreate_test_db():
    conn = pymysql.connect(host="127.0.0.1", user="root", password="123456", port=3306)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE DATABASE IF NOT EXISTS agent_proxy_test "
                "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            conn.commit()
    finally:
        conn.close()


@pytest.fixture(autouse=True)
async def _clean(app):
    yield
    from sqlalchemy import text
    try:
        async with app.state.sessionmaker() as session:
            for table in ("proxy_oauth_credential", "proxy_oauth_client", "proxy_mapping"):
                await session.execute(text(f"DELETE FROM {table}"))
            await session.commit()
    except Exception:
        pass  # Task 7 建 models 前表尚不存在，跳过清理
    await app.state.redis.flushdb()


@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def real_upstream_server():
    """真实 echo 上游：uvicorn 真实监听 127.0.0.1:9901（一次启动，全集成测试共享）。

    与计划原稿的差异（实测必要）：uvicorn 的 serve() 不能作为 task 挂在本进程
    session loop 上——pytest-asyncio 只在 session 级夹具执行时驱动该 loop，
    function 级测试运行期间 session loop 处于停驻状态，连接永远得不到 accept
    （客户端 5s 读超时，session 结束时 parked accept 报 _sockets 断言）。
    因此把 serve() 挂到独立后台线程的独立 loop 上：测试用例各自的 loop
    经真实 TCP 访问它（跨 loop 只过网络，无共享 asyncio 对象，语义不变）。
    断言 server.started 前最多等 10s（端口被占用时快速失败）。
    """
    config = uvicorn.Config(build_echo_app(), host="127.0.0.1", port=9901,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_until_complete, args=(server.serve(),),
                              daemon=True, name="echo-upstream-9901")
    thread.start()
    for _ in range(200):
        # 线程已退出而 started 仍 False（如端口占用崩溃）时提前失败，不必等满 10s
        if server.started or not thread.is_alive():
            break
        await asyncio.sleep(0.05)
    assert server.started, "echo 上游启动失败（127.0.0.1:9901 被占用？）"
    yield server
    server.should_exit = True
    thread.join(timeout=10)
    server.force_exit = True  # 兜底：优雅停机超时则强制置位，防止 join 卡死拖垮会话
    thread.join(timeout=5)
    assert not thread.is_alive(), "echo 上游未在 15s 内停机"
    loop.close()
