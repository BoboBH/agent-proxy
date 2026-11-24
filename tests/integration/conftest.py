"""集成目录独占夹具：建测试库 + 每测试后清库清缓存（仅作用于 integration，避免污染单元测试）。"""
import asyncio
import threading

import httpx
import pymysql
import pytest
import pytest_asyncio
import shutil
import uvicorn

from tests.integration.mock_mcp_sse import build_mcp_sse_app
from tests.integration.mock_mcp_streamable import build_mcp_streamable_app
from tests.integration.mock_oauth_as import build_oauth_as_app
from tests.integration.mock_upstream import build_echo_app


@pytest.fixture(scope="session", autouse=True)
def _clean_test_logs():
    """会话开始清空集成测试日志目录：audit handler 持续 append，不清则审计测试读到上次运行的旧行（非密封）。"""
    shutil.rmtree("logs-test", ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def _recreate_test_db():
    """建测试库 + drop 三业务表（收尾批次 schema 变更：owner_uid/uid BIGINT 化、
    upstream_headers JSON→TEXT 密文列；测试基建允许 drop——表内均为测试数据，
    无状态保留语义），随后 app lifespan 的 create_all 按现行 models 重建。"""
    conn = pymysql.connect(host="127.0.0.1", user="root", password="123456", port=3306)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE DATABASE IF NOT EXISTS agent_proxy_test "
                "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            for table in ("proxy_oauth_credential", "proxy_oauth_client", "proxy_mapping"):
                cur.execute(f"DROP TABLE IF EXISTS agent_proxy_test.{table}")
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


@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def mcp_sse_upstream_server():
    """真实 MCP SSE 上游：uvicorn 真实监听 127.0.0.1:9902（session 级，独立线程 loop）。

    非 autouse 改 autouse（评审自检修正）：SSE 相关测试分布多个文件且均经代理
    隐式访问 9902（无人显式请求夹具时 9902 不会启动）——统一随 session 启动，
    成本一次性 ~1s。启动/停机模式与 echo 上游 9901 夹具一致
    （uvicorn.serve() 挂独立线程独立 loop；测试用例经真实 TCP 访问，跨 loop 只过网络）。
    """
    config = uvicorn.Config(build_mcp_sse_app(), host="127.0.0.1", port=9902,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_until_complete, args=(server.serve(),),
                              daemon=True, name="mcp-sse-upstream-9902")
    thread.start()
    for _ in range(200):
        if server.started or not thread.is_alive():
            break
        await asyncio.sleep(0.05)
    assert server.started, "MCP SSE 上游启动失败（127.0.0.1:9902 被占用？）"
    yield server
    server.should_exit = True
    thread.join(timeout=10)
    server.force_exit = True  # 兜底：SSE 长连接下优雅停机可能超时，强制置位防 join 卡死
    thread.join(timeout=5)
    assert not thread.is_alive(), "MCP SSE 上游未在 15s 内停机"
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def mcp_streamable_upstream_server():
    """真实 MCP Streamable 上游：uvicorn 真实监听 127.0.0.1:9903（session 级，独立线程 loop）。

    启动/停机模式与 echo(9901)/SSE(9902) 夹具一致：uvicorn.serve() 挂独立线程
    独立 loop，测试用例经真实 TCP 访问（跨 loop 只过网络，无共享 asyncio 对象）。
    autouse 统一随 session 启动（启动成本 ~1s 一次性）。
    """
    config = uvicorn.Config(build_mcp_streamable_app(), host="127.0.0.1", port=9903,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_until_complete, args=(server.serve(),),
                              daemon=True, name="mcp-streamable-upstream-9903")
    thread.start()
    for _ in range(200):
        if server.started or not thread.is_alive():
            break
        await asyncio.sleep(0.05)
    assert server.started, "MCP Streamable 上游启动失败（127.0.0.1:9903 被占用？）"
    yield server
    server.should_exit = True
    thread.join(timeout=10)
    server.force_exit = True  # 兜底：长连接下优雅停机可能超时，强制置位防 join 卡死
    thread.join(timeout=5)
    assert not thread.is_alive(), "MCP Streamable 上游未在 15s 内停机"
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def mock_oauth_as_server():
    """mock OAuth2 AS+RS：uvicorn 真实监听 127.0.0.1:9904（session 级，独立线程 loop）。

    启动/停机模式与 9901/9902/9903 夹具一致：uvicorn.serve() 挂独立线程独立 loop，
    测试用例经真实 TCP 访问（跨 loop 只过网络，无共享 asyncio 对象）。
    autouse 统一随 session 启动（启动成本 ~1s 一次性）。
    """
    config = uvicorn.Config(build_oauth_as_app(), host="127.0.0.1", port=9904,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_until_complete, args=(server.serve(),),
                              daemon=True, name="mock-oauth-as-9904")
    thread.start()
    for _ in range(200):
        if server.started or not thread.is_alive():
            break
        await asyncio.sleep(0.05)
    assert server.started, "mock OAuth AS 启动失败（127.0.0.1:9904 被占用？）"
    yield server
    server.should_exit = True
    thread.join(timeout=10)
    server.force_exit = True  # 兜底：优雅停机超时则强制置位，防止 join 卡死拖垮会话
    thread.join(timeout=5)
    assert not thread.is_alive(), "mock OAuth AS 未在 15s 内停机"
    loop.close()


@pytest.fixture(autouse=True)
async def _reset_oauth_as(mock_oauth_as_server):
    """每个集成测试前重置 mock AS 动态状态（签发登记一并清空）——9904 为进程内
    全局单例，不清则用例间 codes/issued/refresh 计数互相污染（非密封）。"""
    try:
        async with httpx.AsyncClient() as c:
            await c.post("http://127.0.0.1:9904/_test/reset")
    except Exception:
        pass  # 非致命：session 夹具已断言启动成功；此处不阻塞其他用例
    yield


@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def real_proxy_app():
    """被测代理本体：uvicorn 真实监听 127.0.0.1:9910（session 级，独立线程 loop）。

    M3 起必须真实服务器：httpx ASGITransport 把响应体整体积攒到 app 结束才返回
    （ASGIResponseStream.__aiter__ 一次性 join 全部 body_parts）——SSE 永不结束
    的流会让 handle_async_request 永不返回，ASGI 直连测试直接挂死。故 SSE 集成
    一律经真实 TCP 访问本服务；「客户端断开→上游取消」同样只有真实服务器可测。
    autouse：SSE 测试遍布多个文件，统一随 session 启动（启动成本 ~1s 一次性）。
    """
    import os

    from agent_proxy.config import Settings
    from agent_proxy.main import create_app

    settings = Settings.from_env({**os.environ, "EXTERNAL_BASE": "http://127.0.0.1:9910"})
    application = create_app(settings)
    config = uvicorn.Config(application, host="127.0.0.1", port=9910,
                            log_level="warning", access_log=False,
                            timeout_graceful_shutdown=5)
    server = uvicorn.Server(config)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_until_complete, args=(server.serve(),),
                              daemon=True, name="agent-proxy-9910")
    thread.start()
    for _ in range(200):
        if server.started or not thread.is_alive():
            break
        await asyncio.sleep(0.05)
    assert server.started, "被测代理启动失败（127.0.0.1:9910 被占用？）"
    yield application
    server.should_exit = True
    thread.join(timeout=10)
    server.force_exit = True  # 兜底：SSE 长连接下优雅停机可能超时，强制置位防 join 卡死
    thread.join(timeout=5)
    assert not thread.is_alive(), "被测代理未在 15s 内停机"
    loop.close()
