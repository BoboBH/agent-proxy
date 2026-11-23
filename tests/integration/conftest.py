"""集成目录独占夹具：建测试库 + 每测试后清库清缓存（仅作用于 integration，避免污染单元测试）。"""
import pymysql
import pytest
import shutil


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
