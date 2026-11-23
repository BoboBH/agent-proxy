"""集成测试夹具：独立测试库 agent_proxy_test + Redis db9 + ASGITransport。"""
import base64
import json
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ.update({
    "ENV": "dev",
    "TOKEN_VERIFY_IMPL": "stub",
    "LOGIN_IMPL": "stub",
    "EXTERNAL_BASE": "http://testserver",
    "MYSQL_DSN": "mysql+aiomysql://root:123456@127.0.0.1:3306/agent_proxy_test",
    "REDIS_URL": "redis://127.0.0.1:6379/9",
    "SSRF_ALLOW_PRIVATE": "true",
    "ENCRYPT_AT_REST": "false",
    "MASTER_KEY": "test-master-key",
    "TRACE_MODE": "metadata",
    "LOG_DIR": "logs-test",
    "LOG_LEVEL": "INFO",
})

from agent_proxy.config import Settings  # noqa: E402
from agent_proxy.main import create_app  # noqa: E402


@pytest.fixture
async def app():
    application = create_app(Settings.from_env(os.environ))
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


def make_token(user_id: str = "u888", role: str | None = None, user_name: str = "张三") -> str:
    payload = {"user_id": user_id, "user_name": user_name}
    if role:
        payload["role"] = role
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"stub.{body}.sig"


def auth(user_id: str = "u888", role: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {make_token(user_id, role)}"}
