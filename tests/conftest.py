"""集成测试夹具：独立测试库 agent_proxy_test + Redis db9 + ASGITransport。

存储连接（host/端口/密码）从开发者 .env 读取（dotenv_values 直读文件，不污染进程
环境），仅替换库名（agent_proxy_test）与 Redis db 号（9）；.env 缺失时回退
127.0.0.1 免密默认。其余测试面（EXTERNAL_BASE、票据、TTL 等）仍在此处钉住，
不随 .env 漂移。
"""
import base64
import json
import os

import pytest
import pytest_asyncio
from dotenv import dotenv_values
from httpx import ASGITransport, AsyncClient

from app.env import BASE_DIR

# 与 env.py 同一来源定位 .env（PROJECT_ROOT 锚定，不随 CWD 漂移）
_dotenv = {k: v for k, v in (dotenv_values(BASE_DIR / ".env") or {}).items() if v}


def _swap_db(url: str, db: str) -> str:
    """替换 URL 最后一段路径（MySQL 库名 / Redis db 号）；无路径段则原样返回。"""
    head, sep, _tail = url.rpartition("/")
    return f"{head}/{db}" if sep and head and _tail else url


MYSQL_DSN = _swap_db(_dotenv.get("MYSQL_DSN", ""), "agent_proxy_test")
REDIS_URL = _swap_db(_dotenv.get("REDIS_URL", ""), "9")

os.environ.update({
    "ENV": "dev",
    "TOKEN_VERIFY_IMPL": "stub",
    "LOGIN_IMPL": "stub",
    "EXTERNAL_BASE": "http://testserver",
    "MYSQL_DSN": MYSQL_DSN or "mysql+aiomysql://root@127.0.0.1:3306/agent_proxy_test",
    "REDIS_URL": REDIS_URL or "redis://127.0.0.1:6379/9",
    "SSRF_ALLOW_PRIVATE": "true",
    "MAX_BODY_SIZE": "1MB",
    "CORS_ALLOWED_ORIGINS": "http://127.0.0.1:9910,http://testserver",
    "MASTER_KEY": "test-master-key",
    "TRACE_MODE": "metadata",
    "LOG_DIR": "logs-test",
    "LOG_LEVEL": "INFO",
})

from app.env import Settings  # noqa: E402

# 先类级关闭 env_file、再 import app.main（模块级 app = create_app() 在导入期实例化
# Settings）：测试进程完全禁读仓库 .env——夹具全部经 os.environ 驱动，开发者本机
# .env 不得影响测试；.env 文件解析行为用例在 unit/test_env.py 以 _env_file=<路径> 显式验证
Settings.model_config["env_file"] = None

from app.main import create_app  # noqa: E402


@pytest.fixture
async def app():
    application = create_app(Settings(_env_file=None))
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


def make_token(user_id: int = 888, role: str | None = None, user_name: str = "张三") -> str:
    """user_id 为 int（收尾批次整数化，与 Identity.user_id: int 同型）。"""
    payload = {"user_id": user_id, "user_name": user_name}
    if role:
        payload["role"] = role
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"stub.{body}.sig"


def auth(user_id: int = 888, role: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {make_token(user_id, role)}"}
