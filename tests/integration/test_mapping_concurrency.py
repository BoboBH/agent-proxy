"""按映射并发上限集成测试（设计 v4.2，慢上游隔离）。

自建 app 实例（MAPPING_MAX_CONCURRENCY=2，独立于其他用例的全局默认）：
- 慢映射并发占满上限 → 超额慢请求 503 PROXY_BUSY（按映射隔离的语义核心）；
- 慢映射饱和期间，其他映射的请求**全部正常**且延迟不受影响。
"""
import asyncio
import os
import time

import pytest
from httpx import ASGITransport, AsyncClient

from tests.utils import make_token

AUTH = {"Authorization": f"Bearer {make_token(888)}"}
ECHO = "http://127.0.0.1:9901/api/v1"


@pytest.fixture()
def small_cap_env():
    yield


async def test_slow_mapping_isolated_from_fast_mapping():
    from app.env import BASE_DIR, Settings
    from app.main import create_app

    settings = Settings(_env_file=BASE_DIR / ".env",
                        token_verify_impl="stub",     # 本测试用 stub 票据鉴权
                        mapping_max_concurrency=2,    # 小上限：2 个并发慢请求即占满
                        log_dir="logs-test")
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://testserver") as c:
            ids = {}
            for name in ("iso-slow", "iso-fast"):
                resp = await c.post("/api/v1/mappings", headers=AUTH,
                                    json={"type": "http", "name": name,
                                          "upstream_url": ECHO, "headers": {}})
                assert resp.status_code == 201, resp.text
                ids[name] = resp.json()["mapping_id"]
            slow_mid, fast_mid = ids["iso-slow"], ids["iso-fast"]

            # 预热（验签/映射缓存/连接池）
            await c.get(f"/p/{fast_mid}/final", headers=AUTH)

            # 10 并发慢请求（各 3s；上限 2 → 等待者 5s 超时 → 503 PROXY_BUSY）
            # 同时 40 个快请求（应全部 200 且延迟无恶化）
            slow_res, fast_res = [], []

            async def slow():
                r = await c.get(f"/p/{slow_mid}/slow?seconds=3", headers=AUTH)
                slow_res.append(r.status_code)

            async def fast():
                t = time.perf_counter()
                r = await c.get(f"/p/{fast_mid}/final", headers=AUTH)
                fast_res.append((r.status_code, time.perf_counter() - t))

            await asyncio.gather(*(slow() for _ in range(10)),
                                 *(fast() for _ in range(40)))

            # 波次动态：上限 2 → 第一波 2 个成功；部分等待者在 5s 窗口内等到第二波
            # 空位（再 2 个成功）；其余等待超时 → 503 PROXY_BUSY
            assert 2 <= slow_res.count(200) <= 4, f"成功数应≈上限波次（实际 {slow_res}）"
            assert slow_res.count(503) >= 4, f"超额慢请求应 503 PROXY_BUSY（实际 {slow_res}）"
            fast_codes = [code for code, _ in fast_res]
            assert fast_codes.count(200) == 40, f"快请求应全部 200（实际 {fast_codes}）"
            fast_lat = sorted(dt for _, dt in fast_res)
            p95 = fast_lat[int(len(fast_lat) * 0.95)]
            assert p95 < 2.0, f"快请求 p95 不应被慢映射拖垮（实际 p95={p95:.2f}s）"

            # 清理
            for mid in (slow_mid, fast_mid):
                await c.delete(f"/api/v1/mappings/{mid}", headers=AUTH)
