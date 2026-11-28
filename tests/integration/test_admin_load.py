"""管理页「实时负载」端点集成测试（GET /api/v1/mappings/load，设计 §15 v4.3）。

- 仅 admin（403）；
- 代理命中后 count_5m 计数可见、inflight 归零；
- 慢请求在途时 inflight ≥ 1（管理视图的「每个代理占用多少连接」语义）。
"""
import asyncio

from tests.utils import make_token

ADMIN = {"Authorization": f"Bearer {make_token(888, role='org_member')}"}
ECHO = "http://127.0.0.1:9901/api/v1"


async def _register(client, name):
    resp = await client.post("/api/v1/mappings", headers=ADMIN,
                             json={"type": "http", "name": name,
                                   "upstream_url": ECHO, "headers": {}})
    assert resp.status_code == 201, resp.text
    return resp.json()["mapping_id"]


async def test_load_counts_and_inflight(client):
    mid = await _register(client, "load-demo")
    r = await client.get(f"/p/{mid}/final",
                         headers={"Authorization": f"Bearer {make_token(888)}"})
    assert r.status_code == 200

    r = await client.get("/api/v1/mappings/load", headers=ADMIN)
    assert r.status_code == 200
    body = r.json()
    assert body["window_seconds"] == 300
    items = {x["mapping_id"]: x for x in body["mappings"]}
    assert items[mid]["count_5m"] >= 1          # 窗口计数可见
    assert items[mid]["inflight"] == 0          # 请求已结束
    assert items[mid]["type"] == "http"


async def test_load_inflight_during_slow_request(client):
    mid = await _register(client, "load-slow")
    task = asyncio.create_task(
        client.get(f"/p/{mid}/slow?seconds=1",
                   headers={"Authorization": f"Bearer {make_token(888)}"}))
    await asyncio.sleep(0.25)                   # 慢请求在途窗口内查负载
    r = await client.get("/api/v1/mappings/load", headers=ADMIN)
    inflight = {x["mapping_id"]: x["inflight"] for x in r.json()["mappings"]}.get(mid, 0)
    assert inflight >= 1
    await task


async def test_load_requires_admin(client):
    r = await client.get("/api/v1/mappings/load",
                         headers={"Authorization": f"Bearer {make_token(888)}"})
    assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"
