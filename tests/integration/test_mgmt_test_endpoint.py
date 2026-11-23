"""test 接口（设计 §6.6）：http 连通判定 / test_request 严格验证 / 5s 短超时 / 安全边界。

上游失败一律 ok=false + detail，不产生代理自身 502/504；仅注册者可测；
mcp 类型 M2 明确返回未支持（M3/M4 补语义验证）。
"""
import glob
import json

from tests.utils import make_token

AUTH = {"Authorization": f"Bearer {make_token('u888')}"}


async def _register(client, user="u888", **overrides):
    payload = {"type": "http", "upstream_url": "http://127.0.0.1:9901/api/v1",
               "headers": {"Authorization": "Bearer sk-real-12345678"}, **overrides}
    resp = await client.post("/api/v1/mappings", json=payload,
                             headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _test(client, mapping_id, user="u888"):
    hdrs = {"Authorization": f"Bearer {make_token(user)}"}
    return await client.post(f"/api/v1/mappings/{mapping_id}/test", headers=hdrs)


async def test_http_probe_connectivity_ok(client):
    """默认 GET upstream_url：任意 HTTP 响应 = 可达（base URL 可能天然 404，不硬判失败）。"""
    created = await _register(client)
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert body["latency_ms"] >= 0 and body["detail"]


async def test_http_probe_strict_expect_match(client):
    created = await _register(client, test_request={"method": "GET",
                                                    "path": "/status/201",
                                                    "expect_status": 201})
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 201


async def test_http_probe_strict_expect_mismatch(client):
    created = await _register(client, test_request={"method": "GET",
                                                    "path": "/status/201",
                                                    "expect_status": 200})
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 201
    assert "200" in body["detail"] and "201" in body["detail"]


async def test_http_probe_strict_post_method_used(client):
    created = await _register(client, test_request={"method": "POST",
                                                    "path": "/orders",
                                                    "expect_status": 200})
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200


async def test_http_probe_timeout_ok_false_no_502(client):
    """上游超 5s：ok=false + detail 超时说明；绝不抛 502/504（设计 §6.6）。"""
    created = await _register(client, upstream_url="http://127.0.0.1:9901/api/v1/slow?seconds=8")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200  # 上游失败不变成代理 5xx
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None
    assert "超时" in body["detail"]


async def test_http_probe_upstream_down_ok_false(client):
    """上游不可达（9902 不存在端口）：ok=false，status_code=None。"""
    created = await _register(client, upstream_url="http://127.0.0.1:9902/api/v1")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None and body["detail"]


async def test_test_endpoint_owner_only_404(client):
    created = await _register(client, user="u888")
    resp = await _test(client, created["mapping_id"], user="u999")
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_test_endpoint_mcp_not_supported_400(client):
    created = await _register(client, type="mcp", upstream_url="https://mcp.ex.com/sse")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 400
    body = resp.json()
    assert body["code"] == "INVALID_PARAM" and "M3" in body["message"]


async def test_test_endpoint_audited_as_test_mapping(client):
    created = await _register(client)
    resp = await _test(client, created["mapping_id"])
    request_id = resp.headers["x-request-id"]
    entries = []
    for path in glob.glob("logs-test/audit.log.*"):
        with open(path, encoding="utf-8") as fh:
            entries.extend(json.loads(x) for x in fh.read().splitlines() if x.strip())
    mine = [e for e in entries if e["request_id"] == request_id]
    assert mine and mine[0]["action"] == "test_mapping"
    assert mine[0]["mapping_id"] == created["mapping_id"]
    assert "sk-real-12345678" not in json.dumps(mine[0])  # 审计不含 header 值（§6.6）
