"""test 接口（设计 §6.6）：http 连通判定 / test_request 严格验证 / 5s 短超时 / 安全边界。

上游失败一律 ok=false + detail，不产生代理自身 502/504；仅注册者可测；
mcp 类型按 SSE 握手语义验证（M3：text/event-stream + 首个 endpoint 事件即通过），
Streamable initialize 语义验证随 M4（§8.4）。
"""
import glob
import json

from tests.integration.mock_mcp_sse import mock_state
from tests.integration.mock_mcp_streamable import streamable_state
from tests.utils import make_token


async def _register(client, user=888, **overrides):
    payload = {"type": "http", "upstream_url": "http://127.0.0.1:9901/api/v1",
               "headers": {"Authorization": "Bearer sk-real-12345678"}, **overrides}
    resp = await client.post("/api/v1/mappings", json=payload,
                             headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _test(client, mapping_id, user=888):
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
    """上游不可达（9909 不存在端口）：ok=false，status_code=None。"""
    created = await _register(client, upstream_url="http://127.0.0.1:9909/api/v1")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None and body["detail"]


async def test_test_endpoint_owner_only_404(client):
    created = await _register(client, user=888)
    resp = await _test(client, created["mapping_id"], user=999)
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


# ---------- M3：mcp + SSE 类型验证（§6.6：text/event-stream + 首个 endpoint 事件即通过） ----------


async def test_mcp_sse_probe_ok(client, mcp_sse_upstream_server):
    """SSE 握手验证：收到 text/event-stream + 首个 endpoint 事件即通过，随后立即断开。"""
    created = await _register(client, type="mcp", upstream_url="http://127.0.0.1:9902/sse",
                              headers={"Authorization": "Bearer sk-mcp-12345678"})
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert "SSE 握手成功" in body["detail"]
    assert "session_id=" in body["detail"] and "test123" not in body["detail"]  # 值已脱敏
    # 与 Task 5 转发管线同规（评审遗留）：SSE 探测连接同样不复用——出站必须
    # 显式 Connection: close（读到首事件即 aclose 的连接绝不回流 keepalive 池）
    assert mock_state["last_sse_headers"].get("connection") == "close"


async def test_mcp_sse_probe_upstream_down_ok_false(client):
    """上游不可达（9909 不存在端口）：ok=false + status_code=None，不抛 502。"""
    created = await _register(client, type="mcp", upstream_url="http://127.0.0.1:9909/sse")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None and "不可达" in body["detail"]


async def test_mcp_sse_probe_no_endpoint_event_ok_false(client, mcp_sse_upstream_server):
    """SSE 流但 5s 内无 endpoint 事件（mock /sse-no-endpoint）：ok=false。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-no-endpoint")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 200
    assert "endpoint" in body["detail"]


# ---------- 评审修复：probe 读阶段兜底 / 事件名复位对齐 / 覆盖补缺 ----------


async def test_mcp_sse_probe_upstream_headers_then_rst_ok_false(client, mcp_sse_upstream_server):
    """评审 Important 1a：上游发完响应头即断（读阶段 aiter_bytes 抛 httpx.HTTPError）
    ——ok=false 兜底而非穿透 500，且 resp 被 aclose（连接不滞留池内）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-headers-then-rst")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200                      # 读阶段失败绝不变成代理 500
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 200
    assert "上游 SSE 流读取失败" in body["detail"]       # 走 HTTPError 兜底分支


async def test_mcp_sse_probe_malformed_endpoint_value_redacted(client, mcp_sse_upstream_server):
    """评审 Important 1b：endpoint 值畸形（`http://[bad` 使 urlparse 抛 ValueError）
    ——脱敏降级指纹占位，握手判定不受影响，绝不 500。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-endpoint-malformed")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert "SSE 握手成功" in body["detail"]
    assert "http://[bad" not in body["detail"]          # 畸形值已降级指纹占位


async def test_mcp_sse_probe_blank_line_resets_event_name(client, mcp_sse_upstream_server):
    """评审 Minor 2：空行结束事件块后事件名复位（与 SseEndpointRewriter 对齐）——
    `event: endpoint\\n\\n` 后的默认类型 data 行不得被误判为 endpoint（假 ok=true）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-endpoint-no-data")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 200
    assert "流结束仍未收到 endpoint 事件" in body["detail"]  # 非超时路径（EOF 即决）


async def test_mcp_sse_probe_same_origin_redirect_ok_false(client, mcp_sse_upstream_server):
    """评审 Minor 4：注册端点为同源重定向（/sse-redirect-same，307 html）——
    probe 判 ok=false（非 SSE 分支），detail 不含 Location（真实 origin 不外泄）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-redirect-same")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 307
    assert "非 SSE 响应" in body["detail"]
    assert "9902/sse" not in body["detail"]             # Location 不落 detail


async def test_mcp_sse_probe_stream_eof_no_endpoint_ok_false(client, mcp_sse_upstream_server):
    """评审 Minor 4：流正常 EOF 但从未发 endpoint 事件——「流结束仍未收到 endpoint
    事件」分支（区别于 5s 超时路径），ok=false 快速即决。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-eof-no-endpoint")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 200
    assert "流结束仍未收到 endpoint 事件" in body["detail"]


async def test_mcp_sse_probe_gzip_upstream_identity_negotiation_ok(client, mcp_sse_upstream_server):
    """M4 评审携带项：gzip SSE 上游（协商式压缩）——probe 必须钉出站
    accept-encoding: identity 读明文（probe 是唯一要解析响应体的路径，aiter_raw
    不解压；identity 钉是「测的即真实路径」原则）。修复前默认 gzip 协商使
    probe 读到压缩体、解析不出 endpoint 事件而误报 ok=false。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-gzip-stream")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert "SSE 握手成功" in body["detail"]
    assert "session_id=" in body["detail"]


async def test_mcp_sse_probe_total_deadline_shared_across_phases(client, mcp_sse_upstream_server):
    """probe 总挂钟期限定稿（M3 Minor 3 → M4 落地）：send（响应头 3s 到达）与读流
    （endpoint 再 3s）共享 5s deadline——旧分阶段语义（各 5s）会 ~6s 返回 ok=true，
    总期限语义必须 ~5s 即 ok=false。"""
    import time as time_mod

    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-slow-hello")
    t0 = time_mod.monotonic()
    resp = await _test(client, created["mapping_id"])
    elapsed = time_mod.monotonic() - t0
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 200
    assert "总期限" in body["detail"]
    assert elapsed < 5.8, f"probe 应在总期限 ~5s 内返回，实际 {elapsed:.1f}s"


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


# ---------- 评审修复：expect_status 校验 / 严格模式语义 / probe 路径安全 ----------


async def test_register_rejects_malformed_expect_status(client):
    """expect_status 非法（非 100-599 int）在注册时拒绝（400 INVALID_PARAM），不留 500 隐患。"""
    resp = await client.post(
        "/api/v1/mappings",
        json={"type": "http", "upstream_url": "http://127.0.0.1:9901/api/v1",
              "headers": {},
              "test_request": {"method": "GET", "path": "/status/201",
                               "expect_status": "abc"}},
        headers={"Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_strict_mode_without_expect_status_judged_failed(client):
    """严格模式语义：无 expect_status 时总 ok=false（不当作「任意状态码皆可」）。

    上游实际可达（status_code 回真实值 201），但严格判定无法执行 → 判失败。
    """
    created = await _register(client, test_request={"method": "GET", "path": "/status/201"})
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 201
    assert "expect_status" in body["detail"]


async def test_probe_dot_segment_path_400(client):
    """probe 的 test_request.path 走与转发一致的 dot-segment 安全检查 → 400 INVALID_PARAM。"""
    created = await _register(client, test_request={"method": "GET", "path": "/../x",
                                                    "expect_status": 200})
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_register_rejects_illegal_test_method(client):
    """M2 遗留 Minor 5：test_request.method 白名单（合法 HTTP 动词），TRACE 等注册即拒。"""
    resp = await client.post(
        "/api/v1/mappings",
        json={"type": "http", "upstream_url": "http://127.0.0.1:9901/api/v1",
              "headers": {},
              "test_request": {"method": "TRACE", "path": "/orders", "expect_status": 200}},
        headers={"Authorization": f"Bearer {make_token(888)}"})
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


# ---------- M4：mcp test 探测式 auto（先 Streamable initialize，拒绝 POST 回落 SSE） ----------


async def test_mcp_streamable_probe_ok(client, mcp_streamable_upstream_server):
    """§6.6 mcp+Streamable：POST initialize → 200 JSON 含 serverInfo → ok=true。
    出站头同时钉住探测专属语义（Task 5 评审核销 4）：accept-encoding=identity
    （探测要解析响应体，读明文）+ connection=close（探测连接绝不回流池）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp")
    streamable_state["received"].clear()
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert "Streamable initialize 成功" in body["detail"]
    assert "mock-mcp-streamable" in body["detail"]       # serverInfo.name 回告
    assert body["latency_ms"] >= 0
    rec = streamable_state["received"][-1]
    assert rec["rpc"]["method"] == "initialize"          # 到上游的即标准 initialize
    assert rec["headers"]["accept-encoding"] == "identity"
    assert rec["headers"]["connection"] == "close"


async def test_mcp_streamable_probe_sse_form_ok(client, mcp_streamable_upstream_server):
    """initialize 以短 SSE 流形态响应（Streamable 允许）：首个 message 事件含
    serverInfo 同样通过（JSON / SSE 两形态判定均覆盖）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp-sse-form")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert "Streamable initialize 成功" in body["detail"]


async def test_mcp_streamable_probe_no_serverinfo_ok_false(client, mcp_streamable_upstream_server):
    """POST 被接受（200 JSON）但 result 缺 serverInfo——§6.6 硬判定 ok=false
    （不回落 SSE：POST 未被拒绝，端点只是非 MCP）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp-no-serverinfo")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 200
    assert "缺少 serverInfo" in body["detail"]


async def test_mcp_streamable_probe_timeout_ok_false_no_5xx(client, mcp_streamable_upstream_server):
    """Streamable 上游可达但 initialize 8s 不响应（> 5s 总期限）：ok=false，
    不产生代理 5xx，也不回落（超时 ≠ 拒绝 POST）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp-slow")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200                       # 上游失败不变成代理 5xx（§6.6）
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None
    assert "超时" in body["detail"]


async def test_mcp_streamable_probe_upstream_down_ok_false(client):
    """上游不可达（9909 不存在端口）：ok=false + status_code=None，不抛 502。"""
    created = await _register(client, type="mcp", upstream_url="http://127.0.0.1:9909/mcp")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] is None and "不可达" in body["detail"]


async def test_mcp_probe_fallback_non_sse_ok_false(client, mcp_sse_upstream_server):
    """回落路径：SSE-only 上游对 POST 回 405 → SSE 握手探测 → 注册端点回非 SSE
    （503 html）→ ok=false 且 detail 不含 Location（真实 origin 不外泄）；
    detail 前缀回告「SSE 端点」来源供排障。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9902/sse-503")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 503
    assert "非 SSE 响应" in body["detail"]
    assert "SSE 端点" in body["detail"]
    assert "9902/sse" not in body["detail"]


# ---------- M4 Task 5 评审核销项：非 2xx 不回落 / 回落成功主场景 / 回落触发器矩阵 ----------


async def test_mcp_probe_no_fallback_on_401(client, mcp_streamable_upstream_server):
    """评审核销 1（回归防）：上游 401（凭据失效）——直接判失败**不回落**，detail
    明示「上游拒绝」且无「回落」/「SSE 端点」前缀（凭据失效应显式暴露，不掩盖为
    形态回落，也不误报为「缺少 serverInfo」的端点形态误导）。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp-401")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200                       # 上游失败不变成代理 5xx
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 401
    assert "上游拒绝（status=401）" in body["detail"]
    assert "SSE 端点" not in body["detail"]
    assert "回落" not in body["detail"]


async def test_mcp_probe_no_fallback_on_500(client, mcp_streamable_upstream_server):
    """评审核销 1：上游 500（服务端错误）——同 401 非 2xx 短路判失败不回落。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp-500")
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 500
    assert "上游拒绝（status=500）" in body["detail"]
    assert "SSE 端点" not in body["detail"]
    assert "回落" not in body["detail"]


async def test_mcp_probe_fallback_sse_ok(client, mcp_sse_upstream_server):
    """评审核销 2（主用户场景）：SSE-only 上游（9902 /sse 仅注册 GET，POST 回 405）
    → 回落 SSE 握手探测成功 → ok=true 且 detail 前缀「SSE 端点（…回落…）」。"""
    created = await _register(client, type="mcp", upstream_url="http://127.0.0.1:9902/sse",
                              headers={"Authorization": "Bearer sk-mcp-12345678"})
    resp = await _test(client, created["mapping_id"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert "SSE 端点" in body["detail"]
    assert "回落" in body["detail"]
    assert "SSE 握手成功" in body["detail"]


async def test_mcp_probe_fallback_trigger_404(client, mcp_streamable_upstream_server):
    """评审核销 4（可选矩阵）：404 回落触发器——未注册路径 POST 回 404 → 回落
    SSE 握手探测 → GET 同路径 404 非 SSE → ok=false，前缀「SSE 端点」。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/never-registered")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 404
    assert "非 SSE 响应" in body["detail"]
    assert "SSE 端点" in body["detail"]


async def test_mcp_probe_fallback_trigger_406(client, mcp_streamable_upstream_server):
    """评审核销 4（可选矩阵）：406 回落触发器——/mcp-406 对 POST/GET 同态 406 →
    回落后「非 SSE 响应（status=406…）」，前缀「SSE 端点」。"""
    created = await _register(client, type="mcp",
                              upstream_url="http://127.0.0.1:9903/mcp-406")
    resp = await _test(client, created["mapping_id"])
    body = resp.json()
    assert body["ok"] is False and body["status_code"] == 406
    assert "非 SSE 响应" in body["detail"]
    assert "SSE 端点" in body["detail"]
