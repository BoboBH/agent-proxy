"""MCP Streamable HTTP 全链路集成（真实 TCP）：测试客户端 → 真实 uvicorn 代理
（9910）→ 真实 TCP → mock MCP Streamable 上游（9903）。

§8.4：单一 /mcp 端点 POST/GET/DELETE；Mcp-Session-Id 白名单双向透传；JSON 或
SSE 响应均流式回传（无需改写）；GET /mcp 服务端推送流经 SSE 解析管线字节透传
（rewriter 对 Streamable 流无操作——见 api/proxy.py 分发注释与设计 §8.4 注记）。
"""
import asyncio
import json
import re

import httpx

from mocks.mcp_streamable import streamable_state
from tests.utils import make_token, read_next_message_data, sse_line_iter

PROXY = "http://127.0.0.1:9910"
UPSTREAM = "http://127.0.0.1:9903/mcp"
AUTH = {"Authorization": f"Bearer {make_token(888)}"}
SESSION = {"Mcp-Session-Id": "sess-m4"}
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)

INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "m4-test", "version": "0"}}}


async def _register_streamable(user=888, **overrides):
    payload = {"type": "mcp", "upstream_url": UPSTREAM,
               "headers": {"Authorization": "Bearer sk-mcp4-12345678"}, **overrides}
    async with httpx.AsyncClient() as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json=payload,
                            headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _sse_active_gauge(metrics_text: str) -> float:
    m = re.search(r"^ap_sse_active_connections ([0-9.]+)$", metrics_text, re.M)
    assert m, "ap_sse_active_connections 不在 metrics 输出中"
    return float(m.group(1))


async def test_initialize_json_response_and_session_header_back_to_client():
    """§8.4 主链路：POST initialize（JSON 响应形态）——响应头 Mcp-Session-Id
    透传回客户端（会话由上游自持，代理无会话状态），出站 header 为存储值。"""
    streamable_state["received"].clear()
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp", json=INITIALIZE, headers=AUTH)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["mcp-session-id"] == "sess-m4"      # 响应侧会话头透传（§8.4）
    assert r.headers.get("x-accel-buffering") == "no"    # §8.1 第 9 条
    assert r.json()["result"]["serverInfo"]["name"] == "mock-mcp-streamable"
    rec = streamable_state["received"][-1]
    assert rec["query"] == {}
    # 出站 header 重建（§8.1 第 1 条）：上游收到存储值，调用方 JWT 不透传
    assert rec["headers"]["authorization"] == "Bearer sk-mcp4-12345678"
    assert not any(v.startswith("stub.") for v in rec["headers"].values())


async def test_tools_list_json_with_session_header_upstream_passthrough():
    """请求侧会话头透传（§8.4）：tools/list 携带 Mcp-Session-Id 经代理原样到达上游。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp",
                         json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                         headers={**AUTH, **SESSION})
    assert r.status_code == 200
    assert [t["name"] for t in r.json()["result"]["tools"]] == ["echo"]
    rec = streamable_state["received"][-1]
    assert rec["headers"]["mcp-session-id"] == "sess-m4"   # 白名单透传（M2 建全的头）
    assert rec["rpc"]["method"] == "tools/list"


async def test_notification_post_202_passthrough():
    """§8.4 矩阵补缺（Task 5 评审携带）：notifications（无 id）POST 经代理 → 上游
    202 无响应体原样透传（MCP Streamable 规范形态，与直连冒烟 test_post_notification_returns_202 对称）。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp",
                         json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                         headers={**AUTH, **SESSION})
    assert r.status_code == 202
    assert streamable_state["received"][-1]["rpc"]["method"] == "notifications/initialized"


async def test_tools_call_sse_form_streamed_back():
    """§8.4「application/json 或 text/event-stream」的 SSE 形态：tools/call 短 SSE
    流经代理流式回传（query 透传切换 mock 形态），JSON-RPC 载荷不改写；
    Mcp-Session-Id 双向透传在 SSE 形态同样断言（Task 5 评审携带）。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("POST", f"{PROXY}/p/{mid}/mcp?form=sse",
                            json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "echo",
                                             "arguments": {"text": "hello-m4"}}},
                            headers={**AUTH, **SESSION}) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            assert resp.headers["mcp-session-id"] == "sess-m4"   # 响应侧会话头透传
            msg = None
            async for line in sse_line_iter(resp):
                if line.startswith("data:"):
                    msg = json.loads(line[len("data:"):].strip())
                    break
    assert msg is not None and msg["id"] == 3
    assert "hello-m4" in json.dumps(msg["result"])
    rec = streamable_state["received"][-1]
    assert rec["query"] == {"form": "sse"}                 # query 原样透传（origin 根还原）
    assert rec["headers"]["mcp-session-id"] == "sess-m4"   # 请求侧会话头透传（双向）


async def test_get_mcp_push_stream_passthrough_with_sse_pipeline_semantics():
    """§8.4 GET /mcp 服务端推送流：GET 命中注册端点路径 → SSE 解析管线——
    Streamable 流无 endpoint 事件，rewriter 字节级无操作透传；Connection: close
    出站钉住 + sse_active 计入，钉住「一条分发表服务两种传输」的分发语义定稿
    （无 transport 字段，见 api/proxy.py 注释 / 设计 §8.4 注记）。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as mc:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            async with c.stream("GET", f"{PROXY}/p/{mid}/mcp",
                                headers={**AUTH, "Accept": "text/event-stream",
                                         **SESSION}) as resp:
                assert resp.status_code == 200
                assert resp.headers["content-type"].startswith("text/event-stream")
                push = None
                async for line in sse_line_iter(resp):
                    if line.startswith("data:"):
                        push = json.loads(line[len("data:"):].strip())
                        break
                m = await mc.get(f"{PROXY}/metrics")
                assert _sse_active_gauge(m.text) == 1.0    # 推送流计入 SSE 活跃连接
        # 退出 stream 上下文 → 客户端断开 → 代理取消上游（§8.1 第 4 条）
        for _ in range(50):
            if streamable_state["get_open"] == 0:
                break
            await asyncio.sleep(0.1)
        assert streamable_state["get_open"] == 0
        m = await mc.get(f"{PROXY}/metrics")
        assert _sse_active_gauge(m.text) == 0.0
    assert push["method"] == "notifications/message"
    assert push["params"]["data"] == "push-hello"
    get_headers = streamable_state["last_get_headers"]
    assert get_headers["connection"] == "close"            # SSE 管线出站语义钉住
    assert get_headers["mcp-session-id"] == "sess-m4"      # 会话头随 GET 透传


async def test_delete_mcp_204_passthrough():
    """§8.4 DELETE /mcp 会话结束：204 原样透传，会话头透传，路径按 origin 根还原。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.delete(f"{PROXY}/p/{mid}/mcp", headers={**AUTH, **SESSION})
    assert r.status_code == 204
    assert streamable_state["last_delete_headers"]["mcp-session-id"] == "sess-m4"
    assert streamable_state["deletes"][-1]["path"] == "/mcp"
    assert streamable_state["deletes"][-1]["query"] == {}


async def test_missing_session_header_upstream_400_passthrough():
    """无会话头（mock 400）→ 上游 4xx 原样透传（§10）：状态码与错误体不改写。"""
    created = await _register_streamable()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp",
                         json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
                         headers=AUTH)                       # 缺 Mcp-Session-Id
    assert r.status_code == 400
    assert "Mcp-Session-Id" in r.text                        # mock 错误体原样


async def test_streamable_trace_body_mode_records_request_and_response(tmp_path):
    """§11.1 body 模式：Streamable POST 的 request/response body 记录（JSON-RPC
    载荷），敏感头指纹化。"""
    import json as jsonlib
    import logging

    from app import trace as trace_mod
    from app.logging_setup import flush_trace

    created = await _register_streamable()
    mid = created["mapping_id"]
    handler_target = tmp_path / "trace.log"
    logger = logging.getLogger("agent_proxy.trace")
    saved = logger.handlers
    logger.handlers = [logging.FileHandler(handler_target, encoding="utf-8")]
    trace_mod.configure("body", 64 * 1024)
    try:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            r = await c.post(f"{PROXY}/p/{mid}/mcp", json=INITIALIZE, headers=AUTH)
            assert r.status_code == 200
        # M4 终审收尾（间歇失败修复）：response trace 行写在转发管线 finally——
        # 最后一个 chunk 下发之后。客户端拿到响应时代理侧 finally 可能尚未执行，
        # 恢复 handler 后立即读文件会偶发缺 response 行（套件高负载下 3 跑 1 败，
        # 单独跑必绿）。有界轮询等 response 行落盘（20×0.1s），超时才失败。
        for _ in range(20):
            if '"phase": "response"' in handler_target.read_text(encoding="utf-8"):
                break
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("response trace 行 2s 内未落盘（转发管线 finally 未执行？）")
    finally:
        logger.handlers = saved
        flush_trace()
        trace_mod.configure("metadata", 64 * 1024)           # 恢复（集成夹具 lifespan 亦会重配）
    recs = [jsonlib.loads(x) for x in
            handler_target.read_text(encoding="utf-8").splitlines() if x.strip()]
    mine = [r for r in recs if r.get("mapping_id") == mid]
    reqs = [r for r in mine if r["phase"] == "request"]
    assert reqs and reqs[0]["url"] == "http://127.0.0.1:9903/mcp"
    # 计划缺陷最小修复：计划原稿断言 `'"method": "initialize"'`（带空格）不成立
    # ——客户端 httpx 序列化 json= 用紧凑分隔符（separators=(",", ":")），请求体
    # 为 `"method":"initialize"`（无空格）
    assert '"method":"initialize"' in reqs[0]["body"]        # 请求体记录（body 模式）
    assert "sk-mcp4-12345678" not in jsonlib.dumps(reqs[0])  # 敏感头指纹化
    req_ids = {r["request_id"] for r in reqs}
    rsps = [r for r in recs if r["phase"] == "response" and r["request_id"] in req_ids]
    assert rsps and rsps[0]["status"] == 200
    assert "serverInfo" in rsps[0]["body"]                   # 响应体记录（JSON-RPC 载荷）


async def test_streamable_auth_and_path_security_matrix():
    """权限与路径安全复用既有用例形态（§7 / §8.1 第 8 条 / §10）：无 token 401、
    非注册者 403、dot-segment 400。"""
    created = await _register_streamable(user=888)
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r401 = await c.post(f"{PROXY}/p/{mid}/mcp",
                            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        r403 = await c.post(f"{PROXY}/p/{mid}/mcp",
                            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                            headers={"Authorization": f"Bearer {make_token(999)}"})
        r400 = await c.get(f"{PROXY}/p/{mid}/%2e%2e/etc/passwd", headers=AUTH)
    assert r401.status_code == 401 and r401.json()["code"] == "INVALID_TOKEN"
    assert r403.status_code == 403 and r403.json()["code"] == "FORBIDDEN"
    assert r400.status_code == 400 and r400.json()["code"] == "INVALID_PARAM"


async def test_streamable_push_stream_trace_body_mode_records_message_events():
    """M5 扫尾 a（M2 Task 5 评审遗留）：GET /mcp 推送流走 SSE 解析管线——body 模式下
    message 事件经 trace.log_sse_event 记录（设计 §8.4 注记「推送流的 message 事件行
    在 body 模式下记录」的集成断言，M3 已实现未断言）；心跳注释行不记录；无 endpoint
    事件（Streamable 流无改写面，rewriter 字节级无操作）。"""
    import glob
    import json as jsonlib

    from app import trace as trace_mod
    from app.logging_setup import flush_trace

    created = await _register_streamable()
    mid = created["mapping_id"]
    trace_mod.configure("body", 64 * 1024)   # 进程级全局：真实服务器与测试同进程，钉住后恢复
    try:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            async with c.stream("GET", f"{PROXY}/p/{mid}/mcp",
                                headers={**AUTH, **SESSION}) as resp:
                assert resp.status_code == 200
                await read_next_message_data(resp)   # 首条推送事件读到即断开
    finally:
        flush_trace()
        trace_mod.configure("metadata", 64 * 1024)          # 恢复（集成夹具 lifespan 亦会重配）
    records = []
    for path in glob.glob("logs-test/trace.log.*"):
        with open(path, encoding="utf-8") as fh:
            records.extend(jsonlib.loads(x) for x in fh.read().splitlines() if x.strip())
    reqs = [r for r in records if r.get("mapping_id") == mid and r["phase"] == "request"]
    assert reqs and reqs[0]["url"] == "http://127.0.0.1:9903/mcp"
    assert "sk-mcp4-12345678" not in jsonlib.dumps(reqs)    # 敏感头指纹化（红线复扫）
    req_ids = {r["request_id"] for r in reqs}
    sse = [r for r in records if r["phase"] == "sse_event" and r["request_id"] in req_ids]
    assert {r["event"] for r in sse} == {"message"}         # 推送流仅 message（无 endpoint 事件）
    assert any("push-hello" in r["data"] for r in sse)      # 推送载荷已记录（§11.1）
    assert not any("ping" in (r.get("data") or "") for r in sse), "心跳注释行不记录"


async def test_probe_multiline_data_initialize_judged_failure():
    """M5 扫尾 b（已知限制回归钉）：/mcp-multiline-data 的 initialize 为多行 data
    SSE——_first_message_data 只取首行不拼接 → JSON 解析失败 → ok=false
    「非合法 JSON」（显式失败，不误判 serverInfo 成功；真实 SDK 均单行）。"""
    created = await _register_streamable(
        upstream_url="http://127.0.0.1:9903/mcp-multiline-data")
    mid = created["mapping_id"]
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{PROXY}/api/v1/mappings/{mid}/test",
                         headers={"Authorization": f"Bearer {make_token(888)}"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and "非合法 JSON" in body["detail"]
