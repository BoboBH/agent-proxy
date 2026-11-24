"""mock MCP Streamable 上游直连冒烟（真实 TCP 127.0.0.1:9903）：不经代理先钉住
mock 自身协议形态，代理链路测试（test_proxy_mcp_streamable.py）才有可信参照。"""
import json

import httpx

from tests.integration.mock_mcp_streamable import streamable_state

BASE = "http://127.0.0.1:9903"
SESSION = {"Mcp-Session-Id": "sess-m4"}


async def test_post_initialize_returns_json_and_session_header():
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{BASE}/mcp",
                         json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": "2025-06-18"}})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["mcp-session-id"] == "sess-m4"
    assert r.json()["result"]["serverInfo"]["name"] == "mock-mcp-streamable"


async def test_post_without_session_rejected_400():
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{BASE}/mcp",
                         json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert r.status_code == 400


async def test_post_notification_returns_202():
    # notifications 无 id：202 无响应体（MCP Streamable 规范形态，mock 钉住）
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{BASE}/mcp",
                         json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                         headers=SESSION)
    assert r.status_code == 202


async def test_post_tools_call_sse_form_short_stream():
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{BASE}/mcp?form=sse",
                         json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                               "params": {"name": "echo", "arguments": {"text": "hi"}}},
                         headers=SESSION)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    data_lines = [x for x in r.text.splitlines() if x.startswith("data:")]
    assert len(data_lines) == 1                      # 短流：单条 message 后 EOF
    msg = json.loads(data_lines[0][len("data:"):].strip())
    assert msg["id"] == 3 and "hi" in json.dumps(msg["result"])


async def test_get_mcp_push_stream_first_event_then_heartbeat():
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5, read=5, write=5, pool=5)) as c:
        async with c.stream("GET", f"{BASE}/mcp",
                            headers={**SESSION, "Accept": "text/event-stream"}) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            saw_push, saw_ping = False, False
            async for line in resp.aiter_lines():
                if line.startswith("data:"):
                    push = json.loads(line[len("data:"):].strip())
                    assert push["method"] == "notifications/message"
                    assert push["params"]["data"] == "push-hello"
                    saw_push = True
                if line.startswith(": ping"):
                    saw_ping = True
                if saw_push and saw_ping:
                    break
            assert saw_push and saw_ping
    assert streamable_state["get_open"] == 0         # 客户端断开 → mock 生成器 finally 执行


async def test_delete_mcp_204():
    async with httpx.AsyncClient() as c:
        r = await c.delete(f"{BASE}/mcp", headers=SESSION)
    assert r.status_code == 204
