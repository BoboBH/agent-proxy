"""直连冒烟（不经代理）：mock MCP SSE 上游 9902 协议形态可用——
endpoint 根相对路径、POST 202 + message 推回、notifications 不回、心跳。"""
import httpx

from tests.integration.mock_mcp_sse import mock_state
from tests.utils import read_first_endpoint_event, read_next_message_data, sse_line_iter

BASE = "http://127.0.0.1:9902"


async def test_sse_handshake_root_relative_endpoint():
    async with httpx.AsyncClient(timeout=httpx.Timeout(5, read=5)) as c:
        async with c.stream("GET", f"{BASE}/sse") as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            endpoint = await read_first_endpoint_event(resp)
    assert endpoint == "/messages?session_id=test123"   # 根相对路径（§8.3 场景）


async def test_messages_post_202_and_message_push_back():
    mock_state["received"].clear()
    async with httpx.AsyncClient(timeout=httpx.Timeout(5, read=5)) as c:
        async with c.stream("GET", f"{BASE}/sse") as resp:
            await read_first_endpoint_event(resp)
            r = await c.post(f"{BASE}/messages?session_id=test123",
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert r.status_code == 202
            msg = await read_next_message_data(resp)
    assert msg["id"] == 1
    assert msg["result"]["tools"][0]["name"] == "echo"
    rec = mock_state["received"][-1]
    assert rec["query"] == {"session_id": "test123"}     # session 经 URL 自持


async def test_initialize_and_tools_call_results():
    mock_state["received"].clear()
    async with httpx.AsyncClient(timeout=httpx.Timeout(5, read=5)) as c:
        async with c.stream("GET", f"{BASE}/sse") as resp:
            await read_first_endpoint_event(resp)
            r = await c.post(f"{BASE}/messages",
                             json={"jsonrpc": "2.0", "id": 2, "method": "initialize",
                                   "params": {"protocolVersion": "2025-06-18"}})
            assert r.status_code == 202
            msg = await read_next_message_data(resp)
            assert msg["result"]["serverInfo"]["name"] == "mock-mcp-sse"
            r = await c.post(f"{BASE}/messages",
                             json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                   "params": {"name": "echo", "arguments": {"text": "direct"}}})
            msg = await read_next_message_data(resp)
    assert mock_state["received"][-1]["rpc"]["params"]["arguments"]["text"] == "direct"
    assert "direct" in str(msg)                          # mock 回显闭环


async def test_notification_accepted_without_message_back():
    mock_state["received"].clear()
    async with httpx.AsyncClient(timeout=httpx.Timeout(5, read=5)) as c:
        async with c.stream("GET", f"{BASE}/sse") as resp:
            await read_first_endpoint_event(resp)
            r = await c.post(f"{BASE}/messages", json={"jsonrpc": "2.0",
                                                       "method": "notifications/initialized"})
            assert r.status_code == 202
            # 流仍活着：下一个到达的是心跳注释行（证明无 message 事件被推回）
            async for line in sse_line_iter(resp):
                if line.startswith(":"):
                    break
    assert mock_state["received"][0]["rpc"]["method"] == "notifications/initialized"
