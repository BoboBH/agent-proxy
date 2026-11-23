"""MCP SSE 全链路集成（真实 TCP）：测试客户端 → 真实 uvicorn 代理（9910）→
真实 TCP → mock MCP SSE 上游（9902）。

经代理 SSE 握手必须收到改写后的 endpoint 事件（data 以 /p/{id} 开头且含
session_id）；POST messages 经代理按上游 origin 根还原到达上游（session_id
保留、出站 header 为存储值、调用方 JWT 不透传）；initialize / tools/list /
tools/call JSON-RPC 全链路；心跳注释行透传；SSE 读超时不设（§8.1 第 5 条）。
"""
import json
import re

import httpx

from tests.integration.mock_mcp_sse import mock_state
from tests.utils import make_token, read_first_endpoint_event, read_next_message_data, sse_line_iter

PROXY = "http://127.0.0.1:9910"
UPSTREAM_BASE = "http://127.0.0.1:9902"
SSE_UPSTREAM = f"{UPSTREAM_BASE}/sse"
AUTH = {"Authorization": f"Bearer {make_token('u888')}"}
SSE_HEADERS = {**AUTH, "Accept": "text/event-stream"}
# SSE 读用宽松超时（流按心跳持续到达，读永不空转超期）
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)


async def _register_mcp(user="u888", **overrides):
    payload = {"type": "mcp", "upstream_url": SSE_UPSTREAM,
               "headers": {"Authorization": "Bearer sk-mcp-12345678"}, **overrides}
    async with httpx.AsyncClient() as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json=payload,
                            headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _post_url(endpoint_path: str) -> str:
    """endpoint 事件改写后的代理地址（根相对）→ 完整 URL。"""
    return f"{PROXY}{endpoint_path}"


def _sse_active_gauge(metrics_text: str) -> float:
    """从 /metrics 文本解析 ap_sse_active_connections 当前值（gauge 无标签单行）。"""
    m = re.search(r"^ap_sse_active_connections ([0-9.]+)$", metrics_text, re.M)
    assert m, "ap_sse_active_connections 不在 metrics 输出中"
    return float(m.group(1))


async def test_sse_handshake_endpoint_event_rewritten():
    """§8.3 核心场景：经代理 SSE 握手收到改写后的 endpoint 事件。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            assert resp.headers.get("x-accel-buffering") == "no"  # 网关关缓冲（§8.1 第 9 条）
            endpoint = await read_first_endpoint_event(resp)
    assert endpoint == f"/p/{mid}/messages?session_id=test123"
    assert endpoint.startswith(f"/p/{mid}/")            # 改写为代理地址（§8.3）


async def test_initialize_roundtrip_via_proxy():
    """initialize JSON-RPC 全链路：POST 经代理 origin 根还原到上游，结果经 SSE 推回。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    mock_state["received"].clear()
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS) as resp:
            endpoint = await read_first_endpoint_event(resp)
            r = await c.post(_post_url(endpoint), json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "m3-test", "version": "0"}}},
                headers=AUTH)
            assert r.status_code == 202
            msg = await read_next_message_data(resp)
    assert msg["result"]["serverInfo"]["name"] == "mock-mcp-sse"
    rec = mock_state["received"][-1]
    assert rec["query"] == {"session_id": "test123"}     # session 经 URL 自持还原
    # 出站 header 重建（§8.1 第 1 条）：上游收到存储值，调用方 JWT 不透传
    assert rec["headers"]["authorization"] == "Bearer sk-mcp-12345678"
    assert not any(v.startswith("stub.") for v in rec["headers"].values())


async def test_tools_list_roundtrip():
    """tools/list JSON-RPC 全链路（notifications/initialized 无 id 不回消息）。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS) as resp:
            endpoint = await read_first_endpoint_event(resp)
            r = await c.post(_post_url(endpoint),
                             json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                             headers=AUTH)
            assert r.status_code == 202
            r = await c.post(_post_url(endpoint),
                             json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                             headers=AUTH)
            assert r.status_code == 202
            msg = await read_next_message_data(resp)
    assert msg["id"] == 2
    tools = msg["result"]["tools"]
    assert tools and tools[0]["name"] == "echo"


async def test_tools_call_roundtrip_echo():
    """tools/call JSON-RPC 全链路：arguments 经上游回显后从 SSE 流读回。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS) as resp:
            endpoint = await read_first_endpoint_event(resp)
            r = await c.post(_post_url(endpoint),
                             json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                   "params": {"name": "echo", "arguments": {"text": "hello-m3"}}},
                             headers=AUTH)
            assert r.status_code == 202
            msg = await read_next_message_data(resp)
    assert "hello-m3" in json.dumps(msg["result"])


async def test_heartbeat_comment_passthrough():
    """心跳注释行字节级透传（§8.3）：endpoint 事件后继续读应见 ': ping'。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS) as resp:
            await read_first_endpoint_event(resp)
            saw = False
            # 计划缺陷最小修复：原稿在 read_first_endpoint_event 之后再次调用
            # resp.aiter_lines()——httpx 0.28 首次迭代即置 is_stream_consumed，
            # 二次调用抛 StreamConsumed（同因 utils.sse_line_iter 已存在），
            # 必须复用同一迭代器（tests.utils.sse_line_iter）
            async for line in sse_line_iter(resp):
                if line.startswith(": ping"):
                    saw = True
                    break
    assert saw


async def test_unknown_path_origin_root_restore_passthrough():
    """§8.3 路径分发第 2 行：其他路径按上游 origin 根还原（/p/{id}/nowhere → 9902/nowhere）。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/nowhere", headers=AUTH)
    assert r.status_code == 404                          # 到达 mock（其 FastAPI 404 形态）
    assert r.json()["detail"] == "Not Found"             # 确证还原到 origin 根而非注册端点


async def test_post_registered_endpoint_maps_405_passthrough():
    """分发语义：非 GET/HEAD 到注册端点路径走 origin 根还原（POST /sse → mock 405 原样透传）。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/sse", json={"a": 1},
                         headers={**AUTH, "Content-Type": "application/json"})
    assert r.status_code == 405                          # mock 的 GET-only 路由


class _TimeoutCaptureClient:
    """捕获 build_request(timeout=...) 的替身 http_client（§8.1 第 5 条：SSE 读超时不设）。"""

    def __init__(self):
        self.timeouts = []

    def build_request(self, method, url, headers=None, content=None, timeout=None):
        self.timeouts.append(timeout)
        return httpx.Request(method, url, headers=headers, content=content)

    async def send(self, request, stream=False):
        async def body():
            yield b"event: endpoint\ndata: /messages?session_id=t\n\n"

        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              content=body())

    async def aclose(self):
        pass


async def test_sse_request_has_no_read_timeout(real_proxy_app):
    """§8.1 第 5 条超时表：SSE 长连接 read=None（依赖心跳保活），connect/pool 沿用配置。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    fake = _TimeoutCaptureClient()
    real = real_proxy_app.state.http_client
    real_proxy_app.state.http_client = fake  # 真实服务器线程逐请求读取 state，换装安全
    try:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS) as resp:
                endpoint = await read_first_endpoint_event(resp)
    finally:
        real_proxy_app.state.http_client = real
    assert endpoint == f"/p/{mid}/messages?session_id=t"
    assert isinstance(fake.timeouts[0], httpx.Timeout)
    assert fake.timeouts[0].read is None
    assert fake.timeouts[0].connect == real_proxy_app.state.settings.upstream_connect_timeout


async def test_proxy_metrics_type_mcp():
    """§15.2 type 标签：mcp 转发的 ap_requests_total 标签 type="mcp"。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/nowhere", headers=AUTH)
        assert r.status_code == 404
        m = await c.get(f"{PROXY}/metrics")
    assert 'route="proxy",type="mcp"' in m.text


async def test_sse_same_origin_redirect_aborted_502():
    """评审 Issue 1：注册端点上游回同源 30x——Location 含注册上游真实 origin，
    不得回传调用方：中止回 502/TOO_MANY_REDIRECTS 且响应无 location 头（§8.1 第 7 条）。"""
    created = await _register_mcp(upstream_url=f"{UPSTREAM_BASE}/sse-redirect-same")
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        # 调用注册端点路径本身（§8.3：非注册路径会被 origin 根还原到别处）
        r = await c.get(f"{PROXY}/p/{mid}/sse-redirect-same", headers=AUTH)
    assert r.status_code == 502
    assert r.json()["code"] == "TOO_MANY_REDIRECTS"
    assert "location" not in r.headers                   # 真实 origin 绝不外泄


async def test_sse_cross_origin_redirect_passthrough():
    """评审 Issue 1 对照面：跨源 30x 属上游自身行为，原样透传（status/location 保留）。"""
    created = await _register_mcp(upstream_url=f"{UPSTREAM_BASE}/sse-redirect-cross")
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/sse-redirect-cross", headers=AUTH)
    assert r.status_code == 307
    assert r.headers["location"] == "http://127.0.0.1:9901/echo-target"


async def test_non_sse_upstream_error_plain_passthrough_no_sse_active():
    """评审 Issue 7：注册端点上游返回非 SSE（503 html）——原样透传（不改写、
    不改状态码）且 sse_active 不计（gauge 前后不变）。"""
    created = await _register_mcp(upstream_url=f"{UPSTREAM_BASE}/sse-503")
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        m0 = await c.get(f"{PROXY}/metrics")
        r = await c.get(f"{PROXY}/p/{mid}/sse-503", headers=AUTH)
        m1 = await c.get(f"{PROXY}/metrics")
    assert r.status_code == 503                          # 上游状态码原样
    assert r.headers["content-type"].startswith("text/html")
    assert "upstream-503-html" in r.text                 # 错误体原样（无任何改写痕迹）
    assert _sse_active_gauge(m0.text) == _sse_active_gauge(m1.text)


async def test_root_registered_endpoint_dispatches_sse_pipeline():
    """评审 Issue 2：裸 origin 注册（端点路径 /）时根路径 /p/{id} 同为注册端点——
    必须走 SSE 管线改写 endpoint（不得被 origin 根还原绕过改写直达上游）。"""
    created = await _register_mcp(upstream_url=UPSTREAM_BASE)
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("GET", f"{PROXY}/p/{mid}", headers=SSE_HEADERS) as resp:
            assert resp.status_code == 200
            endpoint = await read_first_endpoint_event(resp)
    assert endpoint.startswith(f"/p/{mid}/")             # 改写发生（修复前为原样透传）
    assert "session_id=test123" in endpoint


async def test_head_registered_endpoint_dispatches_sse_branch():
    """§8.3 分发表第 1 行含 HEAD：HEAD 到注册端点路径同样走 SSE 初始连接分支。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.head(f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
