"""MCP SSE 全链路集成（真实 TCP）：测试客户端 → 真实 uvicorn 代理（9910）→
真实 TCP → mock MCP SSE 上游（9902）。

经代理 SSE 握手必须收到改写后的 endpoint 事件（data 以 /p/{id} 开头且含
session_id）；POST messages 经代理按上游 origin 根还原到达上游（session_id
保留、出站 header 为存储值、调用方 JWT 不透传）；initialize / tools/list /
tools/call JSON-RPC 全链路；心跳注释行透传；SSE 读超时不设（§8.1 第 5 条）。
"""
import asyncio
import glob
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


# ---------- 第二批：权限 / 路径安全 / 可观测 / 客户端断开取消（§8.1 第 4 条 / §8.3） ----------


async def test_non_owner_mcp_403():
    """private mcp 映射仅注册者可调（§7/§14.2 语义）。"""
    created = await _register_mcp(user="u888")
    mid = created["mapping_id"]
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{PROXY}/p/{mid}/sse",
                        headers={"Authorization": f"Bearer {make_token('u999')}",
                                 "Accept": "text/event-stream"})
    assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN"


async def test_mcp_unauthenticated_401():
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{PROXY}/p/{mid}/sse", headers={"Accept": "text/event-stream"})
    assert r.status_code == 401 and r.json()["code"] == "INVALID_TOKEN"


async def test_mcp_dot_segment_400():
    """§8.1 第 8 条：mcp 子路径同样拒绝 dot-segment（含 URL 编码变体）。"""
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{PROXY}/p/{mid}/%2e%2e/etc/passwd",
                        headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert r.status_code == 400 and r.json()["code"] == "INVALID_PARAM"


async def _sse_active_gauge_http(c) -> float:
    """经 /metrics 取 ap_sse_active_connections 当前值。

    （计划原稿名 _sse_active_gauge，与本文件第一批已有的文本解析 helper 同名，
    模块级重定义会遮蔽既有 test_non_sse_upstream_error_plain_passthrough_no_sse_active
    所用版本——改名并复用既有解析器，语义不变。）
    """
    m = await c.get(f"{PROXY}/metrics")
    return _sse_active_gauge(m.text)


async def test_client_disconnect_cancels_upstream_sse():
    """客户端断开→代理取消上游（§8.1 第 4 条 + §8.3），端到端真实 TCP。

    链路：客户端 FIN → uvicorn 取消 StreamingResponse 生成器 → 代理侧
    upstream_resp.aclose() → 上游 mock 检测断开（/_connections sse_open 归零）；
    期间 ap_sse_active_connections 应为 1.0，断开后归 0.0。
    """
    created = await _register_mcp()
    mid = created["mapping_id"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as mc:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS) as resp:
                endpoint = await read_first_endpoint_event(resp)
                assert endpoint.startswith(f"/p/{mid}/")
                assert await _sse_active_gauge_http(mc) == 1.0
                conns = (await mc.get(f"{UPSTREAM_BASE}/_connections")).json()
                assert conns["sse_open"] == 1
            # 退出 stream 上下文 → 客户端断开（真实 TCP FIN）
        conns = {"sse_open": -1}
        for _ in range(50):                     # 最多等 5s（取消传播 + mock finally 执行）
            conns = (await mc.get(f"{UPSTREAM_BASE}/_connections")).json()
            if conns["sse_open"] == 0:
                break
            await asyncio.sleep(0.1)
        assert conns["sse_open"] == 0, "客户端断开后上游 SSE 连接应被取消（sse_open 归零）"
        assert await _sse_active_gauge_http(mc) == 0.0


async def test_sse_trace_metadata_lines(tmp_path):
    """metadata 模式：SSE 转发写 request/response 行（url 为上游注册端点，header 指纹化）。"""
    import json as jsonlib
    import logging

    from agent_proxy.logging_setup import flush_trace

    created = await _register_mcp()
    mid = created["mapping_id"]
    handler_target = tmp_path / "trace.log"
    logger = logging.getLogger("agent_proxy.trace")
    saved = logger.handlers
    logger.handlers = [logging.FileHandler(handler_target, encoding="utf-8")]
    try:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS) as resp:
                await read_first_endpoint_event(resp)
    finally:
        logger.handlers = saved
    flush_trace()
    recs = [jsonlib.loads(x) for x in
            handler_target.read_text(encoding="utf-8").splitlines() if x.strip()]
    mine = [r for r in recs if r.get("mapping_id") == mid]
    reqs = [r for r in mine if r["phase"] == "request"]
    # 计划缺陷最小修复：设计 §11.1 的 response 行只有 request_id（无 mapping_id），
    # 从 mine 筛 response 必得空集——按 request 行的 request_id 关联
    # （test_proxy_trace.py 已有同款适配注释）
    req_ids = {r["request_id"] for r in reqs}
    rsps = [r for r in recs if r["phase"] == "response" and r["request_id"] in req_ids]
    assert reqs and rsps
    assert reqs[0]["url"] == "http://127.0.0.1:9902/sse"
    assert "sk-mcp-12345678" not in jsonlib.dumps(reqs[0])   # header 指纹化
    assert rsps[0]["status"] == 200                          # 连接建立记录（time-to-headers）
    assert not [r for r in mine if r["phase"] == "sse_event"], "metadata 模式不记 SSE 事件"


async def test_sse_trace_body_mode_endpoint_and_message():
    """body 模式（§11.1）：endpoint 改写前 + 改写后 + message 事件记录；心跳不记。"""
    import json as jsonlib

    from agent_proxy import trace as trace_mod
    from agent_proxy.logging_setup import flush_trace

    created = await _register_mcp()
    mid = created["mapping_id"]
    trace_mod.configure("body", 64 * 1024)  # 进程级全局：真实服务器与测试同进程，钉住后恢复
    try:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=SSE_HEADERS) as resp:
                endpoint = await read_first_endpoint_event(resp)
                r = await c.post(f"{PROXY}{endpoint}",
                                 json={"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                       "params": {"name": "echo", "arguments": {"text": "tr"}}},
                                 headers=AUTH)
                assert r.status_code == 202
                await read_next_message_data(resp)
    finally:
        flush_trace()
        trace_mod.configure("metadata", 64 * 1024)  # 恢复（集成夹具 lifespan 亦会重配）
    records = []
    for path in glob.glob("logs-test/trace.log.*"):
        with open(path, encoding="utf-8") as fh:
            records.extend(jsonlib.loads(x) for x in fh.read().splitlines() if x.strip())
    mine = [r for r in records if r.get("mapping_id") == mid]
    # 计划缺陷最小修复：设计 §11.1 的 response/sse_event 行只有 request_id（无
    # mapping_id），按 mapping_id 筛 sse_event 必得空集——按 request 行的
    # request_id 关联（test_proxy_trace.py 已有同款适配注释）
    req_ids = {r["request_id"] for r in mine if r["phase"] == "request"}
    mine += [r for r in records if r["phase"] in ("response", "sse_event")
             and r["request_id"] in req_ids]
    sse = [r for r in mine if r["phase"] == "sse_event"]
    events = {r["event"] for r in sse}
    assert {"endpoint", "endpoint_rewritten", "message"} <= events
    before = next(r["data"] for r in sse if r["event"] == "endpoint")
    after = next(r["data"] for r in sse if r["event"] == "endpoint_rewritten")
    assert before == "/messages?session_id=test123"          # 改写前（上游原值）
    assert after == f"/p/{mid}/messages?session_id=test123"  # 改写后（代理地址）
    messages = [r for r in sse if r["event"] == "message"]
    assert any('"id": 4' in r["data"] for r in messages)     # tools/call 的 JSON-RPC 响应
    assert not any("ping" in (r.get("data") or "") for r in sse), "心跳注释行不记录"
    assert "sk-mcp-12345678" not in jsonlib.dumps(mine)      # 敏感头仍指纹化
