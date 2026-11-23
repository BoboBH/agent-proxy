"""端到端代理测试（真实 TCP）：注册 → /p/{id}/... 转发 → echo 上游回显验证。

链路：测试 client（ASGITransport）→ 代理 app → 真实 TCP → echo 上游（uvicorn 9901）。
上游地址含 SSRF_ALLOW_PRIVATE=true 放行的 127.0.0.1（测试环境既定）。
"""
import re

import httpx
import pytest

from tests.utils import make_token

UPSTREAM = "http://127.0.0.1:9901/api/v1"
BODY = {"type": "http", "upstream_url": UPSTREAM,
        "headers": {"Authorization": "Bearer sk-real-12345678",
                    "X-API-Key": "stored-key-0000"}}


async def _register(client, user="u888", **overrides):
    payload = {**BODY, **overrides}
    resp = await client.post("/api/v1/mappings", json=payload,
                             headers={"Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _call(client, mapping_id, method, path, *, user="u888", headers=None, **kw):
    hdrs = {"Authorization": f"Bearer {make_token(user)}", **(headers or {})}
    return await client.request(method, f"/p/{mapping_id}{path}", headers=hdrs, **kw)


def _hdr(headers: dict, name: str) -> str | None:
    """按头名小写不敏感取值（echo 经 ASGI 边界回显为小写，不依赖线上大小写）。"""
    lowered = name.lower()
    return next((v for k, v in headers.items() if k.lower() == lowered), None)


async def test_forward_get_echoes_stored_headers_not_caller(client):
    created = await _register(client)
    mid = created["mapping_id"]
    # 计划缺陷最小修复：原稿传 "Bearer caller-jwt-not-forwarded" 会顶掉 _call 的鉴权
    # token（headers 合并 Authorization 后写覆盖）→ 代理 401。真实语义：调用方 JWT 仅
    # 用于代理鉴权，出站被存储值替换——由下方 authorization==存储值 与
    # "stub." not in resp.text 两条断言共同钉住。
    resp = await _call(client, mid, "GET", "/orders?status=paid&page=2",
                       headers={"Authorization": f"Bearer {make_token('u888')}",
                                "X-Caller-Only": "should-not-leak",
                                "Accept": "application/json"})
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "GET" and echo["path"] == "/orders"
    assert echo["query"] == {"status": "paid", "page": "2"}
    sent = echo["headers"]
    assert _hdr(sent, "authorization") == "Bearer sk-real-12345678"  # 存储还原（调用方 JWT 被替换）
    assert _hdr(sent, "x-api-key") == "stored-key-0000"
    assert _hdr(sent, "x-caller-only") is None                       # 调用方非白名单 header 不透传
    assert _hdr(sent, "accept") == "application/json"                # 白名单透传
    assert "stub." not in resp.text                                  # 调用方 JWT 绝不到上游
    assert "${PX:" not in resp.text                                  # 占位符绝不到上游


async def test_forward_root_path_hits_registered_url(client):
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "")
    assert resp.status_code == 200
    assert resp.json()["path"] == "/"  # upstream_url 直达（path 可为空，设计 §6.2）


async def test_forward_post_body_and_content_type(client):
    created = await _register(client)
    mid = created["mapping_id"]
    resp = await _call(client, mid, "POST", "/orders",
                       headers={"Content-Type": "application/json"},
                       content=b'{"item":"book","qty":2}')
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "POST"
    # 计划缺陷最小修复：'{"item":"book","qty":2}' 实为 23 字节（原稿误写 22）
    assert echo["body"] == '{"item":"book","qty":2}' and echo["body_bytes"] == 23
    assert _hdr(echo["headers"], "content-type") == "application/json"
    # 出站无重复 content-type 行（评审补充）：headers_multi 保留逐行原始对，
    # 存储（Authorization/X-API-Key）与 caller Content-Type 归一后必须合并为一行
    ct_lines = [k for k, _v in echo["headers_multi"] if k.lower() == "content-type"]
    assert len(ct_lines) == 1, f"出站 content-type 应恰 1 行，实际 {ct_lines}"


async def test_forward_deep_path(client):
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/orders/42/items?limit=5")
    echo = resp.json()
    assert echo["path"] == "/orders/42/items" and echo["query"] == {"limit": "5"}


async def test_forward_upstream_404_passthrough(client):
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/status/404")
    assert resp.status_code == 404                      # 上游 4xx 原样透传（设计 §10）
    assert "upstream-status-404" in resp.text
    assert resp.headers["content-type"].startswith("text/plain")
    assert resp.headers["x-request-id"]                 # 代理自身中间件仍在


async def test_proxy_unauthenticated_401(client):
    created = await _register(client)
    resp = await client.get(f"/p/{created['mapping_id']}/orders")
    assert resp.status_code == 401 and resp.json()["code"] == "INVALID_TOKEN"


async def test_non_owner_private_403(client):
    created = await _register(client, user="u888")
    resp = await _call(client, created["mapping_id"], "GET", "/orders", user="u999")
    assert resp.status_code == 403 and resp.json()["code"] == "FORBIDDEN"


async def test_missing_mapping_404(client):
    resp = await _call(client, "aB3xK9mQ2wR4", "GET", "/orders")
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_disabled_mapping_404(client):
    created = await _register(client)
    mid = created["mapping_id"]
    resp = await client.put(f"/api/v1/mappings/{mid}", json={"status": "disabled"},
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
    assert resp.status_code == 200
    resp = await _call(client, mid, "GET", "/orders")
    assert resp.status_code == 404 and resp.json()["code"] == "MAPPING_NOT_FOUND"


async def test_mcp_mapping_forward_400(client):
    created = await _register(client, type="mcp", upstream_url="https://mcp.ex.com/sse")
    resp = await _call(client, created["mapping_id"], "GET", "/sse")
    assert resp.status_code == 400 and "M3" in resp.json()["message"]


async def test_dot_segment_sub_path_400(client):
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/%2e%2e/etc/passwd")
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_dot_segment_encoded_slash_composite_400(client):
    """Task 3 复合逃逸修复的运行时回归：`..%252f` 经边界一次解码为 `..%2f`，
    再经上游解码深度两层得 `../..`，逐组件判定必须 400（线上真实逃逸变体）。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/..%252f..")
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_proxy_trace_metadata_wired(client, monkeypatch, tmp_path):
    """metadata 模式下 /p/ 转发写 trace request/response 行（url 含上游 target）。

    计划缺陷最小修复：设计 §11.1 的 response 行只带 request_id（不带 mapping_id，
    request_id 是回放关联键），故 response 行按 request 行的 request_id 关联筛选。
    """
    import json as jsonlib
    import logging

    from agent_proxy.logging_setup import flush_trace
    import agent_proxy.trace as trace_mod

    handler_target = tmp_path / "trace.log"
    logger = logging.getLogger("agent_proxy.trace")
    saved = logger.handlers
    logger.handlers = [logging.FileHandler(handler_target, encoding="utf-8")]
    try:
        created = await _register(client)
        resp = await _call(client, created["mapping_id"], "GET", "/orders?status=paid")
        assert resp.status_code == 200
        flush_trace()
        recs = [jsonlib.loads(x) for x in
                handler_target.read_text(encoding="utf-8").splitlines() if x.strip()]
    finally:
        logger.handlers = saved
    mine = [r for r in recs if r.get("mapping_id") == created["mapping_id"]]
    req = [r for r in mine if r["phase"] == "request"]
    req_ids = {r["request_id"] for r in req}
    rsp = [r for r in recs if r["phase"] == "response" and r["request_id"] in req_ids]
    assert req and rsp
    assert re.match(r"http://127\.0\.0\.1:9901/api/v1/orders\?status=", req[0]["url"])
    assert "sk-real-12345678" not in jsonlib.dumps(req[0])  # 指纹化
    assert rsp[0]["status"] == 200


# ---------- 评审修复回归（真流式 / 流中断观测） ----------


class _RecordingResponse(httpx.Response):
    """记录 aread() 是否被调用的替身响应（真流式判定：send 后 body 不应被整读）。"""

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.aread_called = False

    async def aread(self):
        self.aread_called = True
        return await super().aread()


class _FakeStreamClient:
    """替身 http_client：记录 send(stream=...) 调用形态（Critical 假流式检测器）。"""

    def __init__(self):
        self.sent_stream = None
        self.response = None

    def build_request(self, method, url, headers=None, content=None):
        return httpx.Request(method, url, headers=headers, content=content)

    async def send(self, request, stream=False):
        self.sent_stream = stream

        async def _body():
            yield b"hello-stream"

        # content 必须是 async 迭代器：httpx 禁止对 sync stream 做 async aclose
        self.response = _RecordingResponse(
            200, headers={"content-type": "text/plain"}, content=_body())
        return self.response

    async def aclose(self):
        pass  # lifespan 停机保险（正常路径在 finally 换回真 client，走不到）


async def test_forward_uses_true_streaming_send(client, app):
    """Critical 回归：必须 send(stream=True)。client.request 内部 send(stream=False)
    会 aread() 把上游响应体整体读进内存——假流式：大文件 OOM、M3 SSE 永不 EOF；
    且响应构建完成时 body 未被整读（aread 未调用），body 经流式完整回传。"""
    created = await _register(client)
    mid = created["mapping_id"]
    fake = _FakeStreamClient()
    real = app.state.http_client
    app.state.http_client = fake  # 手动换装（不用 monkeypatch：State 存于 _state，
    try:                          # pytest undo 会 delattr 掉键，致 lifespan 停机 AttributeError）
        resp = await _call(client, mid, "GET", "/orders")
    finally:
        app.state.http_client = real
    assert resp.status_code == 200
    assert fake.sent_stream is True              # 真流式：send(stream=True)
    assert fake.response.aread_called is False   # 响应体未整体读进内存
    assert b"hello-stream" in resp.content       # body 经 StreamingResponse 完整回传


async def test_stream_broken_is_observable(client, app):
    """流中断可观测（评审 Important 项，设计 §10）：upstream_errors code=stream_broken
    计数 + log.exception；不写误导性的 status=200 response trace 行。"""
    from agent_proxy import metrics as metrics_mod

    class _BrokenOnceResponse(httpx.Response):
        async def aiter_bytes(self, chunk_size=None):
            yield b"partial-body"
            raise httpx.ReadError("connection reset mid-stream")

    class _FakeBrokenClient:
        def build_request(self, method, url, headers=None, content=None):
            return httpx.Request(method, url, headers=headers, content=content)

        async def send(self, request, stream=False):
            async def _partial():
                yield b"seed"  # async 流：aclose 合法（本用例 override 了 aiter_bytes）

            return _BrokenOnceResponse(200, headers={"content-type": "text/plain"},
                                       content=_partial())

        async def aclose(self):
            pass  # lifespan 停机保险（正常路径在 finally 换回真 client，走不到）

    before = metrics_mod.upstream_errors_total.labels(
        type="http", code="stream_broken")._value.get()
    fake = _FakeBrokenClient()
    real = app.state.http_client
    app.state.http_client = fake
    created = await _register(client)
    mid = created["mapping_id"]
    try:
        # 不对传输层传播语义做断言：ASGITransport 会缓冲整个响应体（异常在
        # 中间件/传输层被吞，客户端拿到 partial body）；生产 httpcore 真连接下
        # 表现为连接截断——可观测计数才是本用例重点
        await _call(client, mid, "GET", "/orders")
    finally:
        app.state.http_client = real
    after = metrics_mod.upstream_errors_total.labels(
        type="http", code="stream_broken")._value.get()
    assert after == before + 1
