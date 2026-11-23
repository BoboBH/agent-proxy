"""端到端代理测试（真实 TCP）：注册 → /p/{id}/... 转发 → echo 上游回显验证。

链路：测试 client（ASGITransport）→ 代理 app → 真实 TCP → echo 上游（uvicorn 9901）。
上游地址含 SSRF_ALLOW_PRIVATE=true 放行的 127.0.0.1（测试环境既定）。
"""
import re
from contextlib import asynccontextmanager

import httpx

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
    """替身 http_client：记录 send(stream=...) 调用形态（Critical 假流式检测器）。

    responses 可选逐跳脚本 [(status, headers), ...]：默认单跳 200（首跳用例）；
    重定向链用例传两跳脚本（302 同源 → 200），验证跟随跳仍真流式（评审 Critical）。
    """

    def __init__(self, responses=None):
        self.sent_streams = []   # 每跳 send(stream=...) 实参（按跳记录）
        self.sent_stream = None  # 兼容既有首跳断言（最后一跳值）
        self.sent_urls = []      # 每跳请求 URL（按跳记录）
        self.response = None
        self._responses = list(responses) if responses else [
            (200, {"content-type": "text/plain"})]
        self._calls = 0

    def build_request(self, method, url, headers=None, content=None):
        return httpx.Request(method, url, headers=headers, content=content)

    async def send(self, request, stream=False):
        self.sent_streams.append(stream)
        self.sent_stream = stream
        self.sent_urls.append(str(request.url))

        async def _body():
            yield b"hello-stream"

        status, headers = self._responses[min(self._calls, len(self._responses) - 1)]
        self._calls += 1
        # content 必须是 async 迭代器：httpx 禁止对 sync stream 做 async aclose
        self.response = _RecordingResponse(status, headers=headers, content=_body())
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


async def test_forward_redirect_chain_keeps_true_streaming(client, app):
    """Critical 回归（评审修复）：同源重定向跟随跳也必须 build_request+send(stream=True)——
    跳间用 client.request 会在 _response_stream 前 aread() 整体缓冲，正是 Task 5 修掉的
    假流式在跟随路径复活。断言两跳均 stream=True、aread 未调用、body 完整回传。"""
    created = await _register(client)
    mid = created["mapping_id"]
    fake = _FakeStreamClient([
        (302, {"location": "/api/v1/final?via=redirect"}),  # 同源首跳（重定向）
        (200, {"content-type": "text/plain"}),              # 跟随跳
    ])
    real = app.state.http_client
    app.state.http_client = fake
    try:
        resp = await _call(client, mid, "GET", "/orders")
    finally:
        app.state.http_client = real
    assert resp.status_code == 200
    assert fake.sent_streams == [True, True]    # 两跳均真流式（含跟随跳）
    assert fake.sent_urls[-1].endswith("/api/v1/final?via=redirect")  # 同源跟随发生
    assert fake.response.aread_called is False  # 末跳响应体未被整体读进内存
    assert b"hello-stream" in resp.content      # body 经 StreamingResponse 完整回传


async def test_stream_broken_is_observable(client, app, tmp_path):
    """流中断可观测（评审 Important 项，设计 §10）：upstream_errors code=stream_broken
    计数 + log.exception；trace 行为钉住（M2 遗留债务 2）——request 行在，
    不写误导性的 status=200 response 行。"""
    import json as jsonlib
    import logging

    from agent_proxy import metrics as metrics_mod
    from agent_proxy.logging_setup import flush_trace

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

    handler_target = tmp_path / "trace.log"
    logger = logging.getLogger("agent_proxy.trace")
    saved = logger.handlers
    logger.handlers = [logging.FileHandler(handler_target, encoding="utf-8")]
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
        logger.handlers = saved
    after = metrics_mod.upstream_errors_total.labels(
        type="http", code="stream_broken")._value.get()
    assert after == before + 1
    flush_trace()
    recs = [jsonlib.loads(x) for x in
            handler_target.read_text(encoding="utf-8").splitlines() if x.strip()]
    mine = [r for r in recs if r.get("mapping_id") == mid]
    assert [r for r in mine if r["phase"] == "request"], "中断的请求应有 request 行"
    assert not [r for r in mine if r["phase"] == "response"], \
        "流中断不应写误导性的 status=200 response 行"


# ---------- 第二批：重定向 / 大响应流式 / 413 / 连接池 / 502 / 504 ----------


async def test_same_origin_redirect_followed_internally(client):
    """同源 302：代理内部跟随，存储 header 每跳重放；同源 Location 永不回传（§8.1 第 7 条）。"""
    created = await _register(client)
    mid = created["mapping_id"]
    resp = await _call(client, mid, "GET", "/redirect/same-origin")
    assert resp.status_code == 200                                   # 内部跟随完成
    echo = resp.json()
    assert echo["path"] == "/final" and echo["query"] == {"via": "redirect"}
    assert _hdr(echo["headers"], "authorization") == "Bearer sk-real-12345678"  # 每跳重放
    assert "location" not in {k.lower() for k in resp.headers.keys()}


async def test_same_origin_307_post_keeps_method(client):
    """307 保方法（body 不重放为 M2 已知限制：首跳已流式消耗，断言只看方法与路径）。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "POST", "/redirect/307",
                       headers={"Content-Type": "application/json"}, content=b'{"a":1}')
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "POST" and echo["path"] == "/final"


async def test_same_origin_303_post_downgrades_to_get(client):
    """303 → GET（载荷类方法降级，设计 §8.1 第 7 条；307 保方法对照见上一用例）。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "POST", "/redirect/303",
                       headers={"Content-Type": "application/json"}, content=b'{"a":1}')
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "GET" and echo["path"] == "/final"


async def test_malformed_redirect_location_maps_502(client):
    """畸形 Location（"port" 非法端口 → httpx InvalidURL）：解析兜底——先关流再映射
    502 UPSTREAM_ERROR（评审 Important 3 资源卫生；此前该异常逃逸为 500）。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/redirect/bad-location")
    assert resp.status_code == 502 and resp.json()["code"] == "UPSTREAM_ERROR"


async def test_cross_origin_redirect_passthrough(client):
    """跨源 302（→9902 不存在端口）：不跟随原样透传；若被跟随会得到 502 而非 302。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/redirect/cross-origin")
    assert resp.status_code == 302
    assert "127.0.0.1:9902" in resp.headers["location"]


async def test_redirect_loop_stops_at_limit(client):
    """超过 UPSTREAM_MAX_REDIRECTS(默认 3) 仍是同源重定向 → 502 TOO_MANY_REDIRECTS
    中止（评审 Important 2：§8.1 第 7 条「同源 Location 永不回传」——透传会把绝对
    Location 暴露的注册上游 origin 泄给 Agent）；跨源重定向不在此列，保持透传。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/redirect/loop")
    assert resp.status_code == 502 and resp.json()["code"] == "TOO_MANY_REDIRECTS"
    assert "location" not in {k.lower() for k in resp.headers.keys()}  # 同源 Location 不回传
    assert "127.0.0.1:9901" not in resp.text                           # 注册上游 origin 不泄露


async def test_redirect_hop_dot_segment_400(client):
    """Task 3 评审携带项：Location 派生的跳路径与基本路径同有 dot-segment/编码斜杠
    逃逸暴露——同源跳路径必须重过 assert_safe_sub_path（跟随跳 → 400 而非 200）。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/redirect/unsafe")
    assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_request_body_over_limit_413(client):
    """流式计数超限立即 413（conftest MAX_BODY_SIZE=1MB；响应未开始，标准错误体）。"""
    created = await _register(client)
    big = b"x" * (1024 * 1024 + 1024)
    resp = await _call(client, created["mapping_id"], "POST", "/orders",
                       headers={"Content-Type": "application/octet-stream"}, content=big)
    assert resp.status_code == 413 and resp.json()["code"] == "BODY_TOO_LARGE"


async def test_large_response_streamed_intact(client):
    """8MB 响应经代理逐块回传，字节级完整（不整体驻留：转发层为 aiter_bytes 逐块 yield）。"""
    created = await _register(client)
    resp = await _call(client, created["mapping_id"], "GET", "/big?kb=8192")
    assert resp.status_code == 200
    size = 8192 * 1024
    pattern = bytes(range(256))
    expected = (pattern * (size // len(pattern) + 1))[:size]
    assert resp.content == expected


@asynccontextmanager
async def _dedicated_app_client(**env_overrides):
    """专用 app（独立 Settings 覆盖）+ 其测试 client——超时/池上限类用例专用，用毕即弃。"""
    import os

    from agent_proxy.config import Settings
    from agent_proxy.main import create_app
    from httpx import ASGITransport, AsyncClient

    settings = Settings.from_env({**os.environ, **env_overrides})
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        async with AsyncClient(transport=ASGITransport(app=application),
                               base_url="http://testserver") as c:
            yield c


async def test_upstream_dead_port_maps_502(client):
    """评审核销项：上游连接失败（127.0.0.1:1 死端口）→ 502 UPSTREAM_ERROR，
    metrics ap_upstream_errors_total{code=connect} 打点。"""
    from agent_proxy import metrics as metrics_mod

    created = await _register(client, upstream_url="http://127.0.0.1:1/api/v1")
    before = metrics_mod.upstream_errors_total.labels(
        type="http", code="connect")._value.get()
    resp = await _call(client, created["mapping_id"], "GET", "/orders")
    after = metrics_mod.upstream_errors_total.labels(
        type="http", code="connect")._value.get()
    assert resp.status_code == 502 and resp.json()["code"] == "UPSTREAM_ERROR"
    assert after == before + 1


async def test_upstream_read_timeout_maps_504():
    """评审核销项：上游读超时（UPSTREAM_READ_TIMEOUT=1 < slow 3s）→ 504 UPSTREAM_TIMEOUT，
    metrics ap_upstream_errors_total{code=timeout} 打点。"""
    from agent_proxy import metrics as metrics_mod

    before = metrics_mod.upstream_errors_total.labels(
        type="http", code="timeout")._value.get()
    async with _dedicated_app_client(UPSTREAM_READ_TIMEOUT="1") as c:
        resp = await c.post("/api/v1/mappings",
                            json={"type": "http",
                                  "upstream_url": "http://127.0.0.1:9901/api/v1",
                                  "headers": {}},
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
        mid = resp.json()["mapping_id"]
        resp = await _call(c, mid, "GET", "/slow?seconds=3")
    after = metrics_mod.upstream_errors_total.labels(
        type="http", code="timeout")._value.get()
    assert resp.status_code == 504 and resp.json()["code"] == "UPSTREAM_TIMEOUT"
    assert after == before + 1


async def test_pool_exhausted_returns_503():
    """评审核销项：max_connections=1 + 慢上游：第二个请求等池超时 → 503 PROXY_BUSY。

    专用 app（UPSTREAM_MAX_CONNECTIONS=1 + UPSTREAM_POOL_TIMEOUT=2）：2s 池超时
    < 5s 慢响应占用，保证恰一个请求拿到连接、另一个 503（POOL_TIMEOUT 配置可用性
    一并钉住；评审要求断言 [200, 503]）。
    """
    import asyncio

    async with _dedicated_app_client(UPSTREAM_MAX_CONNECTIONS="1",
                                     UPSTREAM_POOL_TIMEOUT="2") as c:
        resp = await c.post("/api/v1/mappings",
                            json={"type": "http",
                                  "upstream_url": "http://127.0.0.1:9901/api/v1",
                                  "headers": {}},
                            headers={"Authorization": f"Bearer {make_token('u888')}"})
        mid = resp.json()["mapping_id"]
        r1, r2 = await asyncio.gather(
            _call(c, mid, "GET", "/slow?seconds=5"),
            _call(c, mid, "GET", "/slow?seconds=5"))
    statuses = sorted(r.status_code for r in (r1, r2))
    busy = [r for r in (r1, r2) if r.status_code == 503]
    assert statuses == [200, 503], f"池耗尽应恰一请求 503: {statuses}"
    assert busy and busy[0].json()["code"] == "PROXY_BUSY"


# ---------- M2 终审遗留债务：重定向跳间 trace（债务 3 / Minor 2） ----------


async def test_redirect_hops_recorded_in_trace(client, tmp_path):
    """M2 遗留债务 3：重定向循环每跳 URL 写 trace request 行（同 request_id 可回放整条链）。"""
    import json as jsonlib
    import logging

    from agent_proxy.logging_setup import flush_trace

    handler_target = tmp_path / "trace.log"
    logger = logging.getLogger("agent_proxy.trace")
    saved = logger.handlers
    logger.handlers = [logging.FileHandler(handler_target, encoding="utf-8")]
    try:
        created = await _register(client)
        resp = await _call(client, created["mapping_id"], "GET", "/redirect/same-origin")
        assert resp.status_code == 200
    finally:
        logger.handlers = saved
    flush_trace()
    recs = [jsonlib.loads(x) for x in
            handler_target.read_text(encoding="utf-8").splitlines() if x.strip()]
    mine = [r for r in recs if r.get("mapping_id") == created["mapping_id"]]
    reqs = [r for r in mine if r["phase"] == "request"]
    assert len(reqs) == 2, "首跳 + 同源跟随跳应各有一条 request 行"
    assert reqs[0]["request_id"] == reqs[1]["request_id"]      # 同 request_id 关联
    assert reqs[0]["url"].endswith("/redirect/same-origin")
    assert reqs[1]["url"].startswith("http://127.0.0.1:9901/api/v1/final?via=")


async def test_redirect_hop_send_failure_traced(client, app, tmp_path):
    """M2 遗留 Minor 2：跳间 send 失败同样留下跳间 URL 的 request 行（先记后发）。"""
    import json as jsonlib
    import logging

    from agent_proxy.logging_setup import flush_trace

    class _FailSecondHopClient(_FakeStreamClient):
        async def send(self, request, stream=False):
            if self.sent_urls:  # 第二跳（跟随跳）连接失败
                raise httpx.ConnectError("hop connection refused", request=request)
            return await super().send(request, stream=stream)

    handler_target = tmp_path / "trace.log"
    logger = logging.getLogger("agent_proxy.trace")
    saved = logger.handlers
    logger.handlers = [logging.FileHandler(handler_target, encoding="utf-8")]
    created = await _register(client)
    mid = created["mapping_id"]
    fake = _FailSecondHopClient([
        (302, {"location": "/api/v1/final?via=redirect"}),  # 同源首跳
        (200, {"content-type": "text/plain"}),
    ])
    real = app.state.http_client
    app.state.http_client = fake
    try:
        resp = await _call(client, mid, "GET", "/orders")
    finally:
        app.state.http_client = real
        logger.handlers = saved
    flush_trace()
    recs = [jsonlib.loads(x) for x in
            handler_target.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert resp.status_code == 502 and resp.json()["code"] == "UPSTREAM_ERROR"
    mine = [r for r in recs if r.get("mapping_id") == mid]
    reqs = [r for r in mine if r["phase"] == "request"]
    assert len(reqs) == 2, "首跳 + 跟随跳（虽 send 失败）应各有一条 request 行"
    assert reqs[1]["url"].startswith("http://127.0.0.1:9901/api/v1/final")
