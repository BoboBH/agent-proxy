import httpx


async def test_echo_upstream_reachable_over_real_tcp():
    """冒烟：不经代理，直连 echo 上游，验证 9901 真实监听可用。"""
    async with httpx.AsyncClient() as c:
        resp = await c.get("http://127.0.0.1:9901/api/v1/ping")
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "GET" and echo["path"] == "/ping"


async def test_echo_upstream_post_body_echo():
    async with httpx.AsyncClient() as c:
        resp = await c.post("http://127.0.0.1:9901/api/v1/orders?x=1",
                            content=b'{"a":1}', headers={"Content-Type": "application/json"})
    assert resp.status_code == 200
    echo = resp.json()
    assert echo["method"] == "POST" and echo["body"] == '{"a":1}'
    assert echo["query"] == {"x": "1"}


# ---------- 直连基线（Task 4 评审携带项）：转发用例断言的上游行为，先直连钉住 ----------


async def test_echo_upstream_status_599_passthrough_shape():
    """上游非常规状态码 599 原样返回（转发用例依赖「上游 4xx/5xx 原样透传」语义）。"""
    async with httpx.AsyncClient() as c:
        resp = await c.get("http://127.0.0.1:9901/api/v1/status/599")
    assert resp.status_code == 599
    assert resp.text == "upstream-status-599"
    assert resp.headers["content-type"].startswith("text/plain")


async def test_echo_upstream_redirect_location_header():
    """302 的 Location 头形状（后续重定向用例按此断言；httpx 默认不跟随）。"""
    async with httpx.AsyncClient(follow_redirects=False) as c:
        resp = await c.get("http://127.0.0.1:9901/api/v1/redirect/same-origin")
    assert resp.status_code == 302
    assert resp.headers["location"] == "/api/v1/final?via=redirect"


async def test_echo_upstream_big_response_byte_length():
    """大响应字节级完整（后续流式转发用例依赖上游 /big 的确定性长度）。"""
    async with httpx.AsyncClient() as c:
        resp = await c.get("http://127.0.0.1:9901/api/v1/big?kb=64")
    assert resp.status_code == 200
    assert len(resp.content) == 64 * 1024
