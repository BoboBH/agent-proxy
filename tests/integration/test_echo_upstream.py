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
