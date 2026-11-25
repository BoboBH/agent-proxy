"""accept-encoding 透明性回归（M4 前置硬项）：上游启用 gzip 时代理必须按压缩
字节透传（aiter_raw），响应头保真——头体一致，严格客户端（uvicorn/h11 侧）不再
因「解压体超过声明 content-length」断连报错。覆盖 M2 http 管线与 M3 SSE 管线
plain 分支两条路径。

必须真实 TCP（uvicorn 9910）：只有真实服务器按声明 content-length 校验响应体
（h11 "Too much data"），ASGI 直连无此强校验，抓不住「头体不一致」缺陷。
测试侧 httpx 同样会按响应头自动解压，故用 aiter_raw 读线上原始字节断言。
"""
import gzip

import httpx

from tests.utils import make_token

PROXY = "http://127.0.0.1:9910"
AUTH = {"X-Proxy-Authorization": f"Bearer {make_token(888)}"}
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)


async def _register(user, payload):
    payload = {"headers": {"Authorization": "Bearer sk-enc-12345678"}, **payload}
    async with httpx.AsyncClient() as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json=payload,
                            headers={"X-Proxy-Authorization": f"Bearer {make_token(user)}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _raw_response(method: str, url: str, headers: dict):
    """经代理取响应：返回 (status, headers, 线上原始字节)——aiter_raw 不解压。"""
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream(method, url, headers=headers) as resp:
            raw = b"".join([chunk async for chunk in resp.aiter_raw()])
            return resp.status_code, dict(resp.headers), raw


async def test_http_pipeline_gzip_body_passthrough_bytes_exact():
    """M2 _response_stream：上游 gzip 响应字节级透传 + 响应头保真（头体一致）。

    修复前：aiter_bytes 自动解压（明文体 > 声明 content-length），真实链路上
    代理侧 uvicorn/h11 报 "Too much data" 断连；修复后压缩字节原样透传。
    """
    created = await _register(888, {"type": "http",
                                       "upstream_url": "http://127.0.0.1:9901/api/v1"})
    status, headers, raw = await _raw_response(
        "GET", f"{PROXY}/p/{created['mapping_id']}/gzip-text", AUTH)
    assert status == 200
    assert headers["content-encoding"] == "gzip"
    declared = int(headers["content-length"])
    assert declared == len(raw), "响应体必须等于声明的压缩长度（头体一致）"
    assert raw.startswith(b"\x1f\x8b")                       # gzip magic：未解压的压缩字节
    assert gzip.decompress(raw) == b"gzip-upstream-payload-" * 40


async def test_sse_pipeline_plain_branch_gzip_passthrough_bytes_exact():
    """M3 SSE 管线 plain 分支（非 event-stream 响应原样回传路径）同样 aiter_raw。"""
    created = await _register(888, {"type": "mcp",
                                       "upstream_url": "http://127.0.0.1:9902/sse-gzip-html"})
    status, headers, raw = await _raw_response(
        "GET", f"{PROXY}/p/{created['mapping_id']}/sse-gzip-html", AUTH)
    assert status == 200
    assert headers["content-encoding"] == "gzip"
    assert int(headers["content-length"]) == len(raw)
    assert raw.startswith(b"\x1f\x8b")
    assert b"upstream-gzip-html" in gzip.decompress(raw)
