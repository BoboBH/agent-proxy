"""Mock MCP SSE 上游（集成测试 / Inspector 联调共用）：监听 127.0.0.1:9902。

协议形态与官方 MCP SSE 服务一致（设计 §8.3 场景）：
- GET /sse：text/event-stream 长连接——先发 `event: endpoint` 事件（data 为
  **根相对路径** `/messages?session_id=test123`，官方 Python/TypeScript SDK 均为
  此形式），随后每 0.2s 发 `: ping` 心跳注释行；每条连接独立消息队列；
- POST /messages：接收 JSON-RPC，回 202 Accepted；有 id 的请求把结果作为
  `event: message` 推回 SSE 流（notifications 无 id 只收不回，MCP 规范）；
  消息广播至所有活跃连接（多客户端同时在线各自可见）；
  initialize 返回 serverInfo、tools/list 返回固定工具列表（echo）、tools/call 回显 arguments；
- GET /sse-no-endpoint：只发心跳、永不发 endpoint 事件（test 接口「握手失败」用例）；
- GET /sse-headers-then-rst：发完响应头即断（断点在 endpoint 事件之前，坏上游
  probe 读阶段 HTTPError 兜底用例）；
- GET /sse-endpoint-malformed：endpoint 值 `http://[bad`（urlparse ValueError，
  probe 脱敏降级用例）；
- GET /sse-endpoint-no-data：`event: endpoint` 块无 data 行即空行结束 + 默认类型
  data 行（空行复位钉住，防假 ok=true）+ EOF；
- GET /sse-eof-no-endpoint：只发一个 message 事件即 EOF（probe「流结束仍未收到
  endpoint 事件」分支用例）；
- GET /：裸 origin 注册形态（评审 Issue 2）——根路径即 SSE 端点，行为与 /sse 一致；
- GET /sse-redirect-same：同源 307（Location 指向本 mock = 注册 upstream origin，
  评审 Issue 1「同源 Location 永不回传」中止用例）；
- GET /sse2：同源 307 的**根相对 Location** 变体（Location: /sse，现网常见形态，
  join 解析后同源判定对照面）；
- GET /sse-redirect-cross：跨源 307（Location 指向 9901 echo 上游，不同端口即不同
  origin，透传对照面）；
- GET /sse-503：注册端点返回非 SSE 错误体（503 text/html，原样透传/不计 sse_active 用例）；
- GET /sse-gzip-stream：协商式 gzip SSE 上游——请求 accept-encoding 含 gzip 时
  返回压缩的**长驻** event-stream（content-encoding: gzip，zlib 同步 flush 逐块
  压缩；probe identity 钉 / gzip SSE 防御透传用例），否则明文长驻 event-stream；
- GET /sse-identity-stream：显式 content-encoding: identity 的**长驻** event-stream
  （identity = RFC 9110 合法「无压缩」声明，体为明文）——SSE 管线 identity 豁免
  用例：不得据此降级 plain 分支（照常改写 + 计 sse_active）；
- GET /sse-slow-hello：响应头迟到 3s + endpoint 事件再迟 3s（probe 总挂钟期限
  定稿用例：分阶段语义 ~6s 误报 ok=true，总期限语义 ~5s 即决 ok=false）；
- GET /_connections：调试端点，返回当前活跃 SSE 连接数（客户端断开→上游取消
  的端到端验证用）。

模块级 mock_state 供测试直读（received 断言出站 header/query；测试自行清空；
last_sse_headers 为最近一次 /sse GET 请求头小写键 dict，供 Connection: close 等
出站语义钉住）。
"""
from __future__ import annotations

import argparse
import asyncio
import gzip
import json
import zlib

from fastapi import FastAPI, Request
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                               Response, StreamingResponse)

# 模块级状态：测试直接 import 断言
mock_state: dict = {"sse_open": 0, "received": [], "queues": [],
                    "last_sse_headers": {}}  # 最近一次 /sse GET 请求头（小写键）


def _result_for(rpc: dict) -> dict:
    method = rpc.get("method")
    if method == "initialize":
        params = rpc.get("params") or {}
        return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp-sse", "version": "0.1.0"}}
    if method == "tools/list":
        return {"tools": [{"name": "echo",
                           "description": "回显输入文本",
                           "inputSchema": {"type": "object",
                                           "properties": {"text": {"type": "string"}}}}]}
    if method == "tools/call":
        args = (rpc.get("params") or {}).get("arguments") or {}
        return {"content": [{"type": "text", "text": json.dumps(args, ensure_ascii=False)}]}
    return {"echo": method}


def build_mcp_sse_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.api_route("/sse", methods=["GET", "HEAD"])
    async def sse_endpoint(request: Request):
        # 记录最近一次 SSE GET 请求头（小写键）供测试断言出站语义
        # （如 Task 5 生产修复的 Connection: close 钉住）
        mock_state["last_sse_headers"] = dict(request.headers.items())
        queue: asyncio.Queue = asyncio.Queue()
        mock_state["queues"].append(queue)

        async def gen():
            mock_state["sse_open"] += 1  # 首行：与 finally 的 -1 对称（客户端在首块下发前断开时生成器未启动，finally 永不执行——计数放 handler 里会在该路径泄漏）
            try:
                yield b"event: endpoint\ndata: /messages?session_id=test123\n\n"
                while True:
                    try:
                        payload = await asyncio.wait_for(queue.get(), timeout=0.2)
                        yield f"event: message\ndata: {payload}\n\n".encode("utf-8")
                    except asyncio.TimeoutError:
                        yield b": ping\n\n"   # 心跳注释行（§8.3：代理透传不记录）
            finally:
                mock_state["sse_open"] -= 1
                if queue in mock_state["queues"]:
                    mock_state["queues"].remove(queue)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.api_route("/", methods=["GET", "HEAD"])
    async def root_sse(request: Request):
        # 裸 origin 注册形态（评审 Issue 2）：根路径即 SSE 端点，行为与 /sse 一致
        return await sse_endpoint(request)

    @app.get("/sse-redirect-same")
    async def sse_redirect_same():
        # 同源重定向（评审 Issue 1）：Location 指向本 mock 自身 = 注册 upstream origin
        return RedirectResponse("http://127.0.0.1:9902/sse", status_code=307)

    @app.get("/sse2")
    async def sse_redirect_same_relative():
        # 同源重定向的**根相对 Location** 变体（现网服务常见形态）：代理须经
        # URL join 解析后才能判定同源——判定必须同样命中（评审 Issue 1 覆盖面）
        return RedirectResponse("/sse", status_code=307)

    @app.get("/sse-redirect-cross")
    async def sse_redirect_cross():
        # 跨源重定向（评审 Issue 1 对照面）：9901 与 9902 不同端口 = 不同 origin
        return RedirectResponse("http://127.0.0.1:9901/echo-target", status_code=307)

    @app.get("/sse-503")
    async def sse_503():
        # 非 SSE 错误体（评审 Issue 7）：原样透传、不进改写管线、不计 sse_active
        return HTMLResponse("<html><body>upstream-503-html</body></html>", status_code=503)

    @app.get("/sse-gzip-html")
    async def sse_gzip_html():
        # M4 accept-encoding 回归：注册端点路径返回 200 + gzip HTML（非
        # event-stream）——进 SSE 管线 plain 分支（原样回传），压缩字节透传、
        # 响应头保真（与 /sse-503 同路径不同编码，plain 分支双覆盖）
        body = gzip.compress(b"<html><body>upstream-gzip-html</body></html>")
        return Response(content=body, media_type="text/html",
                        headers={"content-encoding": "gzip"})

    @app.get("/sse-gzip-stream")
    async def sse_gzip_stream(request: Request):
        # M4 评审携带项（gzip SSE 防御/probe identity 钉）：协商式压缩上游——
        # 调用方 accept-encoding 含 gzip 时对 event-stream 也压缩（真实上游形态），
        # identity / 无协商时返回明文。长驻形态（首块 endpoint+message 事件，随后
        # 心跳）：防御用例需在流保持打开期间采样 sse_active gauge（压缩体上
        # rewriter 分支会 +1，plain 透传分支不计数），单发短流采样必竞态。
        # zlib 同步 flush：每 yield 产出可独立解压的前缀（客户端可增量解压断言）。
        first = (b"event: endpoint\ndata: /messages?session_id=gzipstream\n\n"
                 b"event: message\ndata: {\"ok\":1}\n\n")
        if "gzip" in request.headers.get("accept-encoding", "").lower():
            compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)

            def comp(data: bytes) -> bytes:
                return compressor.compress(data) + compressor.flush(zlib.Z_SYNC_FLUSH)

            async def gen():
                yield comp(first)
                while True:
                    yield comp(b": ping\n\n")
                    await asyncio.sleep(0.2)

            return StreamingResponse(gen(), media_type="text/event-stream",
                                     headers={"content-encoding": "gzip"})

        async def gen_plain():
            yield first
            while True:
                yield b": ping\n\n"
                await asyncio.sleep(0.2)

        return StreamingResponse(gen_plain(), media_type="text/event-stream")

    @app.get("/sse-identity-stream")
    async def sse_identity_stream():
        # M4 Task 2 评审携带项（identity 豁免）：显式 content-encoding: identity
        # 是 RFC 9110 合法的「无压缩」声明，体为明文——SSE 管线不得据此降级 plain
        # 分支（否则丢 endpoint 改写）。长驻形态同 /sse-gzip-stream：流保持打开
        # 期间采样 sse_active gauge（改写分支 +1、plain 分支不计数），单发短流采样必竞态。
        first = (b"event: endpoint\ndata: /messages?session_id=identitystream\n\n"
                 b"event: message\ndata: {\"ok\":1}\n\n")

        async def gen():
            yield first
            while True:
                yield b": ping\n\n"
                await asyncio.sleep(0.2)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"content-encoding": "identity"})

    @app.get("/sse-no-endpoint")
    async def sse_no_endpoint():
        async def gen():
            while True:
                yield b": heartbeat only, no endpoint event\n\n"
                await asyncio.sleep(0.2)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/sse-headers-then-rst")
    async def sse_headers_then_rst():
        # 坏上游（评审 Important 1a）：发完 200 text/event-stream 响应头后连接即断
        # （先发一条心跳注释证明流已启动，再在 endpoint 事件之前断开）——探测读阶段
        # aiter_bytes 抛 httpx.HTTPError，必须 ok=false 兜底而非穿透 500，且 resp
        # 必须 aclose（连接不滞留池内）。注意断点必须在 endpoint 事件之前：
        # probe 读到首 endpoint 即 aclose，之后才断的流探测根本读不到断点。
        async def gen():
            yield b": stream starts, breaks before endpoint event\n\n"
            raise RuntimeError("upstream reset after headers")

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/sse-endpoint-malformed")
    async def sse_endpoint_malformed():
        # 畸形 endpoint 值（评审 Important 1b）：`http://[bad` 使 urlparse 抛
        # ValueError → redact_query 必须降级指纹占位而非 500（与转发管线对同一
        # 输入降级透传同规，mcp_sse.SseEndpointRewriter._rewrite_endpoint_data）
        async def gen():
            yield b"event: endpoint\ndata: http://[bad\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/sse-endpoint-no-data")
    async def sse_endpoint_no_data():
        # 空行复位钉住（评审 Minor 2）：endpoint 事件块**无 data 行**即被空行结束，
        # 随后的默认事件类型 data 行不得被误判为 endpoint（未复位 → 假 ok=true）；
        # 流随即 EOF → probe 走「流结束仍未收到 endpoint 事件」分支
        async def gen():
            yield b"event: endpoint\n\n"
            yield b"data: /messages?session_id=leak\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/sse-eof-no-endpoint")
    async def sse_eof_no_endpoint():
        # EOF 无 endpoint 事件（评审 Minor 4）：流正常结束但从未发 endpoint——
        # probe 读到 EOF 判失败（区别于 5s 超时路径的 /sse-no-endpoint）
        async def gen():
            yield b"event: message\ndata: {\"x\":1}\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/sse-slow-hello")
    async def sse_slow_hello():
        # M4 probe 总期限定稿用例：响应头迟到 3s（handler 内 sleep，send 阶段耗时）
        # + endpoint 事件再迟 3s（读流阶段耗时）= 总 6s > 5s 总期限。旧「分阶段
        # 5s×2」语义会 ok=true（~6s 返回）；总期限语义必 ok=false（~5s 即决）。
        # 头后立即发一条注释行证明流已启动（区别于上游整体无响应的 /slow 路径）。
        # 注意 sleep 必须在 handler 返回 StreamingResponse 之前——Starlette 对
        # StreamingResponse 先发响应头再迭代生成器，生成器内首 yield 前的 sleep
        # 只延迟首块、不延迟响应头（计划原稿误置于 gen 内，send 阶段不再耗时）。
        await asyncio.sleep(3)

        async def gen():
            yield b": stream started\n\n"
            await asyncio.sleep(3)
            yield b"event: endpoint\ndata: /messages?session_id=slow\n\n"
            await asyncio.sleep(3)
            yield b"event: message\ndata: {}\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/messages")
    async def messages(request: Request):
        rpc = json.loads(await request.body())
        mock_state["received"].append({
            "rpc": rpc,
            "query": dict(request.query_params),
            "headers": dict(request.headers.items()),
        })
        if "id" in rpc:  # notifications 无 id：只收不回（MCP 规范）
            payload = json.dumps({"jsonrpc": "2.0", "id": rpc["id"],
                                  "result": _result_for(rpc)}, ensure_ascii=False)
            for queue in list(mock_state["queues"]):
                queue.put_nowait(payload)
        return Response(status_code=202)

    @app.get("/_connections")
    async def connections():
        return JSONResponse({"sse_open": mock_state["sse_open"]})

    return app


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="mock MCP SSE 上游（Inspector 联调用）")
    parser.add_argument("--port", type=int, default=9902,
                        help="监听端口（默认 9902）")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    import uvicorn
    uvicorn.run(build_mcp_sse_app(), host="127.0.0.1", port=args.port,
                log_level="info", access_log=False)
