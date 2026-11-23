"""最小 MCP SSE 上游（测试专用）：经 uvicorn.Server 真实监听 127.0.0.1:9902。

协议形态与官方 MCP SSE 服务一致（设计 §8.3 场景）：
- GET /sse：text/event-stream 长连接——先发 `event: endpoint` 事件（data 为
  **根相对路径** `/messages?session_id=test123`，官方 Python/TypeScript SDK 均为
  此形式），随后每 0.2s 发 `: ping` 心跳注释行；每条连接独立消息队列；
- POST /messages：接收 JSON-RPC，回 202 Accepted；有 id 的请求把结果作为
  `event: message` 推回 SSE 流（notifications 无 id 只收不回，MCP 规范）；
  消息广播至所有活跃连接（多客户端同时在线各自可见）；
  initialize 返回 serverInfo、tools/list 返回固定工具列表（echo）、tools/call 回显 arguments；
- GET /sse-no-endpoint：只发心跳、永不发 endpoint 事件（test 接口「握手失败」用例）；
- GET /：裸 origin 注册形态（评审 Issue 2）——根路径即 SSE 端点，行为与 /sse 一致；
- GET /sse-redirect-same：同源 307（Location 指向本 mock = 注册 upstream origin，
  评审 Issue 1「同源 Location 永不回传」中止用例）；
- GET /sse2：同源 307 的**根相对 Location** 变体（Location: /sse，现网常见形态，
  join 解析后同源判定对照面）；
- GET /sse-redirect-cross：跨源 307（Location 指向 9901 echo 上游，不同端口即不同
  origin，透传对照面）；
- GET /sse-503：注册端点返回非 SSE 错误体（503 text/html，原样透传/不计 sse_active 用例）；
- GET /_connections：调试端点，返回当前活跃 SSE 连接数（客户端断开→上游取消
  的端到端验证用）。

模块级 mock_state 供测试直读（received 断言出站 header/query；测试自行清空；
last_sse_headers 为最近一次 /sse GET 请求头小写键 dict，供 Connection: close 等
出站语义钉住）。
"""
from __future__ import annotations

import asyncio
import json

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

    @app.get("/sse-no-endpoint")
    async def sse_no_endpoint():
        async def gen():
            while True:
                yield b": heartbeat only, no endpoint event\n\n"
                await asyncio.sleep(0.2)

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
