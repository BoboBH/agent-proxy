"""最小 MCP Streamable HTTP 上游（测试专用）：经 uvicorn.Server 真实监听 127.0.0.1:9903。

协议形态与官方 MCP Streamable HTTP 服务一致（设计 §8.4 场景）：
- 单一 /mcp 端点，POST 接 JSON-RPC——initialize 返回 application/json +
  `Mcp-Session-Id: sess-m4` 响应头（会话由上游自持，§8.4）；tools/list /
  tools/call 默认返回 JSON 形态，查询参数 `?form=sse`（或路径别名
  /mcp-sse-form）切换为**短 SSE 流形态**（单条 `event: message` 后 EOF），
  覆盖代理对两种响应形态的回传分支；
- 会话语义：非 initialize 的 POST 缺（或错值）`Mcp-Session-Id` 头 → 400
  （代理必须把客户端会话头双向透传：请求侧带上游、响应侧带客户端）；
- notifications（无 id）→ 202 Accepted 无响应体（MCP Streamable 规范形态）；
- GET /mcp：服务端推送流——连接即发一条 `notifications/message` 服务端推送
  事件，随后每 0.2s 发 `: ping` 心跳注释行；
- DELETE /mcp：204 会话结束；
- POST /mcp-no-serverinfo：initialize 可达但 result 缺 serverInfo（非 MCP 端点
  典型形态，§6.6 硬判定 ok=false 用例）；
- POST /mcp-slow：8s 后才回 initialize（> probe 5s 总期限，超时用例）。

模块级 streamable_state 供测试直读（received / deletes / last_get_headers /
last_delete_headers / get_open；测试自行清空；headers dict 为 Starlette 小写键）。
"""
from __future__ import annotations

import asyncio
import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

SESSION_ID = "sess-m4"

streamable_state: dict = {"received": [], "deletes": [],
                          "last_get_headers": {}, "last_delete_headers": {},
                          "get_open": 0}


def _result_for(rpc: dict) -> dict:
    method = rpc.get("method")
    if method == "initialize":
        params = rpc.get("params") or {}
        return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp-streamable", "version": "0.1.0"}}
    if method == "tools/list":
        return {"tools": [{"name": "echo",
                           "description": "回显输入文本",
                           "inputSchema": {"type": "object",
                                           "properties": {"text": {"type": "string"}}}}]}
    if method == "tools/call":
        args = (rpc.get("params") or {}).get("arguments") or {}
        return {"content": [{"type": "text", "text": json.dumps(args, ensure_ascii=False)}]}
    return {"echo": method}


def build_mcp_streamable_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    async def _handle_rpc(request: Request, sse_form: bool):
        rpc = json.loads(await request.body())
        streamable_state["received"].append({
            "rpc": rpc,
            "query": dict(request.query_params),
            "headers": dict(request.headers.items()),
        })
        if rpc.get("method") != "initialize" \
                and request.headers.get("mcp-session-id") != SESSION_ID:
            # 会话由上游自持（§8.4）：代理必须把客户端的 Mcp-Session-Id 原样带到上游
            return JSONResponse({"error": "missing or invalid Mcp-Session-Id"},
                                status_code=400)
        if "id" not in rpc:  # notifications 无 id：202 无响应体（MCP Streamable 规范）
            return Response(status_code=202)
        payload = json.dumps({"jsonrpc": "2.0", "id": rpc["id"],
                              "result": _result_for(rpc)}, ensure_ascii=False)
        if sse_form:
            async def gen():
                yield f"event: message\ndata: {payload}\n\n".encode("utf-8")
            return StreamingResponse(gen(), media_type="text/event-stream")
        return Response(content=payload.encode("utf-8"), media_type="application/json",
                        headers={"mcp-session-id": SESSION_ID})

    @app.post("/mcp")
    async def mcp_post(request: Request):
        # 计划原稿 `sse_form="sse" in request.query_params` 不成立：QueryParams 的
        # in 判 **key**，`?form=sse` 的 key 是 form——按文档语义取值判（?form=sse）
        return await _handle_rpc(request, sse_form=request.query_params.get("form") == "sse")

    @app.post("/mcp-sse-form")
    async def mcp_post_sse_form(request: Request):
        # 路径别名：SSE 形态（probe 用例的 upstream_url 走路径别名，不带 query）
        return await _handle_rpc(request, sse_form=True)

    @app.post("/mcp-no-serverinfo")
    async def mcp_post_no_serverinfo():
        # initialize 可达但 result 缺 serverInfo（§6.6 硬判定的失败面）
        return JSONResponse({"jsonrpc": "2.0", "id": 1,
                             "result": {"protocolVersion": "2025-06-18",
                                        "capabilities": {}}})

    @app.post("/mcp-slow")
    async def mcp_post_slow():
        # 8s 后才响应（> TEST_PROBE_TIMEOUT 5s 总期限）：probe 超时用例
        await asyncio.sleep(8)
        return JSONResponse({"jsonrpc": "2.0", "id": 1,
                             "result": {"serverInfo": {"name": "slow", "version": "0"}}})

    @app.get("/mcp")
    async def mcp_get(request: Request):
        streamable_state["last_get_headers"] = dict(request.headers.items())

        async def gen():
            # gen 首行计数：与 finally 的 -1 对称（客户端在首块下发前断开时生成器
            # 未启动、finally 永不执行——同 mock_mcp_sse 的泄漏路径修正）
            streamable_state["get_open"] += 1
            try:
                push = json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                                   "params": {"level": "info", "data": "push-hello"}},
                                  ensure_ascii=False)
                yield f"event: message\ndata: {push}\n\n".encode("utf-8")
                while True:
                    yield b": ping\n\n"
                    await asyncio.sleep(0.2)
            finally:
                streamable_state["get_open"] -= 1

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.delete("/mcp")
    async def mcp_delete(request: Request):
        streamable_state["last_delete_headers"] = dict(request.headers.items())
        streamable_state["deletes"].append({"path": request.url.path,
                                            "query": dict(request.query_params)})
        return Response(status_code=204)

    return app
