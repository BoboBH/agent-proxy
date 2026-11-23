"""真实 echo 上游（测试专用）：FastAPI 应用，经 uvicorn.Server 真实监听 127.0.0.1:9901。

用户明确要求「真实的 http 代理测试」：集成测试经代理→上游走真实 TCP，
不用 ASGI 直连伪造上游。端点能力：全路径回显 / 大响应 / 慢响应 / 状态码 /
同源重定向 / 跨源重定向（→ 9902 不存在端口）/ 重定向循环 / 307 保方法。
注意：具体端点必须定义在 /api/v1/{path:path} 回显兜底之前（先注册先匹配）。

回显契约（Task 4 评审携带项）：
- headers 回显的头名为小写——uvicorn/h11 在 ASGI 边界把头名归一为小写，
  上游存储侧的大小写在线上不可见，断言应按头名小写不敏感比较；
- 重复 header / 查询参数经 dict 合并后只保留最后一个值；多值原始对
  用 headers_multi（[[k, v], ...] 逐行）查看，供重复头行断言使用。
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response


def build_echo_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/api/v1/slow")
    async def slow(seconds: float = 1.0):
        await asyncio.sleep(seconds)
        return {"woke": True}

    @app.get("/api/v1/big")
    async def big(kb: int = 1024):
        size = kb * 1024
        pattern = bytes(range(256))
        body = (pattern * (size // len(pattern) + 1))[:size]
        return Response(content=body, media_type="application/octet-stream")

    @app.get("/api/v1/status/{code}")
    async def status_code(code: int):
        return Response(content=f"upstream-status-{code}", status_code=code,
                        media_type="text/plain")

    @app.get("/api/v1/redirect/same-origin")
    async def redirect_same_origin():
        return RedirectResponse("/api/v1/final?via=redirect", status_code=302)

    @app.get("/api/v1/redirect/cross-origin")
    async def redirect_cross_origin():
        return RedirectResponse("http://127.0.0.1:9902/nowhere", status_code=302)

    @app.get("/api/v1/redirect/loop")
    async def redirect_loop():
        return RedirectResponse("/api/v1/redirect/loop", status_code=302)

    @app.post("/api/v1/redirect/307")
    async def redirect_307():
        return RedirectResponse("/api/v1/final", status_code=307)

    @app.api_route("/api/v1", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    @app.api_route("/api/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def echo(request: Request, path: str = ""):
        body = await request.body()
        return {
            "path": "/" + path,
            "method": request.method,
            "query": dict(request.query_params.multi_items()),
            "headers": dict(request.headers.items()),
            "headers_multi": [[k.decode("latin-1"), v.decode("latin-1")]
                              for k, v in request.headers.raw],
            "body": body.decode("utf-8", "replace"),
            "body_bytes": len(body),
        }

    return app
