"""FastAPI 组装：lifespan（引擎/Redis/http_client/建表/自检/优雅停机）、中间件、路由、健康检查。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from app.services import errors, trace
from app.core.cache import build_redis
from app.env import Settings, get_settings
from app.core.db import Base, build_engine, build_sessionmaker
from app.services.logging_service import setup_logging, shutdown_logging
from app.core.middleware import RequestContextMiddleware
from app.routers.mgmt import router as mgmt_router
from app.routers.proxy import router as proxy_router
from app.routers.builtin import router as builtin_router, callback_router as oauth_callback_router
from app.routers.admin import router as admin_pages_router

log = logging.getLogger("agent_proxy")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    setup_logging(settings.log_dir, settings.log_level)
    trace.configure(settings.trace_mode, settings.trace_body_max_size)
    engine = build_engine(settings.mysql_dsn)
    app.state.engine = engine
    app.state.sessionmaker = build_sessionmaker(engine)
    app.state.redis = build_redis(settings.redis_url)
    # 全局共享上游 AsyncClient（设计 §8.1 第 11 条）：连接复用、池上限、超时配置；
    # 重定向由转发层按同源策略手动跟随（第 7 条），不交给 httpx 自动跟随。
    # 池等待 pool=UPSTREAM_POOL_TIMEOUT（默认 5s）：与设计 §8.1 第 10 条「池耗尽立即
    # 503」的已知偏离（评审记录在案）——短暂排队可吸收突发并发毛刺避免误杀，
    # 排队超时后仍映射 503 PROXY_BUSY；需要严格立即拒绝时将该值配置为 0。
    limits = httpx.Limits(max_connections=settings.upstream_max_connections,
                          max_keepalive_connections=settings.upstream_max_connections)
    app.state.http_client = httpx.AsyncClient(
        limits=limits,
        timeout=httpx.Timeout(connect=settings.upstream_connect_timeout,
                              read=settings.upstream_read_timeout, write=60.0,
                              pool=settings.upstream_pool_timeout),
        follow_redirects=False,
        # trust_env=False（设计 §8.1 v2 注记）：服务端出站直连，绝不隐式路由进
        # 环境/系统代理（httpx 默认经 getproxies() 读 Windows 注册表代理——桌面
        # Clash 场景下死端口被代答 502、探测误判可达、SSRF 的 IP 校验被旁路）。
        # 需要经企业代理出站的部署属显式架构决策，届时单独设计，不走环境隐式。
        trust_env=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await app.state.redis.ping()
    log.info("agent-proxy 启动: external_base=%s", settings.external_base)
    yield
    await app.state.http_client.aclose()
    # redis-py 4.x 无 aclose()（5.0 起引入），close() 即异步关闭
    close = getattr(app.state.redis, "aclose", None) or app.state.redis.close
    await close()
    await engine.dispose()
    log.info("agent-proxy 已停止")
    shutdown_logging()  # 最后一步：关闭过程（redis/engine）异常仍可落盘


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="agent-proxy", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    # 路由的 Depends(get_settings) 必须解析到本 app 的 Settings 实例（与
    # app.state.settings 同源）：同一进程可能存在多个 app 实例（M6 起测试双夹具
    # ASGI testserver / 真实 TCP 9910 的 EXTERNAL_BASE 不同），redirect_uri 组装、
    # front_redirect 白名单等按宿主 app 生效。生产单实例时两来源本就一致，行为不变；
    # 修复前 lru_cache 全局读 os.environ，第二实例的 EXTERNAL_BASE 覆盖被吞掉。
    app.dependency_overrides[get_settings] = lambda: settings
    if settings.cors_allowed_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_allowed_origins),
                           allow_methods=["*"],
                           # Authorization：设计 v2 起 /p/ 上是调用方可透传的上游载荷头
                           # （CORS 预检必须放行）；X-Proxy-Authorization：代理身份通道
                           allow_headers=["Authorization", "X-Proxy-Authorization",
                                          "Content-Type"])
    app.add_middleware(RequestContextMiddleware)
    errors.install_error_handlers(app)
    app.include_router(mgmt_router)
    app.include_router(proxy_router)
    app.include_router(builtin_router)
    app.include_router(oauth_callback_router)
    app.include_router(admin_pages_router)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz(request: Request):
        try:
            async with request.app.state.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            await request.app.state.redis.ping()
        except Exception as exc:
            return JSONResponse({"status": "unavailable", "error": str(exc)}, status_code=503)
        return {"status": "ready"}

    @app.get("/metrics")
    async def metrics_endpoint():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


# uvicorn 入口：uvicorn app.main:app（Settings 经 get_settings() 从
# 环境变量 / .env 读取；测试多实例仍走 create_app(settings) 工厂 + dependency_overrides）
app = create_app()


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(
        app='main:app',
        host='0.0.0.0',
        port=8800,
    )
    pass
