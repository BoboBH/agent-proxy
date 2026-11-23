"""FastAPI 组装：lifespan（引擎/Redis/http_client/建表/自检/优雅停机）、中间件、路由、健康检查。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from . import errors, metrics, trace
from .cache import build_redis
from .config import Settings, get_settings
from .db import Base, build_engine, build_sessionmaker
from .logging_setup import setup_logging, shutdown_logging
from .middleware import RequestContextMiddleware
from . import models as _models  # noqa: F401  注册 ORM 元数据供 create_all
from .api.mgmt import router as mgmt_router
from .api.proxy import router as proxy_router

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
        follow_redirects=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await app.state.redis.ping()
    log.info("agent-proxy 启动: listen=%s external_base=%s", settings.listen, settings.external_base)
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
    if settings.cors_allowed_origins:
        from fastapi.middleware.cors import CORSMiddleware
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_allowed_origins),
                           allow_methods=["*"], allow_headers=["Authorization", "Content-Type"])
    app.add_middleware(RequestContextMiddleware)
    errors.install_error_handlers(app)
    app.include_router(mgmt_router)
    app.include_router(proxy_router)

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
