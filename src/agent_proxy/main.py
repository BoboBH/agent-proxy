"""FastAPI 组装：lifespan（引擎/Redis/建表/自检/优雅停机）、中间件、路由、健康检查。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

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
from .api.mgmt import router as mgmt_router

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
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await app.state.redis.ping()
    log.info("agent-proxy 启动: listen=%s external_base=%s", settings.listen, settings.external_base)
    yield
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
