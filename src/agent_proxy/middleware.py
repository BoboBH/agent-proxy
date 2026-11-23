"""中间件：request_id 生成与 X-Request-ID 回传、Prometheus 埋点、审计日志。"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone

from starlette.types import ASGIApp, Receive, Scope, Send

from . import metrics

audit = logging.getLogger("agent_proxy.audit")


def route_name(path: str) -> str:
    if path.startswith("/api/v1/mappings"):
        return "mgmt"
    if path.startswith("/api/v1/builtin"):
        return "builtin"
    if path.startswith("/p/"):
        return "proxy"
    if path.startswith("/admin"):
        return "admin"
    if path in ("/metrics", "/healthz", "/readyz"):
        return "ops"
    return "other"


def _type_of(route: str) -> str:
    return "http" if route == "proxy" else "-"


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        scope.setdefault("state", {})
        request_id = uuid.uuid4().hex
        scope["state"]["request_id"] = request_id
        route = route_name(scope.get("path", ""))
        method = scope.get("method", "")
        start = time.monotonic()
        status_holder = {"status": 0}
        metrics.inflight.inc()

        async def send_wrapper(message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = message.setdefault("headers", [])
                if not any(k.lower() == b"x-request-id" for k, _ in headers):
                    headers.append((b"x-request-id", request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            metrics.inflight.dec()
            status = status_holder["status"] or 500
            t = _type_of(route)
            metrics.requests_total.labels(route=route, type=t, status=str(status)).inc()
            metrics.request_duration.labels(route=route, type=t).observe(duration_ms / 1000)
            if method != "OPTIONS" and route != "ops":  # 运维端点不记审计（设计 §6.2/§15.2）
                state = scope["state"]
                audit.info(json.dumps({
                    "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
                    "request_id": request_id,
                    "user_id": state.get("uid", ""),
                    "user_name": state.get("user_name", ""),
                    "action": state.get("audit_action", route),
                    "mapping_id": state.get("mapping_id", ""),
                    "method": method,
                    "path": scope.get("path", ""),
                    "status": status,
                    "duration_ms": duration_ms,
                    "client_ip": (scope.get("client") or ("",))[0],
                }, ensure_ascii=False))
