"""代理端点 /p/{mapping_id}/{path}（设计 §6.2/§8.2）。

管线：JWT 鉴权 → load_mapping → 可见性（private 仅注册者；public 任意有效身份）→
status=active 拦截（disabled → 404 隐藏）→ http_forward。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..forward.http_forward import stream_http_forward
from ..services import load_mapping
from .deps import get_current_identity, get_db

router = APIRouter(tags=["proxy"])

_PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


async def _handle_proxy(request: Request, mapping_id: str, identity: Identity,
                        session, settings: Settings) -> Response:
    data = await load_mapping(session, request.app.state.redis, mapping_id,
                              settings.cache_ttl)
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    if data["visibility"] == "private" and data["owner_uid"] != identity.user_id:
        raise AppError(403, "FORBIDDEN", "仅注册者可调用该映射")
    # visibility=public：任意有效身份放行（M6 内置映射场景；M2 数据中不出现 public 用户映射）
    if data["status"] != "active":
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在或已禁用")
    if data["type"] != "http":
        # mcp 的 SSE/Streamable 转发随 M3/M4 交付（本计划范围外）
        raise AppError(400, "INVALID_PARAM", "mcp 类型映射转发随 M3 交付，当前仅支持 http")
    request.state.mapping_id = mapping_id
    return await stream_http_forward(request.app.state, data, request)


@router.api_route("/p/{mapping_id}/{path:path}", methods=_PROXY_METHODS)
async def proxy_with_path(request: Request, mapping_id: str, path: str,
                          identity: Identity = Depends(get_current_identity),
                          session=Depends(get_db),
                          settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, session, settings)


@router.api_route("/p/{mapping_id}", methods=_PROXY_METHODS)
async def proxy_root(request: Request, mapping_id: str,
                     identity: Identity = Depends(get_current_identity),
                     session=Depends(get_db),
                     settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, session, settings)
