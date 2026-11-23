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
from .deps import get_current_identity

router = APIRouter(tags=["proxy"])

_PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


async def _handle_proxy(request: Request, mapping_id: str, identity: Identity,
                        settings: Settings) -> Response:
    # DB session 只包住 load_mapping（评审 Important 项）：不走 get_db 依赖——其
    # teardown 在响应发完才执行，SSE/长流会把连接占死（池 10 → ~20 并发即排队）。
    # load_mapping 返回脱管 dict（row_to_dict），session 早关安全。
    async with request.app.state.sessionmaker() as session:
        data = await load_mapping(session, request.app.state.redis, mapping_id,
                                  settings.cache_ttl)
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    # 审计 mapping_id 对后续所有分支生效（含 403/禁用 404/mcp 400，与 mgmt test 接口对齐）
    request.state.mapping_id = mapping_id
    if data["visibility"] == "private" and data["owner_uid"] != identity.user_id:
        raise AppError(403, "FORBIDDEN", "仅注册者可调用该映射")
    # visibility=public：任意有效身份放行（M6 内置映射场景；M2 数据中不出现 public 用户映射）
    if data["status"] != "active":
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在或已禁用")
    if data["type"] != "http":
        # mcp 的 SSE/Streamable 转发随 M3/M4 交付（本计划范围外）
        raise AppError(400, "INVALID_PARAM", "mcp 类型映射转发随 M3 交付，当前仅支持 http")
    return await stream_http_forward(request.app.state, data, request)


@router.api_route("/p/{mapping_id}/{path:path}", methods=_PROXY_METHODS)
async def proxy_with_path(request: Request, mapping_id: str, path: str,
                          identity: Identity = Depends(get_current_identity),
                          settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, settings)


# 注（评审 5d 不采纳）：proxy_root 并非死路由——本 venv 实测 `{path:path}` 路由的
# 正则要求 mapping_id 后必须再有一个 `/`，`/p/{id}`（无尾斜杠）由本路由服务
# （设计 §6.2「path 可为空」）；删除会导致根路径直达上游 404。
@router.api_route("/p/{mapping_id}", methods=_PROXY_METHODS)
async def proxy_root(request: Request, mapping_id: str,
                     identity: Identity = Depends(get_current_identity),
                     settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, settings)
