"""代理端点 /p/{mapping_id}/{path}（设计 §6.2 / §8.2 / §8.3）。

管线：JWT 鉴权 → load_mapping → 可见性（private 仅注册者；public 任意有效身份）→
status=active 拦截（disabled → 404 隐藏）→ 按映射 type 分发：
- http：前缀拼接流式转发（§8.2）；
- mcp：GET/HEAD 且命中注册端点路径 → SSE 初始连接（endpoint 事件改写，§8.3 第 1 行）；
  其余方法/路径按上游 origin 根还原，复用 http 流式管线（§8.3 第 2 行 / §8.5 统一骨架）。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..forward.http_forward import (assert_safe_sub_path, split_sub_path,
                                    stream_http_forward)
from ..forward.mcp_sse import (build_origin_target, registered_endpoint_path,
                               stream_sse_forward)
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
    # 审计 mapping_id 对后续所有分支生效（含 403/禁用 404）
    request.state.mapping_id = mapping_id
    # metrics type 标签（§15.2 http/mcp；中间件回读 state）
    request.state.proxy_type = "mcp" if data["type"] == "mcp" else "http"
    if data["visibility"] == "private" and data["owner_uid"] != identity.user_id:
        raise AppError(403, "FORBIDDEN", "仅注册者可调用该映射")
    # visibility=public：任意有效身份放行（M6 内置映射场景；M3 数据中不出现 public 用户映射）
    if data["status"] != "active":
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在或已禁用")
    if data["type"] == "mcp":
        # 路径分发（§8.3 表）：仅 GET/HEAD 且命中注册端点路径 → SSE 初始连接
        # （stream_sse_forward 不转发请求体，故非 GET/HEAD 不走此分支）；其余
        # 路径按上游 origin 根还原后复用 http 流式管线
        sub_path = split_sub_path(request.scope["path"], mapping_id)
        assert_safe_sub_path(sub_path)
        if request.method in ("GET", "HEAD") and \
                sub_path == registered_endpoint_path(data["upstream_url"]):
            return await stream_sse_forward(request.app.state, data, request)
        target = build_origin_target(data["upstream_url"], sub_path, request.url.query)
        return await stream_http_forward(request.app.state, data, request,
                                         target_override=target, metrics_type="mcp")
    return await stream_http_forward(request.app.state, data, request)


@router.api_route("/p/{mapping_id}/{path:path}", methods=_PROXY_METHODS)
async def proxy_with_path(request: Request, mapping_id: str, path: str,
                          identity: Identity = Depends(get_current_identity),
                          settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, settings)


# 注（M2 评审 5d 不采纳，保留）：proxy_root 并非死路由——`{path:path}` 路由的正则
# 要求 mapping_id 后必须再有一个 `/`，`/p/{id}`（无尾斜杠）由本路由服务
# （设计 §6.2「path 可为空」）；mcp 根路径按 origin 根还原直达 origin。
@router.api_route("/p/{mapping_id}", methods=_PROXY_METHODS)
async def proxy_root(request: Request, mapping_id: str,
                     identity: Identity = Depends(get_current_identity),
                     settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, settings)
