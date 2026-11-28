"""代理端点 /p/{mapping_id}/{path}（设计 §6.2 / §8.2 / §8.3）。

管线：JWT 鉴权 → load_mapping → 可见性（private 仅注册者；public 任意有效身份）→
status=active 拦截（disabled → 404 隐藏）→ 按映射 type 分发：
- http：前缀拼接流式转发（§8.2）；
- mcp：GET/HEAD 且命中注册端点路径 → SSE 初始连接（endpoint 事件改写，§8.3 第 1 行）；
  其余方法/路径按上游 origin 根还原，复用 http 流式管线（§8.3 第 2 行 / §8.5 统一骨架）。
  M4：SSE 管线同时服务 Streamable 服务端推送流（GET /mcp，rewriter 字节级无操作，
  §8.4 注记）。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from app.services.auth import Identity
from app.env import Settings, get_settings
from app.services.errors import AppError
from app.services.forward.http_forward import (assert_safe_sub_path, split_sub_path,
                                  stream_http_forward)
from app.services.forward.mcp_sse import (build_origin_target, registered_endpoint_path,
                                  stream_sse_forward)
from app.services.oauth import credential as oauth_credential
from app.services.mapping_service import load_mapping
from app.services.concurrency import acquire_guard
from app.services.load_stats import record_hit
from app.routers.deps import get_current_identity

router = APIRouter(tags=["proxy"])

_PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


async def _handle_proxy(request: Request, mapping_id: str, identity: Identity,
                        settings: Settings) -> Response:
    # DB session 只包住 load_mapping 与 OAuth 凭证获取（M6）：不走 get_db 依赖——其
    # teardown 在响应发完才执行，SSE/长流会把连接占死（池 10 → ~20 并发即排队）。
    # load_mapping 返回脱管 dict（headers 已解密为明文，收尾批次密文化读取路径），
    # session 早关安全。
    async with request.app.state.sessionmaker() as session:
        data = await load_mapping(session, request.app.state.redis, mapping_id,
                                  settings.cache_ttl, settings.master_key)
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
        if data["auth_mode"] == "oauth":
            # M6 按用户注入（§14.5，设计 v2 起经 forced 通道）：查本人凭证（无/invalid
            # → 401 OAUTH_BINDING_REQUIRED 附授权引导）；expires_at-60s 内刷新（Redis 锁
            # 防并发）。出站 Authorization 恒为本人 access_token 且**压过调用方自带
            # Authorization 透传头**——凭证托管语义（§14.1）不被绕过。static 映射下
            # forced=None：调用方 Authorization 覆盖存储值（设计 v2 调用方优先）。
            token = await oauth_credential.get_callable_credential(
                session, request.app.state.redis, request.app.state, data,
                identity.user_id, settings.master_key, request.state.request_id)
            forced = {"authorization": f"Bearer {token}"}
        else:
            forced = None
    # 按映射并发上限（设计 v4.2，慢上游隔离）：映射内并发达上限时，**该映射自己的**
    # 超额请求等待 MAPPING_MAX_CONCURRENCY 窗口后 503 PROXY_BUSY——全局连接池不被
    # 单一慢映射占满，其他映射不受影响。闸门生命周期与上游连接对齐：管线在响应流
    # 结束 / 客户端断开的 finally 释放；此处 except 兜底覆盖流开始前的错误路径。
    guard = None
    if settings.mapping_max_concurrency > 0:
        guard = await acquire_guard(mapping_id, settings.mapping_max_concurrency,
                                    timeout=settings.upstream_pool_timeout)
    # 实时负载计数（管理页「实时负载」）：按映射的最近 5 分钟请求数（Redis 滑动
    # 窗口）；写入失败不阻断转发（load_stats 内部兜底）。503 被拒的请求也计入
    # （record 在闸门之前——热点映射对运维可见）
    await record_hit(request.app.state.redis, mapping_id)
    try:
        if data["type"] == "mcp":
            # 路径分发（§8.3 表，M4 起同时服务 Streamable）：仅 GET/HEAD 且命中注册
            # 端点路径 → SSE 解析管线（stream_sse_forward 不转发请求体，故非 GET/HEAD
            # 不走此分支）；其余方法/路径按上游 origin 根还原后复用 http 流式管线。
            # M4 分发语义定稿（不新增 transport 字段）：Streamable 上游的 POST/DELETE
            # （JSON-RPC 调用 / 会话结束）本就走 origin 根还原的 http 管线；GET /mcp
            # （服务端推送流）进 SSE 解析管线——rewriter 仅改写 `event: endpoint` 的
            # data 行，Streamable 流只有 message 事件 → 字节级无操作透传，read=None /
            # Connection: close / sse_active 计数对推送流语义同样成立。一条分发表即可
            # 同时正确服务两种传输；设计 §5.1 无 transport 列，不为零行为差异引入
            # schema/DB/缓存连带变更（评审定稿记录，设计 §8.4 注记同步）。
            # 评审 Issue 2（M3）：裸 origin 注册（端点路径为 /）时根路径 /p/{id} 与
            # /p/{id}/ 同为注册端点——空 sub_path 归一为 / 参与匹配
            sub_path = split_sub_path(request.scope["path"], mapping_id)
            assert_safe_sub_path(sub_path)
            if request.method in ("GET", "HEAD") and \
                    (sub_path or "/") == registered_endpoint_path(data["upstream_url"]):
                return await stream_sse_forward(request.app.state, data, request,
                                                forced_headers=forced,
                                                auth_header=settings.proxy_auth_header,
                                                guard=guard)
            target = build_origin_target(data["upstream_url"], sub_path, request.url.query)
            return await stream_http_forward(request.app.state, data, request,
                                             target_override=target, metrics_type="mcp",
                                             forced_headers=forced,
                                             auth_header=settings.proxy_auth_header,
                                             guard=guard)
        return await stream_http_forward(request.app.state, data, request,
                                         forced_headers=forced,
                                         auth_header=settings.proxy_auth_header,
                                         guard=guard)
    except BaseException:
        # 流开始前的任何错误路径（上游连接失败/超时/重定向中止等）释放闸门；
        # 流式阶段的释放由管线响应流的 finally 负责（Guard 幂等，双保险不冲突）
        if guard:
            guard.release()
        raise


@router.api_route("/p/{mapping_id}/{path:path}", methods=_PROXY_METHODS)
async def proxy_with_path(request: Request, mapping_id: str, path: str,
                          identity: Identity = Depends(get_current_identity),
                          settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, settings)


# 注（M2 评审 5d 不采纳，保留）：proxy_root 并非死路由——`{path:path}` 路由的正则
# 要求 mapping_id 后必须再有一个 `/`，`/p/{id}`（无尾斜杠）由本路由服务
# （设计 §6.2「path 可为空」）；mcp 裸 origin 注册（端点路径为 /）时根路径已走
# SSE 管线（评审 Issue 2：空 sub_path 归一为 / 参与注册端点匹配），非裸 origin
# 注册的根路径才按 origin 根还原直达 origin。
@router.api_route("/p/{mapping_id}", methods=_PROXY_METHODS)
async def proxy_root(request: Request, mapping_id: str,
                     identity: Identity = Depends(get_current_identity),
                     settings: Settings = Depends(get_settings)) -> Response:
    return await _handle_proxy(request, mapping_id, identity, settings)
