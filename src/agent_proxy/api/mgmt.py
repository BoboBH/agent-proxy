"""管理接口 /api/v1/mappings（全部要求系统 JWT）。"""
from __future__ import annotations

import logging
import re
from urllib.parse import unquote, urlparse

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import select

from .. import placeholder
from ..models import ProxyMapping
from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..forward.http_forward import probe_http_mapping
from ..forward.mcp_streamable import probe_mcp_mapping
from ..mapping_id import MAPPING_ID_RE
from ..schemas import (ListItemOut, MappingCreate, MappingDetailOut, MappingTestOut,
                       MappingUpdate, RegisteredOut)
from ..services import (build_proxy_url, create_mapping, delete_mapping, get_owned,
                        list_mappings, row_to_dict, update_mapping)
from .deps import get_current_identity, get_db, is_admin

log = logging.getLogger("agent_proxy")
router = APIRouter(prefix="/api/v1/mappings", tags=["mgmt"])

_PROXY_PATH_RE = re.compile(r"^/p/([A-Za-z0-9]{12})(/.*)?$")


def parse_proxy_url(raw: str, external_base: str = "") -> str:
    """proxy_url（URL 编码）或裸 12 位 mapping_id → mapping_id。无法解析 → 400。

    加固（终审债务）：带 netloc 的输入，host 必须等于 EXTERNAL_BASE 的 host，
    防止把任意第三方 URL 当作本服务代理地址解析（探测/混淆）。
    """
    value = unquote(raw)
    if MAPPING_ID_RE.match(value):
        return value
    parsed = urlparse(value)
    if parsed.netloc:
        base_host = urlparse(external_base).hostname if external_base else None
        if not base_host or (parsed.hostname or "") != base_host:
            raise AppError(400, "INVALID_PARAM", "代理地址 host 与本服务不符")
    matched = _PROXY_PATH_RE.match(parsed.path)
    if not matched:
        raise AppError(400, "INVALID_PARAM", "无法解析为本服务代理地址")
    return matched.group(1)


def _registered_out(settings: Settings, data: dict) -> RegisteredOut:
    return RegisteredOut(
        mapping_id=data["mapping_id"], name=data.get("name"), type=data["type"],
        visibility=data["visibility"], auth_mode=data["auth_mode"],
        proxy_url=build_proxy_url(settings, data["mapping_id"], data["upstream_url"], data["type"]),
        # 设计 v3：回显 headers = 代理调用配置（仅 X-Proxy-Authorization，值
        # {{RUNTIME_TOKEN}} 占位符，平台运行时替换）——与输入结构一致，agent 拿到
        # 即可用；真实地址/header 只在 resolve/详情出现
        headers=placeholder.proxy_call_headers(), status=data["status"])


def _detail_out(settings: Settings, data: dict) -> MappingDetailOut:
    base = _registered_out(settings, data).model_dump()
    # 详情/resolve 是 owner 查看真实凭据的入口（audit: view_credentials）→ 返回真实 headers，
    # 仅 POST/PUT 响应脱敏（RegisteredOut）。
    base.update(upstream_url=data["upstream_url"], headers=data["upstream_headers"],
                test_request=data.get("test_request"),
                created_at=data.get("created_at"), updated_at=data.get("updated_at"))
    return MappingDetailOut(**base)


# 注意：静态路由 /resolve 必须先于动态路由 /{mapping_id} 注册（FastAPI 按注册顺序匹配）。
@router.get("/resolve", response_model=MappingDetailOut)
async def resolve_mapping(request: Request, proxy_url: str = Query(None),
                          name: str = Query(None, max_length=128),
                          identity: Identity = Depends(get_current_identity),
                          session=Depends(get_db), settings: Settings = Depends(get_settings)):
    """取回原始 MCP/HTTP 配置（name、真实 url、真实 header，owner 凭据查看语义）。

    两种寻址（二选一，同传/均缺 → 400）：
    - proxy_url：12 位 mapping_id 或完整代理地址（既有语义）；
    - name（设计 v3）：按映射名称取本人映射（重名取最新创建；恒限本人——
      admin 跨属主请走 id/代理地址形态，避免重名歧义）。
    """
    if bool(proxy_url) == bool(name):
        raise AppError(400, "INVALID_PARAM", "proxy_url 与 name 二选一")
    if name:
        stmt = (select(ProxyMapping)
                .where(ProxyMapping.name == name, ProxyMapping.owner_uid == identity.user_id)
                .order_by(ProxyMapping.id.desc()).limit(1))
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is None:
            raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
        mapping_id = row.mapping_id
    else:
        mapping_id = parse_proxy_url(proxy_url, settings.external_base)
    data = await get_owned(session, request.app.state.redis, mapping_id,
                           identity.user_id, settings.cache_ttl, settings.master_key,
                           admin_override=is_admin(identity, settings.admin_role))
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.audit_action = "view_credentials"
    request.state.mapping_id = data["mapping_id"]
    return _detail_out(settings, data)


@router.post("", status_code=201, response_model=RegisteredOut)
async def create_mapping_route(request: Request, body: MappingCreate,
                               identity: Identity = Depends(get_current_identity),
                               session=Depends(get_db),
                               settings: Settings = Depends(get_settings)):
    if body.visibility == "public" and not is_admin(identity, settings.admin_role):
        raise AppError(403, "FORBIDDEN", "仅管理员可创建 public 映射")
    try:
        row = await create_mapping(
            session, request.app.state.redis, settings, identity.user_id,
            type_=body.type, name=body.name, visibility=body.visibility,
            upstream_url=body.upstream_url, headers=body.headers,
            test_request=body.test_request, auth_mode=body.auth_mode)
    except ValueError as exc:  # 含 UpstreamNotAllowed（其子类，header 校验/SSRF 均归 400）
        raise AppError(400, "INVALID_PARAM", str(exc))
    request.state.mapping_id = row.mapping_id
    return _registered_out(settings, row_to_dict(row, settings.master_key))


@router.get("", response_model=list[ListItemOut])
async def list_my_mappings(request: Request,
                           identity: Identity = Depends(get_current_identity),
                           session=Depends(get_db), settings: Settings = Depends(get_settings),
                           page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100)):
    rows = await list_mappings(session, identity.user_id,
                               limit=page_size, offset=(page - 1) * page_size)
    return [ListItemOut(mapping_id=r.mapping_id, name=r.name, type=r.type,
                        upstream_url=r.upstream_url,
                        proxy_url=build_proxy_url(settings, r.mapping_id, r.upstream_url, r.type),
                        status=r.status,
                        created_at=r.created_at.isoformat() if r.created_at else None,
                        updated_at=r.updated_at.isoformat() if r.updated_at else None)
            for r in rows]


@router.get("/{mapping_id}", response_model=MappingDetailOut)
async def get_detail(request: Request, mapping_id: str,
                     identity: Identity = Depends(get_current_identity),
                     session=Depends(get_db), settings: Settings = Depends(get_settings)):
    data = await get_owned(session, request.app.state.redis, mapping_id,
                           identity.user_id, settings.cache_ttl, settings.master_key,
                           admin_override=is_admin(identity, settings.admin_role))
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.audit_action = "view_credentials"
    request.state.mapping_id = data["mapping_id"]
    return _detail_out(settings, data)


@router.put("/{mapping_id}", response_model=RegisteredOut)
async def update_mapping_route(request: Request, mapping_id: str, body: MappingUpdate,
                               identity: Identity = Depends(get_current_identity),
                               session=Depends(get_db),
                               settings: Settings = Depends(get_settings)):
    if body.visibility == "public" and not is_admin(identity, settings.admin_role):
        raise AppError(403, "FORBIDDEN", "仅管理员可设置 public 可见性")
    patch = body.model_dump(exclude_unset=True)
    try:
        data = await update_mapping(session, request.app.state.redis, settings,
                                    mapping_id, identity.user_id,
                                    admin_override=is_admin(identity, settings.admin_role),
                                    **patch)
    except ValueError as exc:  # 含 UpstreamNotAllowed（其子类，header 校验/SSRF 均归 400）
        raise AppError(400, "INVALID_PARAM", str(exc))
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.mapping_id = data["mapping_id"]
    return _registered_out(settings, data)


@router.delete("/{mapping_id}", status_code=204)
async def delete_mapping_route(request: Request, mapping_id: str,
                               identity: Identity = Depends(get_current_identity),
                               session=Depends(get_db),
                               settings: Settings = Depends(get_settings)):
    ok = await delete_mapping(session, request.app.state.redis, mapping_id,
                              identity.user_id,
                              admin_override=is_admin(identity, settings.admin_role))
    if not ok:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.mapping_id = mapping_id
    return Response(status_code=204)


@router.post("/{mapping_id}/test", response_model=MappingTestOut)
async def test_mapping_route(request: Request, mapping_id: str,
                             identity: Identity = Depends(get_current_identity),
                             session=Depends(get_db),
                             settings: Settings = Depends(get_settings)):
    """配置有效性测试（设计 §6.6）：仅注册者、仅已注册映射（防探测滥用）。"""
    data = await get_owned(session, request.app.state.redis, mapping_id,
                           identity.user_id, settings.cache_ttl, settings.master_key,
                           admin_override=is_admin(identity, settings.admin_role))
    if data is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "映射不存在")
    request.state.audit_action = "test_mapping"
    request.state.mapping_id = data["mapping_id"]
    if data["type"] == "mcp":
        # mcp test 探测式 auto（M4 定稿，§6.6）：先 Streamable initialize 硬判定，
        # 端点拒绝 POST（405/404/406）回落 SSE 握手探测（理由见 probe_mcp_mapping
        # docstring：不新增 transport 字段、不用路径后缀启发式）
        return await probe_mcp_mapping(request.app.state, data)
    return await probe_http_mapping(request.app.state, data)
