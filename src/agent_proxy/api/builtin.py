"""内置公共映射（visibility=public）与 OAuth 接口（设计 §6.5 / §14）。

路由清单（M6 交付序，Task 号对应本计划）：
- PUT/GET /api/v1/builtin-mappings/{id}/client     admin OAuth 客户端手动配置（Task 3）
- GET  /api/v1/builtin-mappings                    列表 + 我的绑定状态（Task 4）
- POST /api/v1/builtin-mappings/{id}/authorize     发起授权（Task 4）
- GET  /api/v1/builtin-mappings/{id}/binding       绑定状态查询（Task 4）
- GET  /oauth/callback/{mapping_id}                OAuth 回调（无 JWT，state 关联，Task 4）
- DELETE /api/v1/builtin-mappings/{id}/binding     解绑 + revoke（Task 5）
- POST /api/v1/builtin-mappings/{id}/test          admin 静态 / 绑定用户本人凭证（Task 6）

静态路由注册顺序："" 列表路由先于动态 /{mapping_id}/...（与 mgmt /resolve 先于
/{mapping_id} 同一先例，FastAPI 按注册顺序匹配）。
隐藏存在性：非 public（private/不存在）一律 404 MAPPING_NOT_FOUND。
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..models import OAuthClient
from ..oauth.client import load_client_row, save_oauth_client_row
from ..schemas import OAuthClientOut, OAuthClientSet
from ..services import load_mapping
from ..ssrf import async_validate_upstream_url
from .deps import get_current_identity, get_db, is_admin

log = logging.getLogger("agent_proxy")

router = APIRouter(prefix="/api/v1/builtin-mappings", tags=["builtin"])


async def load_public_mapping(session: AsyncSession, r, mapping_id: str, ttl: int) -> dict:
    """内置接口专用加载：必须 visibility=public；private/不存在一律 404（隐藏存在性）。"""
    data = await load_mapping(session, r, mapping_id, ttl)
    if data is None or data["visibility"] != "public":
        raise AppError(404, "MAPPING_NOT_FOUND", "内置映射不存在")
    return data


def require_oauth_mode(data: dict) -> None:
    """static 公共映射（S3 共享凭据）无需绑定：OAuth 语义一律 400 OAUTH_NOT_APPLICABLE。"""
    if data["auth_mode"] != "oauth":
        raise AppError(400, "OAUTH_NOT_APPLICABLE",
                       "该内置映射为 static 模式（共享静态凭据），无需 OAuth 授权/绑定")


def _client_out(mapping_id: str, row: OAuthClient) -> OAuthClientOut:
    return OAuthClientOut(mapping_id=mapping_id, client_id=row.client_id,
                          client_secret_configured=bool(row.client_secret),
                          token_auth=row.token_auth, authorize_url=row.authorize_url,
                          token_url=row.token_url, scopes=row.scopes, source=row.source)


@router.put("/{mapping_id}/client", response_model=OAuthClientOut)
async def set_oauth_client(request: Request, mapping_id: str, body: OAuthClientSet,
                           identity: Identity = Depends(get_current_identity),
                           session=Depends(get_db),
                           settings: Settings = Depends(get_settings)):
    """手动模式 OAuth 客户端配置（§14.3 降级路径，仅 admin）。client_secret 加密落库；
    重复 PUT 为 upsert（亦可将 dcr 配置覆盖为 manual，管理员兜底手段）。"""
    if not is_admin(identity, settings.admin_role):
        raise AppError(403, "FORBIDDEN", "仅管理员可配置 OAuth 客户端")
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    require_oauth_mode(data)
    # 存 SSRF 校验器的规范化返回值（去尾斜杠）——与 create/update 上游 URL 一致，
    # 消除尾斜杠不对称（authorization_url/redirect_uri 拼接比对依赖规范化形态）。
    try:
        authorize_url = await async_validate_upstream_url(body.authorize_url,
                                                          settings.ssrf_allow_private)
        token_url = await async_validate_upstream_url(body.token_url,
                                                      settings.ssrf_allow_private)
    except ValueError as exc:  # 含 UpstreamNotAllowed（其子类）
        raise AppError(400, "INVALID_PARAM", str(exc))
    await save_oauth_client_row(session, mapping_id, client_id=body.client_id,
                                client_secret_plain=body.client_secret,
                                token_auth=body.token_auth,
                                authorize_url=authorize_url,
                                token_url=token_url, scopes=body.scopes,
                                source="manual", master_key=settings.master_key)
    request.state.audit_action = "oauth_client_set"
    request.state.mapping_id = mapping_id
    row = await load_client_row(session, mapping_id)
    return _client_out(mapping_id, row)


@router.get("/{mapping_id}/client", response_model=OAuthClientOut)
async def get_oauth_client(request: Request, mapping_id: str,
                           identity: Identity = Depends(get_current_identity),
                           session=Depends(get_db),
                           settings: Settings = Depends(get_settings)):
    """查看客户端配置（仅 admin）；secret 只回是否已配置，永不回显值（§14.6）。"""
    if not is_admin(identity, settings.admin_role):
        raise AppError(403, "FORBIDDEN", "仅管理员可查看 OAuth 客户端配置")
    await load_public_mapping(session, request.app.state.redis, mapping_id,
                              settings.cache_ttl)
    row = await load_client_row(session, mapping_id)
    if row is None:
        raise AppError(404, "OAUTH_CLIENT_NOT_CONFIGURED", "尚未配置 OAuth 客户端")
    request.state.mapping_id = mapping_id
    return _client_out(mapping_id, row)
