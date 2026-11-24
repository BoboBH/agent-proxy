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

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import metrics, placeholder
from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..models import OAuthClient, ProxyMapping
from ..oauth.client import (build_authorization_url, build_redirect_uri,
                            build_token_request, consume_state, encode_state_payload,
                            load_client_row, new_code_verifier, new_state,
                            save_oauth_client_row, state_key, validate_front_redirect)
from ..oauth.credential import (decrypt_text, drop_authz_index, encrypt_text,
                                expires_at_from, get_binding_status, load_credential,
                                save_credential, set_authz_index)
from ..schemas import (AuthorizeIn, AuthorizeOut, BindingOut, BuiltinItemOut,
                       OAuthClientOut, OAuthClientSet)
from ..services import build_proxy_url, load_mapping
from ..ssrf import async_validate_upstream_url
from .deps import get_current_identity, get_db, is_admin

log = logging.getLogger("agent_proxy")

router = APIRouter(prefix="/api/v1/builtin-mappings", tags=["builtin"])
# 回调路由：/oauth/callback 无 JWT（身份由 state 关联），独立 router 便于 main 组装；
# metrics/审计 route 归 builtin（middleware.route_name /oauth/* 分支）
callback_router = APIRouter(tags=["builtin"])


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


# 静态列表路由先于动态 /{mapping_id}/... 注册（FastAPI 按注册顺序匹配，/resolve 先例）
@router.get("", response_model=list[BuiltinItemOut])
async def list_builtin_mappings(request: Request,
                                identity: Identity = Depends(get_current_identity),
                                session=Depends(get_db),
                                settings: Settings = Depends(get_settings)):
    """内置映射列表（§6.5）：name / type / proxy_url / 占位符 headers / auth_mode +
    我的绑定状态（页面据此保存完整代理配置）。static 映射 binding=None。"""
    rows = (await session.execute(
        select(ProxyMapping).where(ProxyMapping.visibility == "public")
        .order_by(ProxyMapping.id))).scalars().all()
    out = []
    for row in rows:
        binding = None
        if row.auth_mode == "oauth":
            binding = await get_binding_status(session, request.app.state.redis,
                                               row.mapping_id, identity.user_id)
        out.append(BuiltinItemOut(
            mapping_id=row.mapping_id, name=row.name, type=row.type,
            proxy_url=build_proxy_url(settings, row.mapping_id, row.upstream_url, row.type),
            headers=placeholder.mask_headers(row.upstream_headers or {}),
            auth_mode=row.auth_mode, binding=binding, status=row.status))
    return out


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


@router.post("/{mapping_id}/authorize", response_model=AuthorizeOut)
async def authorize_mapping(request: Request, mapping_id: str, body: AuthorizeIn,
                            identity: Identity = Depends(get_current_identity),
                            session=Depends(get_db),
                            settings: Settings = Depends(get_settings)):
    """发起授权（§14.4）：任意有效用户；front_redirect 域白名单校验 → state +
    PKCE verifier 入 Redis（600s，绑 uid）→ 返回 authorization_url。"""
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    require_oauth_mode(data)
    front_redirect = validate_front_redirect(body.front_redirect,
                                             settings.cors_allowed_origins)
    client_row = await load_client_row(session, mapping_id)
    if client_row is None or not client_row.authorize_url:
        # Task 5 起：无行时改走 ensure_client 的 DCR 分支（§14.3 DCR 优先）
        raise AppError(400, "OAUTH_CLIENT_NOT_CONFIGURED",
                       "该映射尚未配置 OAuth 客户端（管理员手动配置，或首次授权时 DCR）")
    verifier = new_code_verifier()
    state = new_state()
    r = request.app.state.redis
    ttl = settings.oauth_state_ttl
    await r.set(state_key(state), encode_state_payload(
        uid=identity.user_id, mapping_id=mapping_id, code_verifier=verifier,
        front_redirect=front_redirect), ex=ttl)
    await set_authz_index(r, mapping_id, identity.user_id, state, ttl)
    url = build_authorization_url(
        client_row.authorize_url, client_id=client_row.client_id,
        redirect_uri=build_redirect_uri(settings.external_base, mapping_id),
        state=state, code_verifier=verifier, scopes=client_row.scopes)
    request.state.audit_action = "oauth_authorize"
    request.state.mapping_id = mapping_id
    return AuthorizeOut(authorization_url=url)


@router.get("/{mapping_id}/binding", response_model=BindingOut)
async def get_binding_route(request: Request, mapping_id: str,
                            identity: Identity = Depends(get_current_identity),
                            session=Depends(get_db),
                            settings: Settings = Depends(get_settings)):
    """我的绑定状态查询（页面轮询，§14.4 状态机）。"""
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    require_oauth_mode(data)
    binding = await get_binding_status(session, request.app.state.redis, mapping_id,
                                       identity.user_id)
    expires_at = scope = None
    if binding in ("bound", "invalid"):
        cred = await load_credential(session, request.app.state.redis, mapping_id,
                                     identity.user_id)
        if cred is not None:
            expires_at, scope = cred.get("expires_at"), cred.get("scope")
    request.state.mapping_id = mapping_id
    return BindingOut(mapping_id=mapping_id, auth_mode=data["auth_mode"],
                      binding=binding, expires_at=expires_at, scope=scope)


async def _exchange_token(client, token_url: str, headers: dict,
                          form: dict) -> dict | None:
    """code 换 token（§14.4 第 8 步）；网络失败 / 非 200 / 非 JSON → None（上层回跳
    failed）。日志只记异常类型与状态码——token / client_secret 不入任何日志（§14.6）。"""
    try:
        resp = await client.post(token_url, data=form, headers=headers, timeout=15.0)
    except httpx.HTTPError as exc:
        log.warning("token 端点请求失败: %s", type(exc).__name__)
        return None
    if resp.status_code != 200:
        log.warning("token 端点非 200: status=%s", resp.status_code)
        return None
    try:
        return resp.json()
    except ValueError:
        return None


@callback_router.get("/oauth/callback/{mapping_id}")
async def oauth_callback(request: Request, mapping_id: str,
                         session=Depends(get_db),
                         settings: Settings = Depends(get_settings)):
    """OAuth 回调（§14.4，无 JWT——身份由一次性 state 关联）：
    state 原子取删（重放/过期/伪造 → 400 OAUTH_STATE_INVALID）→ 路径 mapping_id
    与 state 载荷一致性校验（防跨映射伪造）→ AS 错误/缺 code → 302 binding=failed →
    code+verifier 换 token → 强制加密落库 uk(mapping_id,uid)（§14.6）→ 302
    front_redirect?binding=success。front_redirect 为 authorize 时已过白名单的存储值。"""
    state = request.query_params.get("state", "")
    code = request.query_params.get("code", "")
    as_error = request.query_params.get("error", "")
    payload = await consume_state(request.app.state.redis, state)
    request.state.uid = payload["uid"]                   # 审计身份来自 state（无 JWT）
    request.state.mapping_id = payload["mapping_id"]
    request.state.audit_action = "oauth_bind"
    if payload["mapping_id"] != mapping_id:
        raise AppError(400, "OAUTH_STATE_INVALID", "state 与回调路径不匹配")
    front_redirect = payload["front_redirect"]
    sep = "&" if "?" in front_redirect else "?"
    if as_error or not code:
        # 用户在 AS 拒绝授权 / AS 错误重定向 / 缺 code：不落凭证，回跳失败态
        metrics.oauth_actions_total.labels(action="fail").inc()
        reason = as_error or "missing_code"
        return RedirectResponse(
            f"{front_redirect}{sep}binding=failed&reason={reason}", status_code=302)
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl)
    require_oauth_mode(data)
    client_row = await load_client_row(session, mapping_id)
    if client_row is None or not client_row.token_url:
        raise AppError(400, "OAUTH_CLIENT_NOT_CONFIGURED",
                       "OAuth 客户端配置缺失，无法换取 token")
    headers, form = build_token_request(
        client_row.token_auth, client_id=client_row.client_id,
        client_secret=(decrypt_text(client_row.client_secret, settings.master_key)
                       if client_row.client_secret else None),
        extra={"grant_type": "authorization_code", "code": code,
               "redirect_uri": build_redirect_uri(settings.external_base, mapping_id),
               "code_verifier": payload["code_verifier"]})
    tokens = await _exchange_token(request.app.state.http_client,
                                   client_row.token_url, headers, form)
    if tokens is None or not tokens.get("access_token"):
        metrics.oauth_actions_total.labels(action="fail").inc()
        return RedirectResponse(
            f"{front_redirect}{sep}binding=failed&reason=token_exchange",
            status_code=302)
    await save_credential(session, request.app.state.redis, mapping_id, payload["uid"],
                          access_token_ct=encrypt_text(tokens["access_token"],
                                                       settings.master_key),
                          refresh_token_ct=(encrypt_text(tokens["refresh_token"],
                                                         settings.master_key)
                                            if tokens.get("refresh_token") else None),
                          expires_at=expires_at_from(tokens.get("expires_in")),
                          scope=tokens.get("scope"), master_key=settings.master_key)
    await drop_authz_index(request.app.state.redis, mapping_id, payload["uid"])
    metrics.oauth_actions_total.labels(action="bind").inc()
    return RedirectResponse(f"{front_redirect}{sep}binding=success", status_code=302)
