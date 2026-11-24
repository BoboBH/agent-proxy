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
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import metrics, placeholder
from ..auth import Identity
from ..config import Settings, get_settings
from ..errors import AppError
from ..forward.http_forward import probe_http_mapping
from ..forward.mcp_streamable import probe_mcp_mapping
from ..models import OAuthClient, ProxyMapping
from ..oauth.client import (build_authorization_url, build_redirect_uri,
                            build_token_request, consume_state, encode_state_payload,
                            ensure_client, load_client_row, new_code_verifier,
                            new_state, save_oauth_client_row, state_key,
                            validate_front_redirect)
from ..oauth.credential import (decrypt_text, delete_credential, drop_authz_index,
                                encrypt_text, expires_at_from, get_binding_status,
                                get_callable_credential, load_credential,
                                save_credential, set_authz_index)
from ..schemas import (AuthorizeIn, AuthorizeOut, BindingOut, BuiltinItemOut,
                       MappingTestOut, OAuthClientOut, OAuthClientSet)
from ..services import build_proxy_url, load_mapping, plain_headers
from ..ssrf import async_validate_upstream_url
from .deps import get_current_identity, get_db, is_admin

log = logging.getLogger("agent_proxy")

router = APIRouter(prefix="/api/v1/builtin-mappings", tags=["builtin"])
# 回调路由：/oauth/callback 无 JWT（身份由 state 关联），独立 router 便于 main 组装；
# metrics/审计 route 归 builtin（middleware.route_name /oauth/* 分支）
callback_router = APIRouter(tags=["builtin"])


async def load_public_mapping(session: AsyncSession, r, mapping_id: str, ttl: int,
                              master_key: str) -> dict:
    """内置接口专用加载：必须 visibility=public；private/不存在一律 404（隐藏存在性）。
    损坏密文经 load_mapping → None → 同样 404（fail-closed，不返回部分明文）。"""
    data = await load_mapping(session, r, mapping_id, ttl, master_key)
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
            # 行内 headers 为密文（收尾批次强制加密）：列表只展示占位符，也须经
            # plain_headers 解密取键名——直接迭代密文字符串会把字符当 header 名
            headers=placeholder.mask_headers(
                plain_headers(row.upstream_headers, settings.master_key)),
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
                                     settings.cache_ttl, settings.master_key)
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
                              settings.cache_ttl, settings.master_key)
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
                                     settings.cache_ttl, settings.master_key)
    require_oauth_mode(data)
    front_redirect = validate_front_redirect(body.front_redirect,
                                             settings.cors_allowed_origins)
    redirect_uri = build_redirect_uri(settings.external_base, mapping_id)
    client = await ensure_client(session, request.app.state, data,
                                 settings.master_key, redirect_uri)
    verifier = new_code_verifier()
    state = new_state()
    r = request.app.state.redis
    ttl = settings.oauth_state_ttl
    await r.set(state_key(state), encode_state_payload(
        uid=identity.user_id, mapping_id=mapping_id, code_verifier=verifier,
        front_redirect=front_redirect), ex=ttl)
    await set_authz_index(r, mapping_id, identity.user_id, state, ttl)
    url = build_authorization_url(
        client["authorize_url"], client_id=client["client_id"],
        redirect_uri=redirect_uri, state=state, code_verifier=verifier,
        scopes=client["scopes"])
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
                                     settings.cache_ttl, settings.master_key)
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


@router.delete("/{mapping_id}/binding", status_code=204)
async def unbind_mapping(request: Request, mapping_id: str,
                         identity: Identity = Depends(get_current_identity),
                         session=Depends(get_db),
                         settings: Settings = Depends(get_settings)):
    """解绑（§14.4）：删除本地凭证；提供方支持时（dcr 客户端经 discovery 拿到
    revocation_endpoint）同时 best-effort 调用 revoke——revoke 失败仅 WARN，
    不影响本地解绑；manual 模式无 revoke 端点配置 → 仅删本地凭证。密文不可解
    （MASTER_KEY 变更 / 行损坏）→ 删本地坏行 + 204 引导重新授权（终审遗留 4：
    原为 500 死局）。"""
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl, settings.master_key)
    require_oauth_mode(data)
    r = request.app.state.redis
    cred = await load_credential(session, r, mapping_id, identity.user_id)
    if cred is None:
        raise AppError(404, "MAPPING_NOT_FOUND", "尚未绑定，无需解绑")
    try:
        access_plain = decrypt_text(cred["access_token"], settings.master_key)
        refresh_plain = (decrypt_text(cred["refresh_token"], settings.master_key)
                         if cred.get("refresh_token") else None)
    except AppError:
        # 密文不可解：revoke 无从谈起（明文已不可得），本地删除坏行本就是更优
        # 恢复路径——删行 + 204 + 引导重新授权，绝不 500 死局（凭证不可解 →
        # 解绑也 500 → 用户被锁死在坏行上）
        log.warning("解绑前解密失败（密文损坏？）：%s/%s 仅删本地凭证，请重新授权",
                    mapping_id, identity.user_id)
        await delete_credential(session, r, mapping_id, identity.user_id)
        await drop_authz_index(r, mapping_id, identity.user_id)
        metrics.oauth_actions_total.labels(action="unbind").inc()
        request.state.audit_action = "oauth_unbind"
        request.state.mapping_id = mapping_id
        return Response(status_code=204)
    deleted = await delete_credential(session, r, mapping_id, identity.user_id)
    if not deleted:
        # 并发解绑窗口（load 与 delete 之间被并发请求删行）：显式 404——assert
        # 会被 python -O 剥离（评审 Minor a）
        raise AppError(404, "MAPPING_NOT_FOUND", "尚未绑定，无需解绑")
    await drop_authz_index(r, mapping_id, identity.user_id)   # §5.3：解绑删 authorizing 索引
    # revoke best-effort ×2（access + refresh，评审 Important 3）：本地删除后
    # refresh token 明文已无处可寻，这是吊销它的最后机会；两者皆失败仅 WARN，
    # 不影响本地解绑（本地删除是不可回退语义）
    try:
        client = await ensure_client(session, request.app.state, data,
                                     settings.master_key,
                                     build_redirect_uri(settings.external_base, mapping_id))
        rev = client.get("revocation_endpoint")
        if rev:
            revocations = [(access_plain, "access_token")]
            if refresh_plain:
                revocations.append((refresh_plain, "refresh_token"))
            for token_plain, hint in revocations:
                headers, form = build_token_request(
                    client["token_auth"], client_id=client["client_id"],
                    client_secret=client["client_secret"],
                    extra={"token": token_plain, "token_type_hint": hint})
                resp = await request.app.state.http_client.post(rev, data=form,
                                                                headers=headers,
                                                                timeout=10.0)
                if resp.status_code != 200:
                    log.warning("revoke 非 200: hint=%s status=%s（本地凭证已删除）",
                                hint, resp.status_code)
    except AppError as exc:
        log.warning("revoke 前置（discovery/ensure_client）失败（忽略）: %s", exc.message)
    except httpx.HTTPError as exc:
        log.warning("revoke 请求失败（忽略）: %s", type(exc).__name__)
    metrics.oauth_actions_total.labels(action="unbind").inc()
    request.state.audit_action = "oauth_unbind"
    request.state.mapping_id = mapping_id
    return Response(status_code=204)


@router.post("/{mapping_id}/test", response_model=MappingTestOut)
async def test_builtin_mapping(request: Request, mapping_id: str,
                               identity: Identity = Depends(get_current_identity),
                               session=Depends(get_db),
                               settings: Settings = Depends(get_settings)):
    """公共映射 test（§6.5 / §6.6）：admin 测静态配置（不注入）；其他用户必须已绑定，
    以本人凭证执行对应验证（mcp 走探测式 auto）。static 公共映射对非 admin → 400
    OAUTH_NOT_APPLICABLE（无「本人凭证」语义，与 PUT client 守卫对称——原 401
    引导 authorize 而 static authorize 必 400，误导死循环）；OAuth 映射无凭证用户
    → 401 OAUTH_BINDING_REQUIRED（§6.6 安全边界）；上游以 401 拒绝 → ok=false +
    detail 追加「重新授权」提示（探测语义沿 M4：非 2xx 不回落直接判失败）。"""
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl, settings.master_key)
    request.state.audit_action = "test_mapping"
    request.state.mapping_id = mapping_id
    injected = False
    if is_admin(identity, settings.admin_role):
        probe_data = data                                 # admin：静态配置实测（不注入）
    else:
        # M6 终审 Important 1：非 admin + static 公共映射无本人凭证可注入——原走
        # get_callable_credential 返回误导性 401 OAUTH_BINDING_REQUIRED（引导去
        # authorize，但 static authorize 本身必 400，死循环）；与 PUT client 的
        # require_oauth_mode 守卫对称，直接 400 OAUTH_NOT_APPLICABLE。
        require_oauth_mode(data)
        token = await get_callable_credential(session, request.app.state.redis,
                                              request.app.state, data,
                                              identity.user_id, settings.master_key,
                                              request.state.request_id)
        probe_data = {**data, "upstream_headers": {**data["upstream_headers"],
                                                   "authorization": f"Bearer {token}"}}
        injected = True
    if probe_data["type"] == "mcp":
        result = await probe_mcp_mapping(request.app.state, probe_data)
    else:
        result = await probe_http_mapping(request.app.state, probe_data)
    if injected and not result["ok"] and result.get("status_code") == 401:
        result["detail"] += "（凭证可能已失效，请重新授权）"
    return result


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
        payload = resp.json()
    except ValueError:
        return None
    # 非 JSON object（数组/字符串）：按换 token 失败处理——裸 .get 会 500（评审 Minor c）
    return payload if isinstance(payload, dict) else None


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
        # reason 是 AS 可控字符串（Task 4 评审携带批）：urlencode 后作为单一参数值
        # 回跳——特殊字符不得拆出新 query 参数（防参数注入）。
        reason = urlencode({"reason": as_error or "missing_code"})
        return RedirectResponse(
            f"{front_redirect}{sep}binding=failed&{reason}", status_code=302)
    data = await load_public_mapping(session, request.app.state.redis, mapping_id,
                                     settings.cache_ttl, settings.master_key)
    require_oauth_mode(data)
    client = await ensure_client(session, request.app.state, data,
                                 settings.master_key,
                                 build_redirect_uri(settings.external_base, mapping_id))
    headers, form = build_token_request(
        client["token_auth"], client_id=client["client_id"],
        client_secret=client["client_secret"],
        extra={"grant_type": "authorization_code", "code": code,
               "redirect_uri": build_redirect_uri(settings.external_base, mapping_id),
               "code_verifier": payload["code_verifier"]})
    tokens = await _exchange_token(request.app.state.http_client,
                                   client["token_url"], headers, form)
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
