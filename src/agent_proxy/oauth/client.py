"""OAuth 客户端层（设计 §14.3）：DCR（RFC 7591）优先 + 手动配置兼容。

本模块 Task 1 交付纯逻辑：PKCE(S256)、state 载荷、authorization_url /
redirect_uri / token 请求 / DCR 载荷组装、token_auth 归一、front_redirect 域
白名单；DB 行存取（load/save）、state 一次性消费（Redis MULTI）Task 3–4 交付，
ensure_client（discovery → DCR 注册 / manual 直读）Task 5 交付。

安全锚点（§14.6）：
- PKCE(S256) 必须——challenge = BASE64URL(SHA256(verifier))（剥 '='）；
- state 一次性、600s TTL、绑定 uid（防 CSRF / 顶号）；
- redirect_uri 精确等于 {EXTERNAL_BASE}/oauth/callback/{mapping_id}；
- front_redirect 仅允许 CORS_ALLOWED_ORIGINS 精确 origin（防开放重定向）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
from urllib.parse import urlencode, urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..errors import AppError
from ..models import OAuthClient
from .credential import decrypt_text, encrypt_text
from .discovery import DiscoveryError, discover_authorization_server, upstream_origin

log = logging.getLogger("agent_proxy")

STATE_KEY_PREFIX = "ap:oauth:state:"


# ---------- PKCE（RFC 7636） ----------

def new_code_verifier() -> str:
    """43-128 字符 base64url；取 32 字节随机 → 43 字符。"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


def code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# ---------- state（ap:oauth:state:{state}，一次性 600s 绑 uid） ----------

def new_state() -> str:
    return secrets.token_hex(16)                       # 128bit，URL 安全


def state_key(state: str) -> str:
    return f"{STATE_KEY_PREFIX}{state}"


def encode_state_payload(*, uid: int, mapping_id: str, code_verifier: str,
                         front_redirect: str) -> str:
    return json.dumps({"uid": uid, "mapping_id": mapping_id,
                       "code_verifier": code_verifier,
                       "front_redirect": front_redirect}, ensure_ascii=False)


def decode_state_payload(raw: str | bytes) -> dict:
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise AppError(400, "OAUTH_STATE_INVALID", "state 载荷非法") from exc
    required = ("uid", "mapping_id", "code_verifier", "front_redirect")
    # 类型守卫：uid 必须为 int（收尾批次整数化：拼缓存键 / 落库 proxy_oauth_credential.uid
    # BIGINT 的输入；str/bool/容器等畸形一律 OAUTH_STATE_INVALID），mapping_id 必须为 str。
    if (not isinstance(payload, dict)
            or not all(k in payload for k in required)
            or not isinstance(payload["uid"], int) or isinstance(payload["uid"], bool)
            or not isinstance(payload["mapping_id"], str)):
        raise AppError(400, "OAUTH_STATE_INVALID", "state 载荷非法")
    return payload


# ---------- URL / 载荷组装 ----------

def build_redirect_uri(external_base: str, mapping_id: str) -> str:
    """精确值（§14.6）：{EXTERNAL_BASE}/oauth/callback/{mapping_id}，不拼额外路径。"""
    return f"{external_base.rstrip('/')}/oauth/callback/{mapping_id}"


def build_authorization_url(authorize_url: str, *, client_id: str, redirect_uri: str,
                            state: str, code_verifier: str,
                            scopes: str | None) -> str:
    params = {"response_type": "code", "client_id": client_id,
              "redirect_uri": redirect_uri, "state": state,
              "code_challenge": code_challenge_s256(code_verifier),
              "code_challenge_method": "S256"}
    if scopes:
        params["scope"] = scopes
    sep = "&" if urlparse(authorize_url).query else "?"
    return f"{authorize_url}{sep}{urlencode(params)}"


def build_dcr_payload(client_name: str, redirect_uri: str) -> dict:
    """RFC 7591 §2 注册载荷：redirect_uris 精确单一值 + PKCE S256 声明。"""
    return {"client_name": client_name, "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
            "code_challenge_method": "S256"}


def normalize_token_auth(value: str | None) -> str:
    """token_auth 白名单归一；AS 未声明 / 声明了未实现形态 → client_secret_post
    （RFC 7591 注册时我方显式声明该形态，此处仅兜底历史脏数据）。"""
    if value in ("client_secret_basic", "client_secret_post", "none"):
        return value
    return "client_secret_post"


def build_token_request(token_auth: str, *, client_id: str,
                        client_secret: str | None,
                        extra: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """按 token_auth 组装 token/revoke 端点请求 (headers, form)。
    client_secret_basic 走 HTTP Basic（RFC 6749 §2.3.1）；client_secret_post 走
    body；none 仅 client_id（公共客户端）。client_id 始终入 form（服务端两种读法兼容）。"""
    form: dict[str, str] = dict(extra)
    form["client_id"] = client_id
    headers: dict[str, str] = {}
    if token_auth == "client_secret_basic" and client_secret is not None:
        raw = f"{client_id}:{client_secret}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    elif client_secret is not None:                    # post / 兜底
        form["client_secret"] = client_secret
    return headers, form


# ---------- front_redirect 域白名单（§14.6 防开放重定向） ----------

def validate_front_redirect(front_redirect: str,
                            allowed_origins: tuple[str, ...]) -> str:
    """仅允许 CORS_ALLOWED_ORIGINS 精确 origin（scheme://host:port）下的地址，
    path/query 保留；空白名单一律拒绝（fail-closed）。非法 → 400 INVALID_PARAM。"""
    if not front_redirect or not front_redirect.strip():
        raise AppError(400, "INVALID_PARAM", "front_redirect 不能为空")
    # 控制字符（\x00-\x1f\x7f）一律拒绝（Task 4 评审携带批）：CRLF 可注入响应头 /
    # 拆分 Location 语义，其余控制字符会让浏览器产生不可预期回跳（自 DoS）。
    if re.search(r"[\x00-\x1f\x7f]", front_redirect):
        raise AppError(400, "INVALID_PARAM", "front_redirect 含非法控制字符")
    parsed = urlparse(front_redirect.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise AppError(400, "INVALID_PARAM", "front_redirect 必须为绝对 http(s) 地址")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    normalized = {o.strip().rstrip("/") for o in allowed_origins}
    if origin not in normalized:
        raise AppError(400, "INVALID_PARAM", f"front_redirect 域不在白名单: {origin}")
    return front_redirect.strip()


# ---------- OAuth 客户端行存取（proxy_oauth_client，uk_mapping 每映射一份） ----------


def _row_to_client(row: OAuthClient, master_key: str) -> dict:
    """行 → client dict：secret 解密、token_auth 归一。revocation_endpoint 仅 DCR
    经 discovery 实时获得（manual 模式无 revoke 端点配置列，§14.4）。"""
    return {"client_id": row.client_id,
            "client_secret": (decrypt_text(row.client_secret, master_key)
                              if row.client_secret else None),
            "token_auth": normalize_token_auth(row.token_auth),
            "authorize_url": row.authorize_url, "token_url": row.token_url,
            "scopes": row.scopes, "source": row.source,
            "revocation_endpoint": None}


async def load_client_row(session: AsyncSession, mapping_id: str) -> OAuthClient | None:
    return (await session.execute(
        select(OAuthClient).where(OAuthClient.mapping_id == mapping_id)
    )).scalar_one_or_none()


async def save_oauth_client_row(session: AsyncSession, mapping_id: str, *,
                                client_id: str, client_secret_plain: str | None,
                                token_auth: str, authorize_url: str | None,
                                token_url: str | None, scopes: str | None,
                                source: str, master_key: str) -> None:
    """upsert；client_secret 强制加密落库（§14.6；收尾批次起全敏感字段同标准）。"""
    row = await load_client_row(session, mapping_id)
    secret_ct = (encrypt_text(client_secret_plain, master_key)
                 if client_secret_plain else None)
    if row is None:
        row = OAuthClient(mapping_id=mapping_id, client_id=client_id,
                          client_secret=secret_ct, token_auth=token_auth,
                          authorize_url=authorize_url, token_url=token_url,
                          scopes=scopes, source=source)
        session.add(row)
    else:
        row.client_id = client_id
        row.client_secret = secret_ct
        row.token_auth = token_auth
        row.authorize_url = authorize_url
        row.token_url = token_url
        row.scopes = scopes
        row.source = source
    await session.commit()


# ---------- state 一次性消费（Redis MULTI 事务管道，兼容 Redis 3.0 无 GETDEL） ----------


async def consume_state(r, state: str) -> dict:
    """原子取删：MULTI 事务管道 GET+DEL（并发回调同一 state 仅一方取到值；
    本地/测试 Redis 3.0.504 无 GETDEL，实现机制钉死在 MULTI，不得改写）。
    不存在（过期 / 伪造 / 已消费）→ 400 OAUTH_STATE_INVALID。"""
    pipe = r.pipeline(transaction=True)
    pipe.get(state_key(state))
    pipe.delete(state_key(state))
    results = await pipe.execute()
    raw = results[0]
    if raw is None:
        raise AppError(400, "OAUTH_STATE_INVALID", "state 无效、已使用或已过期")
    return decode_state_payload(raw)


# ---------- ensure_client：manual 直读 / DCR 注册（§14.3，authorize 时调用） ----------


async def _discover_or_setup_failed(app_state, mapping_data: dict) -> dict:
    """discovery 包装：失败映射 502 OAUTH_CLIENT_SETUP_FAILED（提示改手动配置）。"""
    try:
        return await discover_authorization_server(
            app_state.http_client, upstream_origin(mapping_data["upstream_url"]))
    except DiscoveryError as exc:
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       f"OAuth discovery 失败（{exc}），请管理员改用手动配置") from exc


async def ensure_client(session: AsyncSession, app_state, mapping_data: dict,
                        master_key: str, redirect_uri: str) -> dict:
    """取/建 OAuth 客户端（§14.3 DCR 优先 + 手动兼容）：
    - proxy_oauth_client 有行 → 直读（secret 解密）；source=dcr 行的 authorize/token
      端点实时 discovery（§5.3：DCR 模式两列留空，提供方改端点无需迁移数据）；
    - 无行 → discovery → RFC 7591 注册（redirect_uris 精确单一值、PKCE S256 声明）
      → 落行 source=dcr；
    - discovery/DCR 失败 → 502 OAUTH_CLIENT_SETUP_FAILED（提示管理员改用手动配置）。
    返回 dict：client_id / client_secret(解密) / token_auth / authorize_url /
    token_url / scopes / source / revocation_endpoint。"""
    mapping_id = mapping_data["mapping_id"]
    row = await load_client_row(session, mapping_id)
    if row is not None:
        client = _row_to_client(row, master_key)
        if row.source == "dcr":
            meta = await _discover_or_setup_failed(app_state, mapping_data)
            client["authorize_url"] = meta["authorization_endpoint"]
            client["token_url"] = meta["token_endpoint"]
            client["revocation_endpoint"] = meta.get("revocation_endpoint")
        return client
    meta = await _discover_or_setup_failed(app_state, mapping_data)
    if not meta.get("registration_endpoint"):
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       "AS 元数据无 registration_endpoint，请管理员改用手动配置")
    payload = build_dcr_payload(f"agent-proxy-{mapping_id}", redirect_uri)
    try:
        resp = await app_state.http_client.post(meta["registration_endpoint"],
                                                json=payload, timeout=15.0)
    except httpx.HTTPError as exc:
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       f"DCR 注册请求失败（{type(exc).__name__}），请改用手动配置") from exc
    if resp.status_code not in (200, 201):
        # RFC 7591 §3.2.1：注册成功 = 201 Created（Keycloak/Okta/Auth0 均如此）；
        # 200 兼容宽松实现（评审 Critical 1：原稿只认 200，真实提供方全部 502）
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       f"DCR 注册被拒（status={resp.status_code}），请改用手动配置")
    try:
        reg = resp.json()
    except ValueError as exc:
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       "DCR 响应非 JSON，请改用手动配置") from exc
    if not reg.get("client_id"):
        raise AppError(502, "OAUTH_CLIENT_SETUP_FAILED",
                       "DCR 响应缺少 client_id，请改用手动配置")
    token_auth = normalize_token_auth(reg.get("token_endpoint_auth_method"))
    secret_plain = reg.get("client_secret")
    scopes = reg.get("scope")
    await save_oauth_client_row(session, mapping_id, client_id=reg["client_id"],
                                client_secret_plain=secret_plain, token_auth=token_auth,
                                authorize_url=None, token_url=None,
                                scopes=scopes, source="dcr", master_key=master_key)
    return {"client_id": reg["client_id"], "client_secret": secret_plain,
            "token_auth": token_auth, "authorize_url": meta["authorization_endpoint"],
            "token_url": meta["token_endpoint"], "scopes": scopes,
            "source": "dcr", "revocation_endpoint": meta.get("revocation_endpoint")}
