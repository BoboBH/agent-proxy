"""OAuth 客户端层（设计 §14.3）：DCR（RFC 7591）优先 + 手动配置兼容。

本模块 Task 1 交付纯逻辑：PKCE(S256)、state 载荷、authorization_url /
redirect_uri / token 请求 / DCR 载荷组装、token_auth 归一、front_redirect 域
白名单；DB 行存取（load/save）、state 一次性消费（Redis MULTI）与 ensure_client
（discovery → DCR）随 Task 3–5 增量交付。

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
import secrets
from urllib.parse import urlencode, urlparse

from ..errors import AppError

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


def encode_state_payload(*, uid: str, mapping_id: str, code_verifier: str,
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
    if not isinstance(payload, dict) or not all(k in payload for k in required):
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
    parsed = urlparse(front_redirect.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise AppError(400, "INVALID_PARAM", "front_redirect 必须为绝对 http(s) 地址")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    normalized = {o.strip().rstrip("/") for o in allowed_origins}
    if origin not in normalized:
        raise AppError(400, "INVALID_PARAM", f"front_redirect 域不在白名单: {origin}")
    return front_redirect.strip()
