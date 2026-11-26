"""身份：Identity / TokenVerifier 抽象 + stub 实现。第三方校验实现后续接入（协议实现时定）。"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Protocol

import httpx

from .errors import AppError


class TokenInvalidError(AppError):
    def __init__(self, message: str = "token 缺失或无效"):
        super().__init__(401, "INVALID_TOKEN", message)


class TokenServiceError(AppError):
    def __init__(self, message: str = "身份校验服务不可用"):
        super().__init__(503, "AUTH_SERVICE_UNAVAILABLE", message)


@dataclass(frozen=True)
class Identity:
    """user_id 为 int（收尾批次：内部系统 user_id 整数化——proxy_mapping.owner_uid /
    proxy_oauth_credential.user_id 均为 BIGINT，整条传递链保持 int，杜绝 str/int 混比）。"""
    user_id: int
    user_name: str | None = None
    role: str | None = None


class TokenVerifier(Protocol):
    async def verify(self, token: str) -> Identity: ...

    async def verify_credential(self, credential: str) -> Identity:
        """deps 契约（设计 v4.1）：认证头**完整值**（含 scheme，如 `Bearer x` /
        `Token x`）作为凭证出示；失败 → TokenInvalidError（401 不回退 Cookie）。"""
        ...


class StubVerifier:
    """开发/测试：本地解码 JWT payload 中段，不验签。claims: user_id(必须，整数)/user_name/role。

    纯数字 token 短路（M7 评审指令，仅 stub）：直接作 user_id（`Bearer 12345` →
    Identity(user_id=12345)）——stub 登录页「输入数字即身份」，免构造信封票据；
    isascii 门（评审修复）挡全角数字（"１２３".isdigit() 为 True 但非 ASCII），
    其走下方 JWT 解析 → 401；信封形态（stub.<b64url 载荷>.sig）两路径并存。

    user_id 整数化（收尾批次）：claim 为 int 或数字串均可，统一 int 化——非整数
    （"u888"/容器/None）一律 401 fail-closed（内部系统 user_id 只有整数形态）。"""

    async def verify(self, token: str) -> Identity:
        if token.isascii() and token.isdigit():
            return Identity(user_id=int(token))
        try:
            payload = json.loads(_b64url_decode(token.split(".")[1]))
        except Exception as exc:
            raise TokenInvalidError("token 格式非法") from exc
        if not isinstance(payload, dict):
            raise TokenInvalidError("token 格式非法")
        user_id = payload.get("user_id")
        if isinstance(user_id, str) and user_id.isascii() and user_id.isdigit():
            user_id = int(user_id)
        elif not isinstance(user_id, int) or isinstance(user_id, bool):
            raise TokenInvalidError("user_id claim 必须为整数")
        return Identity(user_id=user_id,
                        user_name=payload.get("user_name"), role=payload.get("role"))

    async def verify_credential(self, credential: str) -> Identity:
        """deps 契约：剥 Bearer/Token scheme 后走既有 verify（纯数字 / 信封票据）。"""
        stripped = credential.strip()
        lowered = stripped.lower()
        if lowered.startswith("bearer "):
            stripped = stripped[7:].strip()
        elif lowered.startswith("token "):
            stripped = stripped[6:].strip()
        return await self.verify(stripped)


class ThirdPartyVerifier:
    """验签接口对接（docs/auth_verify_token_integration.md，设计 v4.1）。

    GET {api_base}/auth/verify_token，Authorization 头**原样透传**调用方凭据
    （接口支持 Bearer/Token 两种 scheme——统一 token 场景：skill 教传的
    `Authorization: Token <jwt>` 在默认头名下即可直通鉴权）。

    结果映射（以 HTTP 状态码为主，文档 §5）：
    - 200 + valid===true → Identity(user_id, user_name, role=user_type)
      （user_type=="admin" 恰好命中现有 admin 判定；身份以 JWT 内 id 为准）；
    - 非 200 / valid 非 true → TokenInvalidError（401 INVALID_TOKEN）；
    - 5xx / 网络错误 → TokenServiceError（503 AUTH_SERVICE_UNAVAILABLE，
      与「token 无效」区分，fail-closed）；
    - status ∈ {locked, deleted} → 拒收（文档 §3.2 安全建议）。

    短 TTL 缓存（60s，文档注记 2/3：不缓存永久、可频繁调用）——代理每请求都会
    鉴权，稳态下避免每次出网。出站客户端 trust_env=False（与 §8.1 v4 直连一致）。
    """
    _CACHE_TTL = 60.0
    _CACHE_MAX = 2048

    def __init__(self, api_base: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        from .config import get_settings   # 延迟导入避免 config↔auth 循环
        self.api_base = ((api_base or get_settings().verify_api_base)
                         .rstrip("/"))
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._cache: dict[str, tuple[float, Identity]] = {}

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=self._transport, timeout=5.0, trust_env=False)
        return self._client

    def _cache_get(self, credential: str) -> Identity | None:
        hit = self._cache.get(credential)
        if hit is None:
            return None
        expires, identity = hit
        if time.monotonic() >= expires:
            self._cache.pop(credential, None)
            return None
        return identity

    async def verify(self, token: str) -> Identity:
        return await self.verify_credential(f"Bearer {token}")

    async def verify_credential(self, credential: str) -> Identity:
        cached = self._cache_get(credential)
        if cached is not None:
            return cached
        req = httpx.Request("GET", f"{self.api_base}/auth/verify_token",
                            headers={"Authorization": credential,
                                     "Accept": "application/json"})
        try:
            resp = await self._get_client().send(req)
        except httpx.HTTPError as exc:
            raise TokenServiceError(f"token 校验服务不可用: {type(exc).__name__}") from exc
        if resp.status_code >= 500:
            # 文档 §5：5xx 属服务异常，有限重试/告警——与「token 无效」区分（fail-closed）
            raise TokenServiceError(
                f"token 校验服务异常（HTTP {resp.status_code}）")
        if resp.status_code != 200:
            raise TokenInvalidError(
                f"token 校验未通过（HTTP {resp.status_code}）: {self._message(resp)}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise TokenInvalidError("token 校验响应非 JSON") from exc
        if not isinstance(body, dict) or body.get("valid") is not True:
            raise TokenInvalidError(
                f"token 校验未通过: {body.get('message') if isinstance(body, dict) else '响应形状非法'}")
        user_id = body.get("user_id")
        if isinstance(user_id, bool) or not isinstance(user_id, int):
            raise TokenInvalidError("verify_token 响应 user_id 非整数")
        if body.get("status") in ("locked", "deleted"):
            raise TokenInvalidError(f"账号状态不可用: {body.get('status')}")
        identity = Identity(
            user_id=user_id,
            user_name=(body.get("username") or body.get("real_name")
                       or body.get("email") or None),
            role=body.get("user_type"))
        if len(self._cache) >= self._CACHE_MAX:
            self._cache.clear()      # 简单防膨胀：满即清（TTL 60s，代价可忽略）
        self._cache[credential] = (time.monotonic() + self._CACHE_TTL, identity)
        return identity

    @staticmethod
    def _message(resp: httpx.Response) -> str:
        try:
            body = resp.json()
        except ValueError:
            return (resp.text or "")[:120]
        if isinstance(body, dict):
            return str(body.get("msg") or body.get("message")
                       or body.get("detail") or resp.text[:120])
        return (resp.text or "")[:120]


def build_verifier(impl: str, api_base: str | None = None) -> TokenVerifier:
    if impl == "stub":
        return StubVerifier()
    if impl == "third_party":
        return ThirdPartyVerifier(api_base)
    raise NotImplementedError(f"未知 TOKEN_VERIFY_IMPL: {impl}")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
