"""身份：Identity / TokenVerifier 抽象 + stub 实现。第三方校验实现后续接入（协议实现时定）。"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Protocol

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
    proxy_oauth_credential.uid 均为 BIGINT，整条传递链保持 int，杜绝 str/int 混比）。"""
    user_id: int
    user_name: str | None = None
    role: str | None = None


class TokenVerifier(Protocol):
    async def verify(self, token: str) -> Identity: ...


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
        if isinstance(user_id, int) and not isinstance(user_id, bool):
            uid = user_id
        elif isinstance(user_id, str) and user_id.isascii() and user_id.isdigit():
            uid = int(user_id)
        else:
            raise TokenInvalidError("user_id claim 必须为整数")
        return Identity(user_id=uid,
                        user_name=payload.get("user_name"), role=payload.get("role"))


class ThirdPartyVerifier:
    """后续接入：对接第三方校验接口（协议确定后实现 verify，注册于 build_verifier）。"""

    async def verify(self, token: str) -> Identity:
        raise NotImplementedError("third_party 校验实现待接入，见设计文档第 7 章")


def build_verifier(impl: str) -> TokenVerifier:
    if impl == "stub":
        return StubVerifier()
    raise NotImplementedError(f"未知 TOKEN_VERIFY_IMPL: {impl}")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
