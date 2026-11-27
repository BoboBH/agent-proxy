"""LoginProvider 抽象 + stub 实现（设计 §15.1，与 auth.TokenVerifier 同风格）。

- stub（默认，开发/测试）：login_url 指向本地假登录页 /admin/login（选择用户/角色，
  浏览器侧按 StubVerifier 同格式构造票据提交 callback）；exchange 复用
  TokenVerifier（StubVerifier）解码——「公司 SSO 的票据校验」在 stub 形态即 JWT
  载荷解码，两者票据互通（测试令牌 stub.<b64url 载荷>.sig 可直接作登录票据）；
- company_sso（后续实现，协议实现时定）：对接公司统一登录，注册为独立 Provider 类
  并在 build_login_provider 白名单放行即可——页面与 API 零改动（§15.1 对接抽象行）。
"""
from __future__ import annotations

from typing import Protocol
from urllib.parse import quote

from app.services.auth import Identity, build_verifier
from app.env import get_settings


class LoginProvider(Protocol):
    def login_url(self, return_to: str) -> str:
        """跳转登录的地址（携带回跳；stub=本地登录页，company_sso=外部统一登录）。"""
        ...

    async def exchange(self, ticket: str) -> Identity:
        """回跳票据换身份；明确无效（无效/过期/格式错）抛 TokenInvalidError。"""
        ...


class StubLoginProvider:
    """本地假登录（仅开发/测试，prod 禁 stub 由 config.validate 门禁）。"""

    def login_url(self, return_to: str) -> str:
        return f"/admin/login?return_to={quote(return_to, safe='')}"

    async def exchange(self, ticket: str) -> Identity:
        return await build_verifier(get_settings().token_verify_impl).verify(ticket)


def build_login_provider(impl: str) -> LoginProvider:
    if impl == "stub":
        return StubLoginProvider()
    raise NotImplementedError(f"未知 LOGIN_IMPL: {impl}")


_provider: LoginProvider | None = None


def get_login_provider() -> LoginProvider:
    """进程级单例（与 api.deps._get_verifier 同风格）：LOGIN_IMPL 一期仅 stub，
    多 app 实例（测试双夹具 ASGI / 真实 TCP 9910）impl 一致，缓存无分叉。"""
    global _provider
    if _provider is None:
        _provider = build_login_provider(get_settings().login_impl)
    return _provider
