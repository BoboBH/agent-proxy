import os
from types import SimpleNamespace

os.environ.setdefault("TOKEN_VERIFY_IMPL", "stub")

import pytest
from starlette.requests import Request

from agent_proxy.api.deps import get_current_identity, is_admin
from agent_proxy.auth import Identity, TokenInvalidError
from agent_proxy.config import get_settings
from agent_proxy.sso.session import SESSION_COOKIE, encode_identity, session_key
from tests.utils import make_token

# 认证通道头名（设计 v4）：可配置（PROXY_AUTH_HEADER），默认 Authorization——
# 该头既是代理身份通道又可透传上游（统一 token）；配置成其他名字则纯代理私有。
AUTH = b"authorization"


class _FakeRedis:
    """Cookie 通道的最小替身：单测不依赖真实 Redis（集成面见 test_cookie_channel.py）。"""

    def __init__(self, store: dict[str, str] | None = None):
        self.store = dict(store or {})

    async def get(self, key: str):
        return self.store.get(key)


def _request(headers: list[tuple[bytes, bytes]], redis: _FakeRedis | None = None) -> Request:
    # Cookie 通道经 request.app.state.redis 取会话——scope 常挂最小 app 替身；
    # 代理认证通道不触达 app，既有用例不受影响
    return Request(scope={"type": "http", "headers": headers, "state": {},
                          "app": SimpleNamespace(state=SimpleNamespace(redis=redis or _FakeRedis()))})


def _session(sid: str, **claims) -> _FakeRedis:
    user_id = claims.pop("user_id")
    return _FakeRedis({session_key(sid): encode_identity(Identity(user_id=user_id, **claims))})


async def test_missing_proxy_auth_header():
    req = _request([])
    with pytest.raises(TokenInvalidError) as excinfo:
        await get_current_identity(req)
    assert (excinfo.value.status, excinfo.value.code) == (401, "INVALID_TOKEN")


async def test_authorization_header_consumed_by_default():
    """设计 v4 默认配置：Authorization 即代理身份通道（携带有效票据 → 通过）。"""
    req = _request([(b"authorization", f"Bearer {make_token(777)}".encode())])
    assert (await get_current_identity(req)).user_id == 777


async def test_custom_proxy_auth_header_via_config(monkeypatch):
    """PROXY_AUTH_HEADER 配置化：切到 x-proxy-authorization 后，该头成为身份通道，
    默认 Authorization 不再被消费（v2 模式经配置即可恢复）。"""
    from agent_proxy.api import deps as deps_mod

    monkeypatch.setenv("PROXY_AUTH_HEADER", "X-Proxy-Authorization")
    get_settings.cache_clear()
    try:
        req = _request([(b"x-proxy-authorization", f"Bearer {make_token(777)}".encode())])
        assert (await get_current_identity(req)).user_id == 777
        req2 = _request([(b"authorization", f"Bearer {make_token(777)}".encode())])
        with pytest.raises(TokenInvalidError):
            await get_current_identity(req2)
    finally:
        get_settings.cache_clear()


async def test_valid_proxy_auth_bearer_writes_state():
    """身份 user_id 为 int（收尾批次整数化）：默认通道信封票据 → int 身份 → state。"""
    req = _request([(AUTH, f"Bearer {make_token(777, role='admin')}".encode())])
    identity = await get_current_identity(req)
    assert identity.user_id == 777 and isinstance(identity.user_id, int)
    assert identity.role == "admin"
    assert identity.user_name == "张三"
    assert req.state.user_id == 777
    assert req.state.user_name == "张三"


async def test_non_dict_payload_rejected_as_401():
    req = _request([(AUTH, b"Bearer stub.MTIz.sig")])  # payload=123 非 dict
    with pytest.raises(TokenInvalidError) as excinfo:
        await get_current_identity(req)
    assert (excinfo.value.status, excinfo.value.code) == (401, "INVALID_TOKEN")


# ---------- M7 双通道：Cookie 会话回退（§15.1「会话与鉴权兼容」） ----------


async def test_cookie_session_fallback_resolves_identity():
    sid = "a" * 32
    redis = _session(sid, user_id=555, user_name="李四")
    req = _request([(b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    identity = await get_current_identity(req)
    assert identity.user_id == 555 and identity.user_name == "李四"
    assert req.state.user_id == 555 and req.state.user_name == "李四"   # 审计身份照常写入


async def test_proxy_auth_precedence_over_cookie_session():
    """代理认证头优先（§15.1）：双通道并存以 X-Proxy-Authorization 身份为准。"""
    sid = "b" * 32
    redis = _session(sid, user_id=999)
    req = _request([(AUTH, f"Bearer {make_token(777)}".encode()),
                    (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    assert (await get_current_identity(req)).user_id == 777


async def test_invalid_proxy_auth_does_not_fall_back_to_cookie():
    """代理认证头优先且失败不回退（钉住语义）：带失效凭证却静默回退会话 = 已撤销
    凭证被会话掩盖继续放行，安全底线不允许。"""
    sid = "c" * 32
    redis = _session(sid, user_id=555)
    req = _request([(AUTH, b"Bearer stub.broken.sig"),
                    (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    with pytest.raises(TokenInvalidError):
        await get_current_identity(req)


async def test_cookie_unknown_or_garbage_sid_401():
    redis = _session("d" * 32, user_id=555)     # 有效会话在别处；两个 sid 都查不到
    for cookie_value in ("e" * 32, "garbage"):
        req = _request([(b"cookie", f"{SESSION_COOKIE}={cookie_value}".encode())], redis=redis)
        with pytest.raises(TokenInvalidError):
            await get_current_identity(req)


async def test_no_proxy_auth_no_cookie_401():
    req = _request([])
    with pytest.raises(TokenInvalidError):
        await get_current_identity(req)


async def test_basic_scheme_on_proxy_auth_with_valid_cookie_uses_session():
    """非 Bearer scheme 语义钉住（沿 Task 2 评审）：X-Proxy-Authorization 上非
    「Bearer 」前缀不构成凭证出示，按 Cookie 会话放行；「失败不回退」仅对
    Bearer 生效。"""
    sid = "f" * 32
    redis = _session(sid, user_id=555, user_name="李四")
    req = _request([(AUTH, b"Basic dXNlcjpwYXNz"),
                    (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    identity = await get_current_identity(req)
    assert identity.user_id == 555 and identity.user_name == "李四"
    assert req.state.user_id == 555


async def test_authorization_scheme_semantics_with_cookie():
    """默认 Authorization 通道的 scheme 语义（设计 v4/v4.1）：
    - Bearer 有效票据 → 身份 777（认证通道胜出，不落 Cookie）；
    - `Token <值>` 是受支持凭证形态（v4.1）：出示失败（stub 不认 JWT）→ 401
      **不回退** Cookie——受支持 scheme 的失效凭证被静默换通道 = 安全底线问题；
    - Basic 等非受支持 scheme → 不构成凭证出示 → Cookie 照常（见
      test_basic_scheme_on_proxy_auth_with_valid_cookie）。"""
    sid = "1a" * 16          # 32 位 hex（sid 校验要求 hex 字符）
    redis = _session(sid, user_id=555)
    req = _request([(b"authorization", f"Bearer {make_token(777)}".encode()),
                    (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    assert (await get_current_identity(req)).user_id == 777
    req2 = _request([(b"authorization", b"Token abc.def.ghi"),
                     (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    with pytest.raises(TokenInvalidError):
        await get_current_identity(req2)


def test_is_admin_matches_role():
    assert is_admin(Identity(user_id=1, role="admin"), "admin")


def test_is_admin_false_when_role_mismatch_or_none():
    assert not is_admin(Identity(user_id=1, role="viewer"), "admin")
    assert not is_admin(Identity(user_id=1), "admin")


async def test_stub_verify_credential_contract(monkeypatch):
    """deps 契约（设计 v4.1）：认证头值带 Bearer/Token 前缀 = 凭证出示 →
    verifier.verify_credential；失败不回退 Cookie；其他 scheme 不遮蔽 Cookie。"""
    from agent_proxy.api import deps as deps_mod

    class _SpyVerifier:
        def __init__(self):
            self.seen = []

        async def verify_credential(self, credential: str) -> Identity:
            self.seen.append(credential)
            if credential == "Token 5436":
                return Identity(user_id=5436)
            raise TokenInvalidError("无效")

    spy = _SpyVerifier()
    monkeypatch.setattr(deps_mod, "_get_verifier", lambda: spy)
    sid = "2b" * 16
    redis_ok = _session(sid, user_id=555)
    req = _request([(b"authorization", b"Token 5436"),
                    (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis_ok)
    assert (await get_current_identity(req)).user_id == 5436
    assert spy.seen == ["Token 5436"]
    req2 = _request([(b"authorization", b"Bearer bad"),
                     (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis_ok)
    with pytest.raises(TokenInvalidError):
        await get_current_identity(req2)          # 凭证出示失败 → 不回退 Cookie
