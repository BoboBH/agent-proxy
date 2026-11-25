import os
from types import SimpleNamespace

os.environ.setdefault("TOKEN_VERIFY_IMPL", "stub")

import pytest
from starlette.requests import Request

from agent_proxy.api.deps import get_current_identity, is_admin
from agent_proxy.auth import Identity, TokenInvalidError
from agent_proxy.sso.session import SESSION_COOKIE, encode_identity, session_key
from tests.utils import make_token

# 认证通道头名（设计 v2）：代理身份走保留命名空间 x-proxy-authorization，
# authorization 还给上游语义（skill 教传的 Token/凭据不再被代理消费）。
AUTH = b"x-proxy-authorization"


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


async def test_authorization_header_no_longer_consumed():
    """设计 v2 核心钉住：authorization 不再是代理认证通道——即使携带**有效**票据
    也 401（skill 教传的 Authorization: Token xxx / Bearer xxx 属上游载荷语义，
    绝不被代理当身份消费）。"""
    req = _request([(b"authorization", f"Bearer {make_token(777)}".encode())])
    with pytest.raises(TokenInvalidError) as excinfo:
        await get_current_identity(req)
    assert (excinfo.value.status, excinfo.value.code) == (401, "INVALID_TOKEN")


async def test_valid_proxy_auth_bearer_writes_state():
    """身份 user_id 为 int（收尾批次整数化）：X-Proxy-Authorization 信封票据 →
    int 身份 → state.user_id。"""
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


async def test_authorization_plus_valid_cookie_uses_session():
    """authorization 任意值（含 Bearer 形态）都不进入认证通道：不遮蔽 Cookie 回退。"""
    sid = "1a" * 16          # 32 位 hex（sid 校验要求 hex 字符）
    redis = _session(sid, user_id=555)
    for value in (b"Token abc.def.ghi", f"Bearer {make_token(777)}".encode()):
        req = _request([(b"authorization", value),
                        (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
        assert (await get_current_identity(req)).user_id == 555


def test_is_admin_matches_role():
    assert is_admin(Identity(user_id=1, role="admin"), "admin")


def test_is_admin_false_when_role_mismatch_or_none():
    assert not is_admin(Identity(user_id=1, role="viewer"), "admin")
    assert not is_admin(Identity(user_id=1), "admin")
