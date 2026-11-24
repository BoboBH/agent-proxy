import os
from types import SimpleNamespace

os.environ.setdefault("TOKEN_VERIFY_IMPL", "stub")

import pytest
from starlette.requests import Request

from agent_proxy.api.deps import get_current_identity, is_admin
from agent_proxy.auth import Identity, TokenInvalidError
from agent_proxy.sso.session import SESSION_COOKIE, encode_identity, session_key
from tests.utils import make_token


class _FakeRedis:
    """Cookie 通道的最小替身：单测不依赖真实 Redis（集成面见 test_cookie_channel.py）。"""

    def __init__(self, store: dict[str, str] | None = None):
        self.store = dict(store or {})

    async def get(self, key: str):
        return self.store.get(key)


def _request(headers: list[tuple[bytes, bytes]], redis: _FakeRedis | None = None) -> Request:
    # Cookie 通道经 request.app.state.redis 取会话——scope 常挂最小 app 替身；
    # Bearer 通道不触达 app，既有用例不受影响
    return Request(scope={"type": "http", "headers": headers, "state": {},
                          "app": SimpleNamespace(state=SimpleNamespace(redis=redis or _FakeRedis()))})


def _session(sid: str, **claims) -> _FakeRedis:
    uid = claims.pop("user_id")
    return _FakeRedis({session_key(sid): encode_identity(Identity(user_id=uid, **claims))})


async def test_missing_authorization_header():
    req = _request([])
    with pytest.raises(TokenInvalidError) as excinfo:
        await get_current_identity(req)
    assert (excinfo.value.status, excinfo.value.code) == (401, "INVALID_TOKEN")


async def test_non_bearer_scheme_rejected():
    req = _request([(b"authorization", b"Basic dXNlcjpwYXNz")])
    with pytest.raises(TokenInvalidError) as excinfo:
        await get_current_identity(req)
    assert (excinfo.value.status, excinfo.value.code) == (401, "INVALID_TOKEN")


async def test_valid_bearer_writes_state():
    req = _request([(b"authorization", f"Bearer {make_token('u777', role='admin')}".encode())])
    identity = await get_current_identity(req)
    assert identity.user_id == "u777"
    assert identity.role == "admin"
    assert identity.user_name == "张三"
    assert req.state.uid == "u777"
    assert req.state.user_name == "张三"


async def test_non_dict_payload_rejected_as_401():
    req = _request([(b"authorization", b"Bearer stub.MTIz.sig")])  # payload=123 非 dict
    with pytest.raises(TokenInvalidError) as excinfo:
        await get_current_identity(req)
    assert (excinfo.value.status, excinfo.value.code) == (401, "INVALID_TOKEN")


# ---------- M7 双通道：Cookie 会话回退（§15.1「会话与鉴权兼容」） ----------


async def test_cookie_session_fallback_resolves_identity():
    sid = "a" * 32
    redis = _session(sid, user_id="u555", user_name="李四")
    req = _request([(b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    identity = await get_current_identity(req)
    assert identity.user_id == "u555" and identity.user_name == "李四"
    assert req.state.uid == "u555" and req.state.user_name == "李四"   # 审计身份照常写入


async def test_bearer_precedence_over_cookie_session():
    """Bearer 优先（§15.1）：双通道并存以 Bearer 身份为准（Agent/API 场景语义不变）。"""
    sid = "b" * 32
    redis = _session(sid, user_id="u999")
    req = _request([(b"authorization", f"Bearer {make_token('u777')}".encode()),
                    (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    assert (await get_current_identity(req)).user_id == "u777"


async def test_invalid_bearer_does_not_fall_back_to_cookie():
    """Bearer 优先且失败不回退（钉住语义）：带失效 Bearer 却静默回退会话 = 已撤销
    凭证被会话掩盖继续放行，安全底线不允许。"""
    sid = "c" * 32
    redis = _session(sid, user_id="u555")
    req = _request([(b"authorization", b"Bearer stub.broken.sig"),
                    (b"cookie", f"{SESSION_COOKIE}={sid}".encode())], redis=redis)
    with pytest.raises(TokenInvalidError):
        await get_current_identity(req)


async def test_cookie_unknown_or_garbage_sid_401():
    redis = _session("d" * 32, user_id="u555")     # 有效会话在别处；两个 sid 都查不到
    for cookie_value in ("e" * 32, "garbage"):
        req = _request([(b"cookie", f"{SESSION_COOKIE}={cookie_value}".encode())], redis=redis)
        with pytest.raises(TokenInvalidError):
            await get_current_identity(req)


async def test_no_bearer_no_cookie_401():
    req = _request([])
    with pytest.raises(TokenInvalidError):
        await get_current_identity(req)


def test_is_admin_matches_role():
    assert is_admin(Identity(user_id="u1", role="admin"), "admin")


def test_is_admin_false_when_role_mismatch_or_none():
    assert not is_admin(Identity(user_id="u1", role="viewer"), "admin")
    assert not is_admin(Identity(user_id="u1"), "admin")
