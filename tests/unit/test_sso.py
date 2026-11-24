"""sso 基础层单测（M7，设计 §15.1）：LoginProvider 抽象与 stub 实现、会话键与
Identity 载荷编解码、Cookie 常量。Redis 存取的集成面见
tests/integration/test_sso_session.py（真实 Redis）。"""
import pytest

from agent_proxy.auth import Identity, TokenInvalidError
from agent_proxy.sso.login import StubLoginProvider, build_login_provider
from agent_proxy.sso.session import (SESSION_COOKIE, SESSION_KEY_PREFIX,
                                     decode_identity, encode_identity,
                                     new_sid, session_key)


# ---------- LoginProvider 抽象 + stub（§15.1 对接抽象） ----------


def test_stub_login_url_carries_encoded_return_to():
    url = StubLoginProvider().login_url("/admin?p=1")
    assert url.startswith("/admin/login?return_to=")
    assert "return_to=%2Fadmin%3Fp%3D1" in url        # return_to 已 URL 编码（safe=""）


async def test_stub_exchange_decodes_ticket_to_identity():
    """stub 票据与 StubVerifier 同格式（tests.utils.make_token 可直接作票据）——
    「公司 SSO 票据校验」在 stub 形态即 JWT 载荷解码，company_sso Provider 实现时替换。"""
    from tests.utils import make_token

    identity = await StubLoginProvider().exchange(
        make_token("u888", role="admin", user_name="张三"))
    assert identity == Identity(user_id="u888", user_name="张三", role="admin")


async def test_stub_exchange_invalid_ticket_raises_token_invalid():
    with pytest.raises(TokenInvalidError):
        await StubLoginProvider().exchange("stub.not-base64!!^.sig")
    with pytest.raises(TokenInvalidError):
        await StubLoginProvider().exchange("")         # 空 ticket 同样 401 面


def test_build_login_provider_stub_type():
    assert isinstance(build_login_provider("stub"), StubLoginProvider)


def test_build_login_provider_unknown_impl_not_implemented():
    with pytest.raises(NotImplementedError):
        build_login_provider("banana")                 # 白名单在 config.validate，双保险


# ---------- 会话键 / Cookie 常量 / Identity 载荷 ----------


def test_session_key_prefix_and_sid_shape():
    assert SESSION_COOKIE == "ap_sess"
    assert SESSION_KEY_PREFIX == "ap:sess:"
    sid = new_sid()
    assert len(sid) == 32 and set(sid) <= set("0123456789abcdef")   # 128bit hex
    assert session_key(sid) == f"ap:sess:{sid}"
    assert len({new_sid(), new_sid(), new_sid()}) == 3               # 随机性（不碰撞）


def test_identity_payload_encode_decode_roundtrip():
    raw = encode_identity(Identity(user_id="u1", user_name="张三", role="admin"))
    assert decode_identity(raw) == Identity(user_id="u1", user_name="张三", role="admin")
    assert decode_identity(encode_identity(Identity(user_id="u2"))) == Identity(user_id="u2")


def test_decode_identity_rejects_malformed_payload():
    assert decode_identity("not-json") is None
    assert decode_identity('{"no_user_id": 1}') is None
    assert decode_identity('{"user_id": 123}') is None              # user_id 必须 str
    assert decode_identity(b'{"user_id": "bin"}') == Identity(user_id="bin")   # bytes 兼容
