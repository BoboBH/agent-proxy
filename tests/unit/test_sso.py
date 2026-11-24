"""sso 基础层单测（M7，设计 §15.1）：LoginProvider 抽象与 stub 实现、会话键与
Identity 载荷编解码、Cookie 常量。Redis 存取的集成面见
tests/integration/test_sso_session.py（真实 Redis）。"""
import logging

import pytest

from agent_proxy.auth import Identity, TokenInvalidError
from agent_proxy.sso.login import StubLoginProvider, build_login_provider
from agent_proxy.sso.session import (SESSION_COOKIE, SESSION_KEY_PREFIX,
                                     decode_identity, destroy_session,
                                     encode_identity, get_session, new_sid,
                                     session_key)


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


def test_get_login_provider_returns_same_instance():
    """进程级单例（评审补充）：两次调用返回同一实例；首尾重置 _provider 做隔离，
    避免污染其他用例/其他测试文件的 get_settings 缓存面。"""
    import agent_proxy.sso.login as login_mod

    login_mod._provider = None                         # 重置隔离准备
    try:
        first = login_mod.get_login_provider()
        assert login_mod.get_login_provider() is first
        assert isinstance(first, StubLoginProvider)
    finally:
        login_mod._provider = None                     # 还原，不带走缓存状态


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


def test_decode_identity_rejects_non_dict_json():
    """JSON 合法但非对象（数组 / null）同样按非法载荷处理（评审补充）。"""
    assert decode_identity("[1]") is None
    assert decode_identity("null") is None


def test_decode_identity_rejects_non_string_fields():
    assert decode_identity('{"user_id": "u1", "user_name": 123}') is None   # user_name 必须 str
    assert decode_identity('{"user_id": "u1", "role": 5}') is None          # role 同型校验


def test_decode_identity_rejects_empty_user_id():
    assert decode_identity('{"user_id": ""}') is None               # 空 user_id = 未认证


async def test_get_session_redis_error_returns_none_with_warning(caplog):
    """Redis 异常 → None + WARN 日志（评审补充：fake-Redis 单测钉住降级路径，
    不抛 500——集成面为 test_sso_session.py / test_cookie_channel.py）。"""

    class _BoomRedis:
        async def get(self, key):
            raise RuntimeError("redis down")

    with caplog.at_level(logging.WARNING, logger="agent_proxy"):
        assert await get_session(_BoomRedis(), "a" * 32) is None
    assert any(r.levelno == logging.WARNING and "会话读取失败" in r.getMessage()
               for r in caplog.records)


def test_stub_login_url_encodes_crlf_in_return_to():
    """return_to 组装前 quote(safe='')（评审补充钉住）：\r\n 被编码，无 CRLF 头注入面。"""
    url = StubLoginProvider().login_url("/admin\r\nX-Injected: 1")
    assert "\r" not in url and "\n" not in url
    assert "%0D" in url and "%0A" in url


# ---------- sid 格式校验（Task 2 评审加固：防键空间注入） ----------


class _RecordingRedis:
    """记录全部 Redis 命令的替身：非法 sid 必须在格式校验处短路（零命令触达）。
    （不抛断言——get_session 的 except Exception 会吞掉 fake 内的异常。）"""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    async def get(self, key):
        self.calls.append(("get", key))
        return None

    async def delete(self, key):
        self.calls.append(("delete", key))


async def test_get_session_rejects_non_32hex_sid_without_redis_access():
    """sid 仅接受 new_sid() 形态（32 位小写 hex）：Cookie 是攻击者可控输入，
    非 128bit-hex 一律按未登录处理（None），不触达 Redis。"""
    for bad in ("junk", "a" * 31, "A" * 32, "g" * 40, f"{'a' * 32}/extra",
                f"{'a' * 31} "):
        r = _RecordingRedis()
        assert await get_session(r, bad) is None
        assert r.calls == []                             # 零 Redis 命令


async def test_destroy_session_rejects_non_32hex_sid_without_redis_access():
    for bad in ("junk", "A" * 32, f"{'b' * 32}/x"):
        r = _RecordingRedis()
        await destroy_session(r, bad)                    # 短路 no-op
        assert r.calls == []                             # 零 Redis 命令
