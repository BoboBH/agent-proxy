import base64
import json

import pytest

from agent_proxy.auth import Identity, StubVerifier, TokenInvalidError, build_verifier
from tests.utils import make_token


async def test_stub_verify_ok():
    identity = await StubVerifier().verify(make_token("u999", role="admin", user_name="李四"))
    assert identity.user_id == "u999"
    assert identity.role == "admin"
    assert identity.user_name == "李四"


async def test_stub_verify_without_role():
    identity = await StubVerifier().verify(make_token("u888"))
    assert identity.role is None


async def test_stub_verify_missing_uid():
    payload = base64.urlsafe_b64encode(json.dumps({"foo": 1}).encode()).decode()
    with pytest.raises(TokenInvalidError):
        await StubVerifier().verify(f"stub.{payload}.sig")


async def test_stub_verify_garbage():
    with pytest.raises(TokenInvalidError):
        await StubVerifier().verify("not-a-jwt")


async def test_stub_verify_pure_digit_token_shortcut():
    """纯数字 token 直接作 user_id（M7 stub 登录简化）：`Bearer 12345` →
    Identity(user_id="12345")（user_name/role 为 None），在 JWT 解析之前短路——
    stub 登录页输入数字即身份，免构造信封；信封票据路径不受影响（上方既有用例）。
    全角数字（isdigit=True 但 isascii=False）不短路，走 JWT 解析 → 401。"""
    identity = await StubVerifier().verify("12345")
    assert identity == Identity(user_id="12345")
    assert (await StubVerifier().verify("0")).user_id == "0"
    with pytest.raises(TokenInvalidError):
        await StubVerifier().verify("１２３")


def test_build_verifier_unknown_impl():
    with pytest.raises(NotImplementedError):
        build_verifier("magic")
