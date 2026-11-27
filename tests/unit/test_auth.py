import base64
import json

import pytest

from app.auth import Identity, StubVerifier, TokenInvalidError, build_verifier
from tests.utils import make_token


async def test_stub_verify_ok():
    identity = await StubVerifier().verify(make_token(999, role="admin", user_name="李四"))
    assert identity.user_id == 999
    assert identity.role == "admin"
    assert identity.user_name == "李四"


async def test_stub_verify_without_role():
    identity = await StubVerifier().verify(make_token(888))
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
    Identity(user_id=12345)（user_name/role 为 None），在 JWT 解析之前短路——
    stub 登录页输入数字即身份，免构造信封；信封票据路径不受影响（上方既有用例）。
    全角数字（isdigit=True 但 isascii=False）不短路，走 JWT 解析 → 401。"""
    identity = await StubVerifier().verify("12345")
    assert identity == Identity(user_id=12345)
    assert (await StubVerifier().verify("0")).user_id == 0
    with pytest.raises(TokenInvalidError):
        await StubVerifier().verify("１２３")


async def test_stub_verify_envelope_user_id_must_be_integer():
    """收尾批次整数化：信封 user_id 为 int / 数字串均可（统一 int 化）；
    非整数（"u888"/浮点/容器/bool）一律 401 fail-closed——内部系统 user_id
    只有整数形态，不静默容错（避免 str/int 混型流入 owner_uid 比较链）。"""
    def _envelope(claims: dict) -> str:
        body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        return f"stub.{body}.sig"

    assert (await StubVerifier().verify(_envelope({"user_id": 888}))).user_id == 888
    assert (await StubVerifier().verify(_envelope({"user_id": "888"}))).user_id == 888
    for bad in ("u888", 1.5, True, ["888"], {"v": 1}, None, ""):
        with pytest.raises(TokenInvalidError):
            await StubVerifier().verify(_envelope({"user_id": bad}))


def test_build_verifier_unknown_impl():
    with pytest.raises(NotImplementedError):
        build_verifier("magic")
