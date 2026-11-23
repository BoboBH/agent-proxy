import base64
import json

import pytest

from agent_proxy.auth import StubVerifier, TokenInvalidError, build_verifier
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


def test_build_verifier_unknown_impl():
    with pytest.raises(NotImplementedError):
        build_verifier("magic")
