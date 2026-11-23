import os

os.environ.setdefault("TOKEN_VERIFY_IMPL", "stub")

import pytest
from starlette.requests import Request

from agent_proxy.api.deps import get_current_identity, is_admin
from agent_proxy.auth import Identity, TokenInvalidError
from tests.utils import make_token


def _request(headers: list[tuple[bytes, bytes]]) -> Request:
    return Request(scope={"type": "http", "headers": headers, "state": {}})


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


def test_is_admin_matches_role():
    assert is_admin(Identity(user_id="u1", role="admin"), "admin")


def test_is_admin_false_when_role_mismatch_or_none():
    assert not is_admin(Identity(user_id="u1", role="viewer"), "admin")
    assert not is_admin(Identity(user_id="u1"), "admin")
