import pytest

from agent_proxy.ssrf import UpstreamNotAllowed, validate_upstream_url


def test_strip_trailing_slash():
    assert validate_upstream_url("http://10.0.0.5/api/v1/", allow_private=True) == "http://10.0.0.5/api/v1"


def test_reject_non_http_scheme():
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("ftp://10.0.0.5", allow_private=True)


def test_reject_private_when_not_allowed():
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("http://127.0.0.1:6379", allow_private=False)


def test_allow_private_when_enabled():
    assert validate_upstream_url("http://127.0.0.1:6379", allow_private=True).endswith("6379")


def test_reject_missing_host():
    with pytest.raises(UpstreamNotAllowed):
        validate_upstream_url("http:///path", allow_private=True)
