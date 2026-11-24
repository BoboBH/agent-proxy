import pytest

from agent_proxy.placeholder import mask_headers, validate_headers


def test_mask_same_key_different_value():
    masked = mask_headers({"Authorization": "Bearer sk-real-key", "X-User-Id": "u-888"})
    assert masked == {"Authorization": "${PX:Authorization}", "X-User-Id": "${PX:X-User-Id}"}
    assert "sk-real-key" not in str(masked)


def test_validate_rejects_bad_name():
    with pytest.raises(ValueError):
        validate_headers({"bad header": "v"})


def test_validate_rejects_too_many():
    with pytest.raises(ValueError):
        validate_headers({f"h{i}": "v" for i in range(33)})


def test_validate_rejects_long_value():
    with pytest.raises(ValueError):
        validate_headers({"X-K": "x" * 4097})


def test_validate_rejects_non_str_key():
    with pytest.raises(ValueError):
        validate_headers({1: "v"})


def test_validate_empty_ok():
    validate_headers({})
