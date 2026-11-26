import pytest

from agent_proxy.placeholder import proxy_call_headers, validate_headers


def test_proxy_call_headers_spec():
    """设计 v4：回显 headers = 代理调用配置，头名跟随 PROXY_AUTH_HEADER 配置
    （默认 Authorization）；值 {{RUNTIME_TOKEN}} 占位符由平台运行时替换；
    每次调用返回新 dict（防共享可变状态被响应链改写）。"""
    spec = proxy_call_headers()   # 默认 Authorization
    assert spec == {"Authorization": "{{RUNTIME_TOKEN}}"}
    spec["Authorization"] = "mutated"
    assert proxy_call_headers() == {"Authorization": "{{RUNTIME_TOKEN}}"}
    assert proxy_call_headers("X-Proxy-Authorization") == \
        {"X-Proxy-Authorization": "{{RUNTIME_TOKEN}}"}


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
