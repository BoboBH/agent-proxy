import pytest

from agent_proxy.placeholder import proxy_call_headers, validate_headers


def test_proxy_call_headers_spec():
    """设计 v3：回显 headers = 代理调用配置（仅 X-Proxy-Authorization，值{{RUNTIME_TOKEN}}
    占位符，由平台运行时替换）；每次调用返回新 dict（防共享可变状态被响应链改写）。"""
    spec = proxy_call_headers()
    assert spec == {"X-Proxy-Authorization": "{{RUNTIME_TOKEN}}"}
    spec["X-Proxy-Authorization"] = "mutated"
    assert proxy_call_headers() == {"X-Proxy-Authorization": "{{RUNTIME_TOKEN}}"}


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
