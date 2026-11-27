"""forward 纯函数单测：前缀拼接（§8.2）、子路径分发、dot-segment 拒绝（§8.1 第 8 条）。"""
import httpx
import pytest

from app.services.errors import AppError
from app.services.forward.http_forward import (assert_safe_sub_path, build_forward_target,
                                  _origin, _redirect_method, split_sub_path)


def test_build_target_prefix_join():
    assert build_forward_target("http://bobo.com/api/v1", "/orders", "status=paid") \
        == "http://bobo.com/api/v1/orders?status=paid"


def test_build_target_deep_path_and_trailing_slash_normalized():
    assert build_forward_target("http://bobo.com/api/v1/", "/a/b/c", "") \
        == "http://bobo.com/api/v1/a/b/c"


def test_build_target_empty_sub_path_direct_to_registered_url():
    assert build_forward_target("http://bobo.com/api/v1", "", "") == "http://bobo.com/api/v1"


@pytest.mark.parametrize("bad", ["/..", "/../etc", "/a/..", "/.", "/a/./b",
                                 "/%2e%2e", "/a/%2E%2E/b", "/%252e"])
def test_assert_safe_sub_path_rejects_dot_segments(bad):
    with pytest.raises(AppError) as ei:
        assert_safe_sub_path(bad)
    assert ei.value.status == 400 and ei.value.code == "INVALID_PARAM"


@pytest.mark.parametrize("bad", ["/..%252f", "/%2e%2e%252f", "/a/..%252fb",
                                 "/..%2f", "/%2e%2e%2fetc",
                                 "/..%5C", "/%2e%2e%5C"])
def test_assert_safe_sub_path_rejects_encoded_slash_composites(bad):
    """复合逃逸变体（Task 3 评审携带项）：编码斜杠与 dot 的组合，解码后按组件切分出 `..`。

    线上链路：`..%252f` 经 uvicorn 第 0 层解码 → `..%2f`（与段相等比较永不命中），
    上游再解码一次即 `../` → 逃逸注册前缀。修复契约：每层解码后按 / 切分，逐组件判定。
    """
    with pytest.raises(AppError) as ei:
        assert_safe_sub_path(bad)
    assert ei.value.status == 400 and ei.value.code == "INVALID_PARAM"


@pytest.mark.parametrize("ok", ["", "/", "/orders", "/orders/123", "/a-b.c_d", "/%E4%B8%AD"])
def test_assert_safe_sub_path_allows_normal_paths(ok):
    assert_safe_sub_path(ok)


def test_split_sub_path_basic():
    assert split_sub_path("/p/aB3xK9mQ2wR4/orders", "aB3xK9mQ2wR4") == "/orders"


def test_split_sub_path_empty_root():
    assert split_sub_path("/p/aB3xK9mQ2wR4", "aB3xK9mQ2wR4") == ""


def test_split_sub_path_prefix_mismatch_400():
    with pytest.raises(AppError) as ei:
        split_sub_path("/other/orders", "aB3xK9mQ2wR4")
    assert ei.value.status == 400


# ---------- Task 6 评审修复回归：重定向辅助函数 ----------


def test_redirect_method_303_downgrades_payload_methods():
    """303 → GET 仅降级载荷类方法（设计 §8.1 第 7 条）；GET 本就不变。"""
    for m in ("POST", "PUT", "PATCH", "DELETE"):
        assert _redirect_method(303, m) == "GET"
    assert _redirect_method(303, "GET") == "GET"


def test_redirect_method_301_302_307_308_keep_method():
    for status in (301, 302, 307, 308):
        assert _redirect_method(status, "POST") == "POST"
        assert _redirect_method(status, "DELETE") == "DELETE"


def test_origin_default_port_normalized():
    """origin 比较的端口归一（评审 Minor）：省略与显式默认端口必须判同一 origin。"""
    assert _origin(httpx.URL("http://x.com/a")) == ("http", "x.com", 80)
    assert _origin(httpx.URL("https://x.com/a")) == ("https", "x.com", 443)
    assert _origin(httpx.URL("https://x.com:443/b")) == _origin(httpx.URL("https://x.com/b"))
    assert _origin(httpx.URL("http://x.com:80/b")) == _origin(httpx.URL("http://x.com/c"))
    assert _origin(httpx.URL("http://x.com:8080/b")) == ("http", "x.com", 8080)
