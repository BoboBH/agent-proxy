"""forward 纯函数单测：前缀拼接（§8.2）、子路径分发、dot-segment 拒绝（§8.1 第 8 条）。"""
import pytest

from agent_proxy.errors import AppError
from agent_proxy.forward.http_forward import (assert_safe_sub_path, build_forward_target,
                                              split_sub_path)


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
