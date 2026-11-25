"""出站 header 重建（设计 v2 透传模型）单测：存储全量打底 + 调用方全量透传（同名调用方
覆盖存储）+ forced 最高优先（oauth 托管凭证）。

保留命名空间（绝不透传）：x-proxy-authorization（代理身份，已消费）、cookie（防平台
会话 ap_sess 泄漏上游）、hop-by-hop 双向剥离。

评审修复约定沿袭：出站 key 统一小写归一。HTTP 头名大小写不敏感，存储 / caller /
explicit / forced 四源若同名不同大小写会并存为两个 key，经 httpx 发出重复头行。
"""
from agent_proxy.headers import build_outbound_headers, filter_response_headers, is_hop_by_hop


def test_stored_plus_caller_passthrough_caller_wins_on_collision():
    """核心语义（设计 v2）：调用方 header 全量透传；与存储同名时调用方胜出
    （skill 教传的 Authorization: Token xxx 原样直达上游）。"""
    out = build_outbound_headers(
        {"Authorization": "Bearer sk-real-12345678", "X-User-Id": "u-888"},
        {"Authorization": "Token skill-jwt", "X-Custom": "cv", "User-Agent": "agent/1.0",
         "Accept": "application/json"},
        content_type="application/json", content_length="11", content_encoding=None)
    assert out["authorization"] == "Token skill-jwt"      # 调用方覆盖存储
    assert out["x-user-id"] == "u-888"                    # 存储照常注入
    assert out["x-custom"] == "cv"                        # 任意调用方头透传
    assert out["user-agent"] == "agent/1.0"
    assert out["accept"] == "application/json"
    assert out["content-type"] == "application/json"


def test_stored_value_used_when_caller_omits_name():
    """调用方未带该头 → 存储值出站（公共映射共享凭据的默认路径）。"""
    out = build_outbound_headers(
        {"Authorization": "Bearer sk-real-12345678"},
        {"Accept": "application/json"},
        content_type=None, content_length=None, content_encoding=None)
    assert out["authorization"] == "Bearer sk-real-12345678"


def test_reserved_proxy_auth_header_never_forwarded():
    """保留命名空间：x-proxy-authorization 是代理身份通道（已被消费），无论来自
    调用方还是存储都绝不透传上游。"""
    out = build_outbound_headers(
        {"X-Proxy-Authorization": "Bearer 888"},
        {"X-Proxy-Authorization": "Bearer 999", "X-Ok": "v"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"x-ok": "v"}


def test_cookie_header_never_forwarded():
    """cookie 整头剥离（防平台会话 ap_sess 泄漏给上游）；上游 cookie 走存储 headers。"""
    out = build_outbound_headers(
        {},
        {"Cookie": "ap_sess=abc; sid=1", "X-Ok": "v"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"x-ok": "v"}


def test_host_header_never_forwarded():
    """host 由 httpx 按目标 URL 派生——透传调用方 host 会破坏上游 vhost 路由。"""
    out = build_outbound_headers(
        {},
        {"Host": "127.0.0.1:8800", "X-Ok": "v"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"x-ok": "v"}


def test_forced_oauth_credential_wins_over_caller():
    """oauth 型映射（M6 凭证托管）：注入的本人凭证最高优先——调用方自带
    Authorization 也不能覆盖（否则托管语义被绕过）。"""
    out = build_outbound_headers(
        {"Authorization": "Bearer stored"},
        {"Authorization": "Token caller-skill-jwt"},
        content_type=None, content_length=None, content_encoding=None,
        forced={"authorization": "Bearer user-access-token"})
    assert out["authorization"] == "Bearer user-access-token"


def test_explicit_body_params_override_caller_values():
    out = build_outbound_headers({}, {"Content-Type": "text/plain"},
                                 content_type="application/gzip",
                                 content_length="7", content_encoding="gzip")
    assert out["content-type"] == "application/gzip"
    assert out["content-length"] == "7"
    assert out["content-encoding"] == "gzip"


def test_mcp_and_negotiation_headers_forwarded():
    out = build_outbound_headers(
        {}, {"Mcp-Session-Id": "s-001", "Last-Event-ID": "42",
             "MCP-Protocol-Version": "2025-06-18", "Accept-Encoding": "gzip"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"mcp-session-id": "s-001", "last-event-id": "42",
                   "mcp-protocol-version": "2025-06-18", "accept-encoding": "gzip"}


def test_hop_by_hop_stripped_from_both_sides():
    out = build_outbound_headers(
        {"Connection": "close", "Keep-Alive": "timeout=5", "X-Keep": "v"},
        {"Transfer-Encoding": "chunked", "Te": "trailers", "Upgrade": "websocket",
         "Proxy-Authorization": "Basic x", "Proxy-Note": "n"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"x-keep": "v"}          # 两侧 hop-by-hop 全部剥离，仅剩普通头
    assert is_hop_by_hop("Proxy-Foo")       # Proxy-* 前缀兜底


def test_proxy_auth_header_name_not_caught_by_hop_by_hop_prefix():
    """x-proxy-authorization 不得被 proxy-* 前缀误伤——它由保留名单剥离（语义不同），
    但剥离动作必须独立成立（若 hop 前缀误伤会掩盖保留名单回归）。"""
    assert not is_hop_by_hop("X-Proxy-Authorization")
    out = build_outbound_headers({}, {"X-Proxy-Authorization": "Bearer 1"},
                                 content_type=None, content_length=None,
                                 content_encoding=None)
    assert out == {}


def test_stored_and_caller_same_name_case_insensitive_caller_wins():
    """存储头与调用方头同名不同大小写：归一后仅该头一行，调用方（本次载荷）胜出。"""
    out = build_outbound_headers(
        {"Content-Type": "application/json"},
        {"content-type": "text/plain"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"content-type": "text/plain"}


def test_explicit_overrides_caller_no_duplicate_line():
    """explicit 规范大写名与 caller ASGI 小写名归一为同一 key：仅一个小写键，无重复行。"""
    out = build_outbound_headers(
        {}, {"content-type": "text/plain", "content-length": "3"},
        content_type="application/gzip", content_length="7", content_encoding=None)
    assert out == {"content-type": "application/gzip", "content-length": "7"}
    assert list(out) == ["content-type", "content-length"]  # 仅小写键，无第二种大小写


def test_is_hop_by_hop_case_insensitive():
    assert is_hop_by_hop("CONNECTION")   # 大写变体同样命中
    assert not is_hop_by_hop("X-Custom")


def test_empty_inputs_minimal():
    assert build_outbound_headers({}, {}, None, None, None) == {}


def test_filter_response_headers_strips_hop_by_hop():
    out = filter_response_headers({
        "Content-Type": "application/json", "Content-Length": "3",
        "Set-Cookie": "a=1", "X-Custom": "v",
        "Connection": "close", "Keep-Alive": "x", "Transfer-Encoding": "chunked",
        "Trailer": "x", "Proxy-Foo": "bar",
    })
    assert out == {"Content-Type": "application/json", "Content-Length": "3",
                   "Set-Cookie": "a=1", "X-Custom": "v"}


def test_filter_response_headers_empty():
    assert filter_response_headers({}) == {}
