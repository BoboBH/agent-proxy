"""出站 header 重建（安全核心）单测：存储全量 + 协议白名单；调用方其余 header 一律不透传。

评审修复约定：出站 key 统一小写归一。HTTP 头名大小写不敏感，存储 / caller /
explicit 三源若同名不同大小写会并存为两个 key，经 httpx 发出重复头行（上线事故级）。
"""
from agent_proxy.headers import build_outbound_headers, filter_response_headers, is_hop_by_hop


def test_stored_full_plus_whitelist_caller_jwt_not_forwarded():
    out = build_outbound_headers(
        {"Authorization": "Bearer sk-real-12345678", "X-User-Id": "u888"},
        {"Authorization": "Bearer caller-system-jwt", "Accept": "application/json",
         "X-Caller-Only": "should-not-leak", "User-Agent": "agent/1.0",
         "Cookie": "sid=abc"},
        content_type="application/json", content_length="11", content_encoding=None)
    assert out["authorization"] == "Bearer sk-real-12345678"      # 存储还原（调用方 JWT 被丢弃）
    assert out["x-user-id"] == "u888"
    assert out["accept"] == "application/json"                    # 白名单透传
    assert out["content-type"] == "application/json"
    assert out["content-length"] == "11"
    assert "x-caller-only" not in out and "user-agent" not in out and "cookie" not in out


def test_explicit_body_params_override_caller_values():
    out = build_outbound_headers({}, {"Content-Type": "text/plain"},
                                 content_type="application/gzip",
                                 content_length="7", content_encoding="gzip")
    assert out["content-type"] == "application/gzip"
    assert out["content-length"] == "7"
    assert out["content-encoding"] == "gzip"


def test_mcp_protocol_headers_whitelisted():
    out = build_outbound_headers(
        {}, {"Mcp-Session-Id": "s-001", "Last-Event-ID": "42",
             "MCP-Protocol-Version": "2025-06-18", "X-Other": "no"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"mcp-session-id": "s-001", "last-event-id": "42",
                   "mcp-protocol-version": "2025-06-18"}


def test_hop_by_hop_stripped_from_both_sides():
    out = build_outbound_headers(
        {"Connection": "close", "Keep-Alive": "timeout=5", "X-Keep": "v"},
        {"Transfer-Encoding": "chunked", "Te": "trailers", "Upgrade": "websocket",
         "Proxy-Authorization": "Basic x", "Proxy-Note": "n"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"x-keep": "v"}          # 两侧 hop-by-hop 全部剥离，仅剩普通头
    assert is_hop_by_hop("Proxy-Foo")       # Proxy-* 前缀兜底


# ---------- 评审修复：出站 key 小写归一（防重复头上线） ----------


def test_stored_and_caller_same_name_case_insensitive_caller_wins():
    """存储头与 caller 白名单头同名不同大小写：归一后仅该头一行，caller（本次载荷）胜出。"""
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
