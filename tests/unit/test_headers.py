"""出站 header 重建（安全核心）单测：存储全量 + 协议白名单；调用方其余 header 一律不透传。"""
from agent_proxy.headers import build_outbound_headers, filter_response_headers, is_hop_by_hop


def test_stored_full_plus_whitelist_caller_jwt_not_forwarded():
    out = build_outbound_headers(
        {"Authorization": "Bearer sk-real-12345678", "X-User-Id": "u888"},
        {"Authorization": "Bearer caller-system-jwt", "Accept": "application/json",
         "X-Caller-Only": "should-not-leak", "User-Agent": "agent/1.0",
         "Cookie": "sid=abc"},
        content_type="application/json", content_length="11", content_encoding=None)
    assert out["Authorization"] == "Bearer sk-real-12345678"      # 存储还原（调用方 JWT 被丢弃）
    assert out["X-User-Id"] == "u888"
    assert out["Accept"] == "application/json"                    # 白名单透传
    assert out["Content-Type"] == "application/json"
    assert out["Content-Length"] == "11"
    assert "X-Caller-Only" not in out and "User-Agent" not in out and "Cookie" not in out


def test_explicit_body_params_override_caller_values():
    out = build_outbound_headers({}, {"Content-Type": "text/plain"},
                                 content_type="application/gzip",
                                 content_length="7", content_encoding="gzip")
    assert out["Content-Type"] == "application/gzip"
    assert out["Content-Length"] == "7"
    assert out["Content-Encoding"] == "gzip"


def test_mcp_protocol_headers_whitelisted():
    out = build_outbound_headers(
        {}, {"Mcp-Session-Id": "s-001", "Last-Event-ID": "42",
             "MCP-Protocol-Version": "2025-06-18", "X-Other": "no"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"Mcp-Session-Id": "s-001", "Last-Event-ID": "42",
                   "MCP-Protocol-Version": "2025-06-18"}


def test_hop_by_hop_stripped_from_both_sides():
    out = build_outbound_headers(
        {"Connection": "close", "Keep-Alive": "timeout=5", "X-Keep": "v"},
        {"Transfer-Encoding": "chunked", "Te": "trailers", "Upgrade": "websocket",
         "Proxy-Authorization": "Basic x", "Proxy-Note": "n"},
        content_type=None, content_length=None, content_encoding=None)
    assert out == {"X-Keep": "v"}          # 两侧 hop-by-hop 全部剥离，仅剩普通头
    assert is_hop_by_hop("Proxy-Foo")       # Proxy-* 前缀兜底


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
