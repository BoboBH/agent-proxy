"""出站 header 重建（设计 v4）单测：**存储优先**（映射配了同名头 → 替换调用方值；
没配 → 调用方透传）+ forced 最高（oauth 托管）+ 协议显式值（content-*，真实载荷）。

认证头名可配置（PROXY_AUTH_HEADER，默认 Authorization）：
- 默认 Authorization：既作代理身份，又可作为上游凭证透传（统一 token 场景）；
- 配置为其他名字（如 x-proxy-authorization）：该头纯代理私有，绝不透传。

保留命名空间（来源无关，绝不透传）：cookie（防平台会话 ap_sess 泄漏）、host
（按转发目标派生）；hop-by-hop 双向剥离。

出站 key 统一小写归一（防同名不同大小写发重复头行）。
"""
from agent_proxy.headers import build_outbound_headers, filter_response_headers, is_hop_by_hop


def test_stored_wins_caller_passthrough_when_absent():
    """核心语义（设计 v4）：映射配了同名头 → 存储值替换调用方；没配的头 → 调用方
    原样透传（agent-email「直接使用 token」场景：映射不配 Authorization，调用方的
    Authorization: Token xxx 直达上游）。"""
    out = build_outbound_headers(
        {"Authorization": "Bearer stored-cred"},
        {"Authorization": "Token caller-skill-jwt", "X-Custom": "cv",
         "User-Agent": "agent-skill/1.0"},
        content_type="application/json", content_length="11", content_encoding=None,
        auth_header="authorization")
    assert out["authorization"] == "Bearer stored-cred"   # 存储优先（替换调用方）
    assert out["x-custom"] == "cv"                        # 未配置的头透传
    assert out["user-agent"] == "agent-skill/1.0"
    assert out["content-type"] == "application/json"


def test_caller_authorization_passthrough_when_mapping_has_none():
    """映射未配 Authorization + 调用方携带 → 原样透传（默认认证头可作上游凭证）。"""
    out = build_outbound_headers(
        {},
        {"Authorization": "Token shared-jwt"},
        content_type=None, content_length=None, content_encoding=None,
        auth_header="authorization")
    assert out == {"authorization": "Token shared-jwt"}


def test_custom_auth_header_is_reserved_not_forwarded():
    """配置为非默认名（x-proxy-authorization）时：该头纯代理私有——调用方/存储侧
    都不透传（v2 模式经配置恢复）；默认名 authorization 不在保留名单。"""
    out = build_outbound_headers(
        {"X-Proxy-Authorization": "Bearer stored"},
        {"X-Proxy-Authorization": "Bearer 999", "X-Ok": "v"},
        content_type=None, content_length=None, content_encoding=None,
        auth_header="x-proxy-authorization")
    assert out == {"x-ok": "v"}
    out2 = build_outbound_headers(
        {"X-Proxy-Authorization": "Bearer stored"},
        {"X-Proxy-Authorization": "Bearer 999", "Authorization": "Bearer caller"},
        content_type=None, content_length=None, content_encoding=None,
        auth_header="x-proxy-authorization")
    assert out2["authorization"] == "Bearer caller"       # 默认名在自定义模式下自由透传


def test_forced_oauth_credential_wins_over_stored_and_caller():
    """oauth 型映射（M6 凭证托管）：注入的本人凭证最高优先——压过存储与调用方。"""
    out = build_outbound_headers(
        {"Authorization": "Bearer stored"},
        {"Authorization": "Token caller-skill-jwt"},
        content_type=None, content_length=None, content_encoding=None,
        forced={"authorization": "Bearer user-access-token"},
        auth_header="authorization")
    assert out["authorization"] == "Bearer user-access-token"


def test_cookie_and_host_never_forwarded():
    out = build_outbound_headers(
        {"Cookie": "upstream=1", "Host": "stored-host"},
        {"Cookie": "ap_sess=leak-me", "Host": "127.0.0.1:8800", "X-Ok": "v"},
        content_type=None, content_length=None, content_encoding=None,
        auth_header="authorization")
    assert out == {"x-ok": "v"}


def test_explicit_body_params_win_over_stored_and_caller():
    """content-* 描述真实载荷——显式值压过存储与调用方（forced 除外）。"""
    out = build_outbound_headers(
        {"Content-Type": "text/stored"},
        {"Content-Type": "text/caller"},
        content_type="application/gzip", content_length="7", content_encoding="gzip",
        auth_header="authorization")
    assert out["content-type"] == "application/gzip"
    assert out["content-length"] == "7"
    assert out["content-encoding"] == "gzip"


def test_mcp_and_negotiation_headers_passthrough():
    out = build_outbound_headers(
        {}, {"Mcp-Session-Id": "s-001", "Last-Event-ID": "42",
             "MCP-Protocol-Version": "2025-06-18", "Accept-Encoding": "gzip"},
        content_type=None, content_length=None, content_encoding=None,
        auth_header="authorization")
    assert out == {"mcp-session-id": "s-001", "last-event-id": "42",
                   "mcp-protocol-version": "2025-06-18", "accept-encoding": "gzip"}


def test_hop_by_hop_stripped_from_both_sides():
    out = build_outbound_headers(
        {"Connection": "close", "Keep-Alive": "timeout=5", "X-Keep": "v"},
        {"Transfer-Encoding": "chunked", "Te": "trailers", "Upgrade": "websocket",
         "Proxy-Authorization": "Basic x", "Proxy-Note": "n"},
        content_type=None, content_length=None, content_encoding=None,
        auth_header="authorization")
    assert out == {"x-keep": "v"}
    assert is_hop_by_hop("Proxy-Foo")


def test_stored_and_caller_same_name_case_insensitive():
    """同名不同大小写：归一后仅一行，存储优先（v4）。"""
    out = build_outbound_headers(
        {"Content-Type": "application/json"},
        {"content-type": "text/plain"},
        content_type=None, content_length=None, content_encoding=None,
        auth_header="authorization")
    assert out == {"content-type": "application/json"}


def test_explicit_overrides_caller_no_duplicate_line():
    out = build_outbound_headers(
        {}, {"content-type": "text/plain", "content-length": "3"},
        content_type="application/gzip", content_length="7", content_encoding=None,
        auth_header="authorization")
    assert out == {"content-type": "application/gzip", "content-length": "7"}
    assert list(out) == ["content-type", "content-length"]


def test_is_hop_by_hop_case_insensitive():
    assert is_hop_by_hop("CONNECTION")
    assert not is_hop_by_hop("X-Custom")


def test_empty_inputs_minimal():
    assert build_outbound_headers({}, {}, None, None, None) == {}
    assert build_outbound_headers({}, {}, None, None, None,
                                  auth_header="x-proxy-authorization") == {}


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
