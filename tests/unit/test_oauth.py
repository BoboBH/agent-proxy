"""oauth 基础层单测（设计 §14.3 / §14.6）：Fernet 强制加密、PKCE(S256)、
state 载荷、authorization_url / redirect_uri 组装、token_auth 三形态请求组装、
DCR 注册载荷、AS 元数据解析、front_redirect 域白名单。"""
import base64
import hashlib
import json

import httpx
import pytest

from agent_proxy.errors import AppError
from agent_proxy.oauth.client import (build_authorization_url, build_dcr_payload,
                                      build_redirect_uri, build_token_request,
                                      code_challenge_s256, decode_state_payload,
                                      encode_state_payload, new_code_verifier,
                                      new_state, normalize_token_auth,
                                      state_key, validate_front_redirect)
from agent_proxy.oauth.credential import (encrypt_text, decrypt_text,
                                          expires_at_from, is_expired)
from agent_proxy.oauth.discovery import (DiscoveryError, discover_authorization_server,
                                         parse_as_metadata, parse_protected_resource,
                                         upstream_origin)

MASTER = "test-master-key"

# RFC 7636 附录 B 官方向量（S256 已知答案，钉死 challenge 算法）
RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

ALLOWED = ("http://127.0.0.1:9910", "http://testserver")


# ---------- crypto（§14.6：强制加密，不受 ENCRYPT_AT_REST 影响） ----------

def test_encrypt_decrypt_roundtrip_and_ciphertext_form():
    ct = encrypt_text("at-secret-value-123456", MASTER)
    assert ct != "at-secret-value-123456"
    assert ct.startswith("gAAAA")                      # Fernet 密文形态（读库验证的判据）
    assert decrypt_text(ct, MASTER) == "at-secret-value-123456"


def test_encrypt_requires_master_key_fail_closed():
    with pytest.raises(AppError) as ei:
        encrypt_text("x", "")
    assert (ei.value.status, ei.value.code) == (500, "INTERNAL_ERROR")


def test_decrypt_wrong_key_maps_to_internal_error():
    ct = encrypt_text("x", MASTER)
    with pytest.raises(AppError) as ei:
        decrypt_text(ct, "another-key")
    assert ei.value.code == "INTERNAL_ERROR"


def test_is_expired_none_means_never_and_skew_60s():
    from datetime import datetime, timedelta, timezone
    assert is_expired(None) is False                   # 无 expires_at = 永不过期
    now = datetime.now(timezone.utc)                   # aware UTC（utcnow 已弃用）
    assert is_expired(now + timedelta(seconds=30), now=now) is True    # 60s 提前量内
    assert is_expired(now + timedelta(seconds=120), now=now) is False
    assert is_expired(now - timedelta(seconds=1), now=now) is True


def test_is_expired_normalizes_naive_db_datetime_against_aware_now():
    """DB DateTime 列回读 naive → 按 UTC 语义归一（写侧 expires_at_from 同为 UTC），
    与 aware now 比较不抛 TypeError（模块内时间形态一致化）。"""
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    naive_past = (now - timedelta(seconds=1)).replace(tzinfo=None)
    assert is_expired(naive_past, now=now) is True
    naive_future = (now + timedelta(seconds=120)).replace(tzinfo=None)
    assert is_expired(naive_future, now=now) is False


def test_expires_at_from_returns_aware_utc_and_rejects_bad_input():
    from datetime import datetime, timezone
    out = expires_at_from(3600)
    assert out is not None and out.tzinfo is timezone.utc          # aware UTC（不再 utcnow）
    assert abs((out - datetime.now(timezone.utc)).total_seconds() - 3600) < 5
    assert expires_at_from(None) is None
    assert expires_at_from("not-a-number") is None
    assert expires_at_from(0) is None and expires_at_from(-30) is None


# ---------- PKCE（RFC 7636 S256 必须） ----------

def test_pkce_s256_known_vector():
    assert code_challenge_s256(RFC_VERIFIER) == RFC_CHALLENGE


def test_pkce_verifier_shape_and_randomness():
    v1, v2 = new_code_verifier(), new_code_verifier()
    assert len(v1) == 43 and v1 != v2                  # 32 字节 → base64url 43 字符
    assert code_challenge_s256(v1) != code_challenge_s256(v2)


# ---------- state（一次性 600s 绑 uid 的载荷，§14.4） ----------

def test_state_roundtrip_and_key_prefix():
    state = new_state()
    assert len(state) == 32                            # token_hex(16)
    assert state_key(state) == f"ap:oauth:state:{state}"
    payload = encode_state_payload(uid="u888", mapping_id="m1m2m3m4m5m6",
                                   code_verifier="v" * 43, front_redirect="http://t/c")
    restored = decode_state_payload(payload)
    assert restored == {"uid": "u888", "mapping_id": "m1m2m3m4m5m6",
                        "code_verifier": "v" * 43, "front_redirect": "http://t/c"}


def test_state_payload_missing_fields_rejected():
    from agent_proxy.errors import AppError
    with pytest.raises(AppError) as ei:
        decode_state_payload('{"uid": "u888"}')
    assert ei.value.code == "OAUTH_STATE_INVALID"
    with pytest.raises(AppError):
        decode_state_payload("not-json")


def test_state_payload_uid_and_mapping_id_must_be_str():
    """类型守卫：uid/mapping_id 非字符串（数字/None/容器）→ OAUTH_STATE_INVALID，
    不让畸形类型流入鉴权决策（uid 拼缓存键/落库）。"""
    base = {"code_verifier": "v" * 43, "front_redirect": "http://t/c"}
    for bad in ({"uid": 123, "mapping_id": "m1", **base},
                {"uid": "u888", "mapping_id": None, **base},
                {"uid": ["u888"], "mapping_id": "m1", **base}):
        with pytest.raises(AppError) as ei:
            decode_state_payload(json.dumps(bad))
        assert ei.value.code == "OAUTH_STATE_INVALID"


# ---------- URL / redirect_uri / DCR 载荷 ----------

def test_redirect_uri_exact_form():
    assert build_redirect_uri("http://127.0.0.1:9910/", "m1m2m3m4m5m6") == \
        "http://127.0.0.1:9910/oauth/callback/m1m2m3m4m5m6"


def test_authorization_url_contains_pkce_and_state():
    url = build_authorization_url("http://127.0.0.1:9904/oauth/authorize",
                                  client_id="cl-1",
                                  redirect_uri="http://t/oauth/callback/m1m2m3m4m5m6",
                                  state="s" * 32, code_verifier=RFC_VERIFIER,
                                  scopes="read write")
    assert "response_type=code" in url and "client_id=cl-1" in url
    assert f"code_challenge={RFC_CHALLENGE}" in url
    assert "code_challenge_method=S256" in url and "scope=read+write" in url
    assert "state=" in url and "redirect_uri=http%3A%2F%2Ft%2Foauth%2Fcallback%2F" in url


def test_authorization_url_rejoins_existing_query():
    url = build_authorization_url("http://as/oauth/authorize?prompt=login",
                                  client_id="c", redirect_uri="http://t/cb",
                                  state="s", code_verifier=RFC_VERIFIER, scopes=None)
    assert "prompt=login&" in url


def test_dcr_payload_rfc7591_fields():
    payload = build_dcr_payload("agent-proxy-m1m2m3m4m5m6",
                                "http://t/oauth/callback/m1m2m3m4m5m6")
    assert payload["redirect_uris"] == ["http://t/oauth/callback/m1m2m3m4m5m6"]
    assert set(payload["grant_types"]) == {"authorization_code", "refresh_token"}
    assert payload["token_endpoint_auth_method"] == "client_secret_post"
    assert payload["code_challenge_method"] == "S256"


# ---------- token 请求组装（token_auth 三形态，RFC 6749 §2.3） ----------

def test_token_request_client_secret_post():
    headers, form = build_token_request("client_secret_post", client_id="c1",
                                        client_secret="s1",
                                        extra={"grant_type": "refresh_token",
                                               "refresh_token": "rt1"})
    assert headers == {} and form["client_id"] == "c1" and form["client_secret"] == "s1"
    assert form["grant_type"] == "refresh_token"


def test_token_request_client_secret_basic():
    headers, form = build_token_request("client_secret_basic", client_id="c1",
                                        client_secret="s1", extra={"code": "cd1"})
    assert headers["Authorization"].startswith("Basic ")
    raw = base64.b64decode(headers["Authorization"][len("Basic "):]).decode()
    assert raw == "c1:s1"
    assert "client_secret" not in form and form["code"] == "cd1"


def test_token_request_none_public_client():
    headers, form = build_token_request("none", client_id="pub",
                                        client_secret=None, extra={"code": "cd1"})
    assert headers == {} and form["client_id"] == "pub" and "client_secret" not in form


def test_normalize_token_auth_fallback_to_post():
    assert normalize_token_auth(None) == "client_secret_post"
    assert normalize_token_auth("client_secret_jwt") == "client_secret_post"
    assert normalize_token_auth("client_secret_basic") == "client_secret_basic"


# ---------- discovery 元数据解析（RFC 9728 → RFC 8414 链） ----------

def test_discovery_parse_protected_resource_prefers_first_as_server():
    origin = "http://127.0.0.1:9904"
    assert parse_protected_resource({"authorization_servers": ["http://as-inner"]},
                                    origin) == "http://as-inner"
    assert parse_protected_resource({}, origin) == origin            # 缺省回退 origin
    assert parse_protected_resource("not-a-dict", origin) == origin


def test_discovery_parse_protected_resource_requires_http_scheme():
    """authorization_servers[0] 非 http(s) scheme（file/gopher/空壳）或 urlparse
    本身解析失败（畸形 IPv6 抛 ValueError）→ 回退 origin，不让畸形值进入第二跳
    URL 构造。"""
    origin = "http://127.0.0.1:9904"
    assert parse_protected_resource({"authorization_servers": ["file:///etc/passwd"]},
                                    origin) == origin
    assert parse_protected_resource({"authorization_servers": ["gopher://x"]},
                                    origin) == origin
    assert parse_protected_resource({"authorization_servers": ["   "]}, origin) == origin
    assert parse_protected_resource({"authorization_servers": ["http://[::1"]},
                                    origin) == origin    # urlparse ValueError → 回退
    assert parse_protected_resource(
        {"authorization_servers": ["https://as.ex.com"]},
        origin) == "https://as.ex.com"                               # https 合法保留


def test_discovery_parse_as_metadata_ok_and_missing():
    meta = parse_as_metadata({"authorization_endpoint": "http://a/auth",
                              "token_endpoint": "http://a/token",
                              "registration_endpoint": "http://a/reg"})
    assert meta["registration_endpoint"] == "http://a/reg"
    with pytest.raises(DiscoveryError):
        parse_as_metadata({"authorization_endpoint": "http://a/auth"})   # 缺 token_endpoint
    with pytest.raises(DiscoveryError):
        parse_as_metadata(None)


def test_discovery_upstream_origin_helper():
    assert upstream_origin("https://mcp.ex.com/sse?a=1") == "https://mcp.ex.com"


# ---------- discovery 探测函数（MockTransport，非 200 / 非 JSON / InvalidURL 归一） ----------

def _mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_discovery_probe_non_200_raises_discovery_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})
    async with _mock_client(handler) as c:
        with pytest.raises(DiscoveryError):
            await discover_authorization_server(c, "http://up.example")


async def test_discovery_probe_non_json_raises_discovery_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not-json</html>")
    async with _mock_client(handler) as c:
        with pytest.raises(DiscoveryError):
            await discover_authorization_server(c, "http://up.example")


async def test_discovery_malformed_metadata_url_invalidurl_raises_discovery_error():
    """畸形元数据 URL：authorization_servers 指向非法 port（scheme 合法可过解析校验，
    请求构造期抛 httpx.InvalidURL——直继承 Exception、非 HTTPError，不会被原 except
    捕获）——必须归一 DiscoveryError（映射 502 OAUTH_CLIENT_SETUP_FAILED），否则
    逃逸成 500。"""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"authorization_servers": [
            "http://as.ex.com:notaport"]})
    async with _mock_client(handler) as c:
        with pytest.raises(DiscoveryError):
            await discover_authorization_server(c, "http://up.example")


# ---------- front_redirect 域白名单（§14.6 防开放重定向） ----------

def test_front_redirect_allows_whitelisted_origin_with_path_query():
    out = validate_front_redirect("http://testserver/console?page=1", ALLOWED)
    assert out == "http://testserver/console?page=1"


def test_front_redirect_rejects_outside_whitelist():
    for bad in ("http://evil.example.com/cb",                    # 域不同
                "http://127.0.0.1:8080/cb",                      # 端口不同
                "https://testserver/cb",                         # scheme 不同
                "javascript:alert(1)",                           # 非 http(s)
                "/relative/path",                                # 相对地址
                "", "   "):
        with pytest.raises(AppError) as ei:
            validate_front_redirect(bad, ALLOWED)
        assert ei.value.code == "INVALID_PARAM"


def test_front_redirect_empty_whitelist_fail_closed():
    with pytest.raises(AppError):
        validate_front_redirect("http://testserver/cb", ())


def test_front_redirect_rejects_control_chars():
    """Task 4 评审携带批：值含 [\x00-\x1f\x7f] 一律拒绝——防 CRLF 注入响应 /
    畸形 Location 自 DoS；白名单 origin 命中不构成豁免。"""
    for bad in ("http://testserver/cb\r\nX-Inj: 1",       # CRLF 注入
                "http://testserver/\x00cb",                # NUL
                "http\x1b://testserver/cb",                # ESC
                "http://testserver/cb\x7f"):               # DEL
        with pytest.raises(AppError) as ei:
            validate_front_redirect(bad, ALLOWED)
        assert ei.value.code == "INVALID_PARAM"
