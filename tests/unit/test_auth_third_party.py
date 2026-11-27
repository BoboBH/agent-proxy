"""ThirdPartyVerifier 单测（设计 v4.1：对接 docs/auth_verify_token_integration.md）。

MockTransport 注入 → 不出网；覆盖：成功映射 / Token scheme 原样透传 / 401·403·
valid:false → 401 INVALID_TOKEN / 5xx·网络错误 → 503 AUTH_SERVICE_UNAVAILABLE /
locked·deleted 拒收 / user_id 非整数拒收 / 短 TTL 缓存 / build_verifier 默认 beta 基址。
"""
import httpx
import pytest

from app.services.auth import (ThirdPartyVerifier, TokenInvalidError,
                               TokenServiceError, build_verifier)

BETA_BASE = "https://bapal.9m-tec.com/alphapal/api/ai-service"
OK_BODY = {"valid": True, "user_id": 8743, "username": "someone@example.com",
           "real_name": "张三", "user_type": "org_member", "status": "active",
           "token_kind": "access"}


def _third(handler) -> ThirdPartyVerifier:
    return ThirdPartyVerifier(BETA_BASE, transport=httpx.MockTransport(handler))


async def test_third_verify_ok_hits_verify_token_with_bearer():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["method"] = request.method
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=OK_BODY)

    identity = await _third(handler).verify_credential("Bearer eyA.eyJz.igm")
    assert identity.user_id == 8743 and isinstance(identity.user_id, int)
    assert identity.user_name == "someone@example.com"
    assert identity.role == "org_member"
    assert seen["url"] == f"{BETA_BASE}/auth/verify_token"
    assert seen["method"] == "GET"
    assert seen["auth"] == "Bearer eyA.eyJz.igm"


async def test_third_verify_credential_passes_token_scheme_verbatim():
    """API 原生支持 Token scheme——凭据头原样透传（统一 token 场景：skill 教传的
    Authorization: Token <jwt> 在默认头名下即可直通鉴权）。"""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == "Token abc.def.sig"
        return httpx.Response(200, json=OK_BODY)

    identity = await _third(handler).verify_credential("Token abc.def.sig")
    assert identity.user_id == 8743


async def test_third_401_maps_to_invalid_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"msg": "令牌已过期"})

    with pytest.raises(TokenInvalidError) as excinfo:
        await _third(handler).verify_credential("Bearer bad")
    assert "令牌已过期" in excinfo.value.message


async def test_third_200_valid_false_maps_to_invalid():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"valid": False, "message": "用户不存在或令牌无效"})

    with pytest.raises(TokenInvalidError):
        await _third(handler).verify_credential("Bearer x")


async def test_third_403_env_forbidden_maps_to_invalid_not_retry():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "beta 白名单限制"})

    with pytest.raises(TokenInvalidError):
        await _third(handler).verify_credential("Bearer x")


async def test_third_5xx_maps_to_service_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="bad gateway")

    with pytest.raises(TokenServiceError) as excinfo:
        await _third(handler).verify_credential("Bearer x")
    assert excinfo.value.status == 503


async def test_third_network_error_maps_to_service_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(TokenServiceError):
        await _third(handler).verify_credential("Bearer x")


async def test_third_rejects_locked_and_deleted_status():
    for status in ("locked", "deleted"):
        def handler(request: httpx.Request, _s=status) -> httpx.Response:
            return httpx.Response(200, json={**OK_BODY, "status": _s})

        with pytest.raises(TokenInvalidError):
            await _third(handler).verify_credential("Bearer x")


async def test_third_rejects_non_int_user_id():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={**OK_BODY, "user_id": "8743"})

    with pytest.raises(TokenInvalidError):
        await _third(handler).verify_credential("Bearer x")


async def test_third_short_ttl_cache_avoids_repeat_http():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=OK_BODY)

    v = _third(handler)
    await v.verify_credential("Bearer same-token")
    await v.verify_credential("Bearer same-token")
    assert calls["n"] == 1        # 短 TTL 缓存（文档注记 2/3：不缓存永久、可频繁调用）


def test_build_verifier_third_party_uses_settings_default_base():
    v = build_verifier("third_party")
    assert isinstance(v, ThirdPartyVerifier)
    assert v.api_base == BETA_BASE        # 默认 beta 环境（VERIFY_API_BASE 可切生产）
