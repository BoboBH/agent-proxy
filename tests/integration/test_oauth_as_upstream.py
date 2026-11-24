"""mock OAuth AS（9904）直连冒烟（真实 TCP）：先钉住 mock 自身协议行为，代理链路
测试（binding/injection/dcr）才有可信参照。覆盖：well-known×2、DCR、authorize
（redirect_uri 精确/PKCE 必须）、token（code 一次性 / PKCE S256 校验 / client 认证
basic+post）、refresh（可复用 + 脚本化失败）、revoke（连带 refresh）、RS echo、
preset 手动客户端。"""
import base64

import httpx

from tests.integration.mock_mcp_streamable import secure_state
from tests.integration.mock_oauth_as import as_state

BASE = "http://127.0.0.1:9904"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"   # RFC 7636 附录 B
REDIRECT = "http://127.0.0.1:9910/oauth/callback/m1m2m3m4m5m6"


async def _register(c, **overrides) -> dict:
    payload = {"client_name": "smoke", "redirect_uris": [REDIRECT],
               "grant_types": ["authorization_code", "refresh_token"],
               "token_endpoint_auth_method": "client_secret_post", **overrides}
    resp = await c.post(f"{BASE}/oauth/register", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _authorize_params(client_id: str) -> dict:
    return {"client_id": client_id, "redirect_uri": REDIRECT,
            "response_type": "code", "state": "st-1",
            "code_challenge": CHALLENGE, "code_challenge_method": "S256"}


async def _code(c, client_id: str) -> str:
    r = await c.get(f"{BASE}/oauth/authorize", params=_authorize_params(client_id),
                    follow_redirects=False)
    assert r.status_code == 302, r.text
    location = r.headers["location"]
    assert location.startswith(f"{REDIRECT}?code=") and "state=st-1" in location
    return location.split("code=")[1].split("&")[0]


async def test_well_known_pair_served():
    async with httpx.AsyncClient() as c:
        pr = (await c.get(f"{BASE}/.well-known/oauth-protected-resource")).json()
        assert pr["authorization_servers"] == [BASE]
        meta = (await c.get(f"{BASE}/.well-known/oauth-authorization-server")).json()
        assert meta["token_endpoint"] == f"{BASE}/oauth/token"
        assert meta["registration_endpoint"] == f"{BASE}/oauth/register"
        assert meta["revocation_endpoint"] == f"{BASE}/oauth/revoke"
        assert "S256" in meta["code_challenge_methods_supported"]


async def test_dcr_register_issues_client_and_records_request():
    async with httpx.AsyncClient() as c:
        body = await _register(c, client_name="agent-proxy-test")
    assert body["client_id"].startswith("cl-") and body["client_secret"].startswith("cs-")
    assert as_state["registrations"][-1]["client_name"] == "agent-proxy-test"
    assert as_state["registrations"][-1]["redirect_uris"] == [REDIRECT]


async def test_authorize_rejects_wrong_redirect_uri_and_missing_pkce():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        bad_redirect = await c.get(f"{BASE}/oauth/authorize", params={
            **_authorize_params(cl["client_id"]),
            "redirect_uri": "http://evil.example.com/cb"}, follow_redirects=False)
        assert bad_redirect.status_code == 400            # redirect_uri 精确匹配
        no_pkce = await c.get(f"{BASE}/oauth/authorize", params={
            "client_id": cl["client_id"], "redirect_uri": REDIRECT,
            "response_type": "code", "state": "s"}, follow_redirects=False)
        assert no_pkce.status_code == 400                 # PKCE 必须
        unknown_client = await c.get(f"{BASE}/oauth/authorize", params={
            **_authorize_params("cl-unknown")}, follow_redirects=False)
        assert unknown_client.status_code == 400


async def test_token_exchange_full_and_code_one_time():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        ok = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert ok.status_code == 200
        tokens = ok.json()
        assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 3600
        assert tokens["access_token"] in secure_state["valid_tokens"]
        # code 一次性：同一 code 第二次换 → invalid_grant
        replay = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"


async def test_token_pkce_wrong_verifier_rejected():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": "wrong-verifier-wrong-verifier-wrong-verifier-wrong",
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
    assert r.status_code == 400                          # S256(verifier) != challenge
    assert r.json()["error"] == "invalid_grant"


async def test_token_client_secret_post_mismatch_401():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": "whatever",
            "client_id": cl["client_id"], "client_secret": "bad-secret"})
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


async def test_token_client_secret_basic_auth_accepted():
    async with httpx.AsyncClient() as c:
        cl = await _register(c, token_endpoint_auth_method="client_secret_basic")
        code = await _code(c, cl["client_id"])
        basic = base64.b64encode(
            f"{cl['client_id']}:{cl['client_secret']}".encode()).decode()
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER},
            headers={"Authorization": f"Basic {basic}"})
    assert r.status_code == 200


async def test_refresh_grant_and_scripted_failure():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        tokens = (await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})).json()
        r1 = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert r1.status_code == 200
        assert r1.json()["access_token"] != tokens["access_token"]
        assert len(as_state["refresh_events"]) == 1
        # 脚本化失败：fail_refresh=True → invalid_grant（刷新失败→invalid 用例依赖）
        as_state["fail_refresh"] = True
        r2 = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert r2.status_code == 400
        as_state["fail_refresh"] = False
        # 伪造/已吊销 refresh token → invalid_grant
        r3 = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": "rt-forged",
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert r3.status_code == 400


async def test_revoke_discards_access_and_paired_refresh():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        tokens = (await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})).json()
        rv = await c.post(f"{BASE}/oauth/revoke", data={
            "token": tokens["access_token"], "token_type_hint": "access_token"})
        assert rv.status_code == 200
        assert tokens["access_token"] not in secure_state["valid_tokens"]
        assert tokens["refresh_token"] in as_state["revoked_refresh"]
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert r.status_code == 400                      # 配对 refresh 已连带作废


async def test_preset_manual_client_flow_post():
    async with httpx.AsyncClient() as c:
        code = await _code(c, "manual-cl")
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": "manual-cl", "client_secret": "manual-cs-123456"})
    assert r.status_code == 200                          # 手动模式凭证被 mock AS 认可


async def test_rs_echo_returns_headers():
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{BASE}/api/v1/orders?id=1",
                        headers={"Authorization": "Bearer at-echo-probe"})
    assert r.status_code == 200
    body = r.json()
    assert body["path"] == "/v1/orders" and body["query"]["id"] == "1"
    assert body["headers"]["authorization"] == "Bearer at-echo-probe"
