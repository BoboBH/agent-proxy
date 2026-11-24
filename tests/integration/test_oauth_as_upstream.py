"""mock OAuth AS（9904）直连冒烟（真实 TCP）：先钉住 mock 自身协议行为，代理链路
测试（binding/injection/dcr）才有可信参照。覆盖：well-known×2、DCR、authorize
（redirect_uri 精确/PKCE 必须/plain 降级拒绝）、token（code 一次性 / 跨客户端盗用
拒绝 / redirect_uri 缺失拒绝 / PKCE S256 校验 / client 认证 basic+post+none /
refresh_token 绑定归属 client）、refresh（可复用 + 脚本化失败）、revoke（客户端
认证门 + 凭证记入 revocations + 连带 refresh）、/_test/reset 清 secure_state、
RS echo、preset 手动客户端。"""
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
    # 评审 Critical 1：RFC 7591 §3.2.1 注册成功 = 201 Created（mock 钉住真实提供方行为）
    assert resp.status_code == 201, resp.text
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


async def test_token_cross_client_code_and_refresh_theft_rejected():
    """跨客户端盗用：A 签发的 code 用 B 的身份兑换 → invalid_grant（code 绑定签发
    client，且拒绝不消耗 code——归属方仍可正常兑换）；A 的 refresh_token 用 B 的
    身份刷新 → invalid_grant（rt 绑定归属 client_id）。"""
    async with httpx.AsyncClient() as c:
        cl_a = await _register(c, client_name="victim")
        cl_b = await _register(c, client_name="thief")
        code = await _code(c, cl_a["client_id"])
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl_b["client_id"], "client_secret": cl_b["client_secret"]})
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
        ok = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl_a["client_id"], "client_secret": cl_a["client_secret"]})
        assert ok.status_code == 200                      # 盗用未消耗合法 code
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token",
            "refresh_token": ok.json()["refresh_token"],
            "client_id": cl_b["client_id"], "client_secret": cl_b["client_secret"]})
        assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


async def test_token_missing_redirect_uri_rejected():
    """code 绑定 authorize 时的 redirect_uri，token 请求缺失该参数 → invalid_grant。"""
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


async def test_authorize_plain_challenge_downgrade_rejected():
    """PKCE 降级攻击：code_challenge_method=plain → 400 invalid_request（仅 S256）。"""
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        r = await c.get(f"{BASE}/oauth/authorize", params={
            **_authorize_params(cl["client_id"]),
            "code_challenge_method": "plain"}, follow_redirects=False)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    assert "S256" in r.json()["error_description"]


async def test_public_client_none_auth_token_flow():
    """token_endpoint_auth_method=none 公共客户端全路径：注册不签发 secret，
    token 请求仅 client_id（无凭证）→ 200 并登记 9903 校验面。"""
    async with httpx.AsyncClient() as c:
        cl = await _register(c, token_endpoint_auth_method="none")
        assert "client_secret" not in cl
        code = await _code(c, cl["client_id"])
        r = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"]})
    assert r.status_code == 200, r.text
    assert r.json()["access_token"] in secure_state["valid_tokens"]


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
        # 脚本化失败：fail_refresh=True → invalid_grant（刷新失败→invalid 用例依赖）；
        # try/finally 复位——断言失败时不得把开关泄漏给后续用例（Task 2 评审携带）
        as_state["fail_refresh"] = True
        try:
            r2 = await c.post(f"{BASE}/oauth/token", data={
                "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
            assert r2.status_code == 400
        finally:
            as_state["fail_refresh"] = False
        # 伪造/已吊销 refresh token → invalid_grant
        r3 = await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": "rt-forged",
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
        assert r3.status_code == 400


async def test_revoke_requires_client_auth_and_records_credentials():
    """/oauth/revoke 客户端认证门（与 token 端点同构）：无凭证/错凭证 → 401；
    通过后凭证（client_id/client_secret/形态）记入 revocations——Task 5 断言
    「凭证确实随 revoke 发出」依赖该记录面。"""
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        tokens = (await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})).json()
        no_auth = await c.post(f"{BASE}/oauth/revoke",
                               data={"token": tokens["access_token"]})
        assert no_auth.status_code == 401
        assert no_auth.json()["error"] == "invalid_client"
        bad = await c.post(f"{BASE}/oauth/revoke", data={
            "token": tokens["access_token"], "client_id": cl["client_id"],
            "client_secret": "wrong-secret"})
        assert bad.status_code == 401
        unknown = await c.post(f"{BASE}/oauth/revoke", data={
            "token": tokens["access_token"], "client_id": "cl-unknown",
            "client_secret": "whatever"})
        assert unknown.status_code == 401
        ok = await c.post(f"{BASE}/oauth/revoke", data={
            "token": tokens["access_token"], "client_id": cl["client_id"],
            "client_secret": cl["client_secret"]})
        assert ok.status_code == 200
        rec = as_state["revocations"][-1]
        assert rec["token"] == tokens["access_token"]
        assert rec["client_id"] == cl["client_id"]
        assert rec["client_secret"] == cl["client_secret"]
        assert rec["client_auth"] == "post"
        basic = base64.b64encode(
            f"{cl['client_id']}:{cl['client_secret']}".encode()).decode()
        rv2 = await c.post(f"{BASE}/oauth/revoke", data={"token": "at-gone"},
                           headers={"Authorization": f"Basic {basic}"})
        assert rv2.status_code == 200
        assert as_state["revocations"][-1]["client_auth"] == "basic"
        assert as_state["revocations"][-1]["client_id"] == cl["client_id"]
        none_cl = await _register(c, token_endpoint_auth_method="none")
        rv3 = await c.post(f"{BASE}/oauth/revoke",
                           data={"token": "at-gone2", "client_id": none_cl["client_id"]})
        assert rv3.status_code == 200
        assert as_state["revocations"][-1]["client_auth"] == "none"
        assert as_state["revocations"][-1]["client_id"] == none_cl["client_id"]


async def test_test_reset_clears_secure_state_received():
    """/_test/reset 同步清 secure_state["received"]（9903 /mcp-secure 记录面）——
    conftest 每测试前复位依赖此行为，注入断言需干净起点。"""
    async with httpx.AsyncClient() as c:
        await c.post("http://127.0.0.1:9903/mcp-secure",
                     json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert secure_state["received"]
        await c.post(f"{BASE}/_test/reset")
    assert secure_state["received"] == []


async def test_revoke_discards_access_and_paired_refresh():
    async with httpx.AsyncClient() as c:
        cl = await _register(c)
        code = await _code(c, cl["client_id"])
        tokens = (await c.post(f"{BASE}/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})).json()
        rv = await c.post(f"{BASE}/oauth/revoke", data={
            "token": tokens["access_token"], "token_type_hint": "access_token",
            "client_id": cl["client_id"], "client_secret": cl["client_secret"]})
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
