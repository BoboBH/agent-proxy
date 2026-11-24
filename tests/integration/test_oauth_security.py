"""OAuth 安全专项（§14.6 / §13 OAuth 行）。与 binding flow 的重放/伪造用例互补：
- state TTL 钉 600s + 过期（直删模拟）→ 400；
- front_redirect origin 精确匹配（scheme/端口变体拒绝，path/query 保留放行）；
- token / refresh_token / client_secret 落库全密文（明文不落库）；
- 签发 token、refresh token、client_secret、授权 code 不出现在任何日志文件；
- 权限矩阵正向面：非 admin 普通用户可对 admin 建的公共映射发起授权绑定；
- 刷新锁释放属主校验（终审遗留 1：Lua compare-and-delete，非属主删除被拒）。"""
import glob
from urllib.parse import urlparse, parse_qs

from sqlalchemy import select

from agent_proxy.models import OAuthClient, OAuthCredential
from agent_proxy.oauth.credential import (decrypt_text, refresh_lock_key,
                                          release_refresh_lock)
from tests.utils import make_token

ADMIN = {"Authorization": f"Bearer {make_token(100, 'admin')}"}
U888 = {"Authorization": f"Bearer {make_token(888)}"}
FRONT = "http://testserver/console"
MASTER = "test-master-key"

CLIENT_BODY = {"client_id": "manual-cl", "client_secret": "manual-cs-123456",
               "token_auth": "client_secret_post",
               "authorize_url": "http://127.0.0.1:9904/oauth/authorize",
               "token_url": "http://127.0.0.1:9904/oauth/token", "scopes": "read"}


async def _setup_and_bind(client):
    created = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "oauth",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}, headers=ADMIN)).json()
    mid = created["mapping_id"]
    await client.put(f"/api/v1/builtin-mappings/{mid}/client", json=CLIENT_BODY,
                     headers=ADMIN)
    r = await client.post(f"/api/v1/builtin-mappings/{mid}/authorize",
                          json={"front_redirect": FRONT}, headers=U888)
    assert r.status_code == 200, r.text
    authz_url = r.json()["authorization_url"]
    import httpx
    async with httpx.AsyncClient() as browser:
        redir = await browser.get(authz_url, follow_redirects=False)
    assert redir.status_code == 302
    parsed = parse_qs(urlparse(authz_url).query)
    code_from_as = parse_qs(urlparse(redir.headers["location"]).query)["code"][0]
    return mid, parsed["state"][0], code_from_as


async def _complete_callback(client, mid, state, code):
    """回调落地凭证（计划原稿缺陷修正：_setup_and_bind 只走到 AS 302 拿 code，
    credential 行由回调创建——落库断言面须先完成回调）。"""
    resp = await client.get(f"/oauth/callback/{mid}?code={code}&state={state}",
                            follow_redirects=False)
    assert resp.status_code == 302 and "binding=success" in resp.headers["location"]


async def test_state_ttl_pinned_600(client, app):
    mid, state, _ = await _setup_and_bind(client)
    ttl = await app.state.redis.ttl(f"ap:oauth:state:{state}")
    assert 590 < ttl <= 601                               # OAUTH_STATE_TTL=600


async def test_state_expired_simulated_400(client, app):
    """过期语义：直删 state key 模拟 TTL 到期（600s 等不起）——与「伪造不存在」
    同一 400 分支（consume_state 未命中即 OAUTH_STATE_INVALID）。"""
    mid, state, code = await _setup_and_bind(client)
    await app.state.redis.delete(f"ap:oauth:state:{state}")
    resp = await client.get(f"/oauth/callback/{mid}?code={code}&state={state}",
                            follow_redirects=False)
    assert resp.status_code == 400
    assert resp.json()["code"] == "OAUTH_STATE_INVALID"


async def test_front_redirect_origin_exact_match(client):
    mid = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "oauth",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}, headers=ADMIN)).json()["mapping_id"]
    await client.put(f"/api/v1/builtin-mappings/{mid}/client", json=CLIENT_BODY,
                     headers=ADMIN)
    for bad in ("https://testserver/cb",                   # scheme 不同
                "http://testserver:8080/cb",               # 端口不同
                "http://evil.testserver/cb",               # 子域形似（netloc 精确比较）
                "http://testserver.evil.com/cb"):
        resp = await client.post(f"/api/v1/builtin-mappings/{mid}/authorize",
                                 json={"front_redirect": bad}, headers=U888)
        assert resp.status_code == 400 and resp.json()["code"] == "INVALID_PARAM"


async def test_front_redirect_path_query_preserved(client):
    """origin 精确匹配只约束 scheme://netloc——白名单域下的 path/query 保留放行
    （页面回跳定位用），不做路径白名单。"""
    mid = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "oauth",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}, headers=ADMIN)).json()["mapping_id"]
    await client.put(f"/api/v1/builtin-mappings/{mid}/client", json=CLIENT_BODY,
                     headers=ADMIN)
    resp = await client.post(
        f"/api/v1/builtin-mappings/{mid}/authorize",
        json={"front_redirect": f"{FRONT}?next=/x&tab=1"}, headers=U888)
    assert resp.status_code == 200                        # path/query 保留放行


async def test_all_secrets_ciphertext_at_rest(client, app):
    """§14.6 强制加密三面：client_secret + access_token + refresh_token 全密文。"""
    mid, state, code = await _setup_and_bind(client)
    await _complete_callback(client, mid, state, code)
    async with app.state.sessionmaker() as session:
        client_row = (await session.execute(
            select(OAuthClient).where(OAuthClient.mapping_id == mid))).scalar_one()
        cred_row = (await session.execute(
            select(OAuthCredential).where(
                OAuthCredential.mapping_id == mid))).scalar_one()
    assert client_row.client_secret.startswith("gAAAA")
    assert cred_row.access_token.startswith("gAAAA")
    assert cred_row.refresh_token.startswith("gAAAA")
    dump = f"{client_row.client_secret}{cred_row.access_token}{cred_row.refresh_token}"
    assert "manual-cs-123456" not in dump                 # 明文不落库
    assert decrypt_text(cred_row.access_token, MASTER).startswith("at-")


async def test_issued_secrets_absent_from_all_logs(client, app):
    """§14.6：token、client_secret 不入任何日志（trace/audit/运行日志全文件扫描）；
    授权 code 亦不得入日志（日志只记 path 不含 query）。"""
    mid, state, code = await _setup_and_bind(client)
    await _complete_callback(client, mid, state, code)
    async with app.state.sessionmaker() as session:
        cred_row = (await session.execute(
            select(OAuthCredential).where(
                OAuthCredential.mapping_id == mid))).scalar_one()
    access = decrypt_text(cred_row.access_token, MASTER)
    refresh = decrypt_text(cred_row.refresh_token, MASTER)
    secrets_scan = (access, refresh, CLIENT_BODY["client_secret"], code, state)
    for path in glob.glob("logs-test/**/*.log*", recursive=True):
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        for secret in secrets_scan:
            assert secret not in text, f"{path} 泄漏敏感值（{secret[:6]}…）"


async def test_non_admin_user_can_authorize_admin_mapping(client):
    """§14.2 正向面：public 映射任意有效用户可发起授权绑定（admin 仅限创建/改删）。"""
    mid = (await client.post("/api/v1/mappings", json={
        "type": "http", "visibility": "public", "auth_mode": "oauth",
        "upstream_url": "http://10.0.0.5/api/v1", "headers": {}}, headers=ADMIN)).json()["mapping_id"]
    await client.put(f"/api/v1/builtin-mappings/{mid}/client", json=CLIENT_BODY,
                     headers=ADMIN)
    resp = await client.post(f"/api/v1/builtin-mappings/{mid}/authorize",
                             json={"front_redirect": FRONT}, headers=U888)
    assert resp.status_code == 200
    assert "authorization_url" in resp.json()


async def test_refresh_lock_release_owner_checked(client, app):
    """终审遗留 1：刷新锁释放属主校验（Lua compare-and-delete）——非属主删除被拒
    （防持锁超 30s TTL 后误删继任者新锁 → 并发刷新失防），属主删除成功；
    Redis 3.0 的 EVAL 可用性由本用例钉住。"""
    lock = refresh_lock_key("m-sec", 888)
    await app.state.redis.set(lock, "req-holder-a", ex=30)
    assert await release_refresh_lock(app.state.redis, "m-sec", 888,
                                      "req-holder-b") is False   # 非属主：拒绝
    assert await app.state.redis.get(lock) == b"req-holder-a"    # 锁未被误删
    assert await release_refresh_lock(app.state.redis, "m-sec", 888,
                                      "req-holder-a") is True    # 属主：释放
    assert await app.state.redis.get(lock) is None
    # 幂等：锁不存在时属主再释放 → False（0），不报错
    assert await release_refresh_lock(app.state.redis, "m-sec", 888,
                                      "req-holder-a") is False
