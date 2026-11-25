"""DCR 全流程（真实 TCP 9910 → 9904 AS）：首次 authorize 无 client 行 → discovery
（protected-resource → authorization-server 两步）→ RFC 7591 动态注册 → source=dcr
落库 → 授权绑定 → 按用户注入调用（http 形态经 9904 RS echo 验证）→ 解绑（revoke
连带）→ metrics ap_oauth_actions_total 计数。
（DCR 失败 → 502 OAUTH_CLIENT_SETUP_FAILED 用例在 test_oauth_binding_flow.py 迁移版。）"""
import re

import httpx
from sqlalchemy import select

from agent_proxy.models import OAuthCredential, OAuthClient
from agent_proxy.oauth.credential import decrypt_text, invalidate_credential
from tests.integration.mock_oauth_as import as_state
from tests.utils import make_token

PROXY = "http://127.0.0.1:9910"
AS = "http://127.0.0.1:9904"
FRONT = "http://127.0.0.1:9910/console"
MASTER = "test-master-key"
ADMIN = {"Authorization": f"Bearer {make_token(100, 'admin')}"}
U888 = {"Authorization": f"Bearer {make_token(888)}"}
U999 = {"Authorization": f"Bearer {make_token(999)}"}
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)

MANUAL_CLIENT = {"client_id": "manual-cl", "client_secret": "manual-cs-123456",
                 "token_auth": "client_secret_post",
                 "authorize_url": f"{AS}/oauth/authorize",
                 "token_url": f"{AS}/oauth/token", "scopes": "read"}


async def _setup_manual_http():
    """手动模式 preset client（manual 行无 revoke 端点配置列 → 解绑仅删本地）。"""
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json={
            "type": "http", "visibility": "public", "auth_mode": "oauth",
            "upstream_url": f"{AS}/api", "headers": {}}, headers=ADMIN)
        assert resp.status_code == 201, resp.text
        mid = resp.json()["mapping_id"]
        put = await c.put(f"{PROXY}/api/v1/builtin-mappings/{mid}/client",
                          json=MANUAL_CLIENT, headers=ADMIN)
    assert put.status_code == 200, put.text
    return mid


async def _create_oauth_http():
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json={
            "type": "http", "visibility": "public", "auth_mode": "oauth",
            "upstream_url": f"{AS}/api", "headers": {}}, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()["mapping_id"]


async def _authorize(mid, user_headers=U888):
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        resp = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/authorize",
                            json={"front_redirect": FRONT}, headers=user_headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["authorization_url"]


async def _complete_binding(authz_url):
    """浏览器角色：真实 TCP 走 9904 authorize → 302 → 真实 TCP 打到 9910 回调。"""
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as browser:
        redir = await browser.get(authz_url, follow_redirects=False)
        assert redir.status_code == 302, redir.text
        callback_url = redir.headers["location"]
        cb = await browser.get(callback_url, follow_redirects=False)
    return cb


async def _proxy_call(mid, path, headers):
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        return await c.get(f"{PROXY}/p/{mid}/{path}", headers=headers)


async def _cred_token(app, mid, user_id=888) -> str:
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.user_id == user_id))).scalar_one()
    return decrypt_text(row.access_token, MASTER)


async def test_dcr_registers_on_first_authorize_and_binds(app):
    as_state["registrations"].clear()
    mid = await _create_oauth_http()
    # 无 client 行 + 上游 9904 有 well-known → DCR 成功
    authz_url = await _authorize(mid)
    assert len(as_state["registrations"]) == 1
    reg = as_state["registrations"][-1]
    assert reg["redirect_uris"] == [f"{PROXY}/oauth/callback/{mid}"]   # 精确单一值
    assert set(reg["grant_types"]) == {"authorization_code", "refresh_token"}
    assert reg["token_endpoint_auth_method"] == "client_secret_post"
    # 落库 source=dcr（§5.3：authorize_url/token_url 留空）
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthClient).where(
            OAuthClient.mapping_id == mid))).scalar_one()
    assert row.source == "dcr" and row.authorize_url is None and row.token_url is None
    assert row.client_id.startswith("cl-")
    assert row.client_secret.startswith("gAAAA")
    # 完成 binding
    cb = await _complete_binding(authz_url)
    assert cb.status_code == 302
    assert cb.headers["location"] == f"{FRONT}?binding=success"
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        b = await c.get(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "bound"


async def test_dcr_injected_call_reaches_upstream_with_own_token(app):
    mid = await _create_oauth_http()
    cb = await _complete_binding(await _authorize(mid))
    assert cb.status_code == 302
    token = await _cred_token(app, mid)
    r = await _proxy_call(mid, "orders?id=1", U888)
    assert r.status_code == 200
    body = r.json()
    # 出站 Authorization: Bearer <该用户 access_token>（§14.5「仅还原注册者 header」唯一例外）
    assert body["headers"]["authorization"] == f"Bearer {token}"
    assert not any(v.startswith("stub.") for v in body["headers"].values())  # JWT 不透传
    # 另一用户未绑定 → 401 OAUTH_BINDING_REQUIRED（任意有效用户可调 public，但须先绑定）
    r999 = await _proxy_call(mid, "orders", U999)
    assert r999.status_code == 401
    assert r999.json()["code"] == "OAUTH_BINDING_REQUIRED"
    assert f"/builtin-mappings/{mid}/authorize" in r999.json()["message"]  # body 附授权引导


async def test_unbind_revokes_and_401_afterwards(app):
    mid = await _create_oauth_http()
    await _complete_binding(await _authorize(mid))
    token = await _cred_token(app, mid)
    # 评审修复（Important 3）：refresh token 同批 revoke——本地删除后 RT 明文已
    # 无处可寻，这是吊销它的最后机会
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.user_id == 888))).scalar_one()
    refresh = decrypt_text(row.refresh_token, MASTER)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.delete(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert r.status_code == 204
    # 本地凭证删除 + revoke best-effort 到达 AS（dcr 客户端经 discovery 拿 revocation_endpoint）
    async with app.state.sessionmaker() as session:
        rows = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid))).scalars().all()
    assert rows == []
    assert any(x["token"] == token and x["hint"] == "access_token"
               for x in as_state["revocations"])
    assert any(x["token"] == refresh and x["hint"] == "refresh_token"
               for x in as_state["revocations"])
    # refresh token 已在 AS 侧作废：拿 RT（DCR 客户端凭证）换新 → invalid_grant
    async with app.state.sessionmaker() as session:
        cl = (await session.execute(select(OAuthClient).where(
            OAuthClient.mapping_id == mid))).scalar_one()
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        rt = await c.post(f"{AS}/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": refresh,
            "client_id": cl.client_id,
            "client_secret": decrypt_text(cl.client_secret, MASTER)})
    assert rt.status_code == 400 and rt.json()["error"] == "invalid_grant"
    # 解绑后调用 → 401；binding 状态回 unbound
    r = await _proxy_call(mid, "orders", U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        b = await c.get(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "unbound"
    # 再解绑 → 404
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r2 = await c.delete(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert r2.status_code == 404


async def test_oauth_metrics_bind_unbind_counters(app):
    mid = await _create_oauth_http()
    await _complete_binding(await _authorize(mid))
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        await c.delete(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
        m = await c.get(f"{PROXY}/metrics")
    text = m.text
    bind = re.search(r'^ap_oauth_actions_total\{action="bind"\} ([0-9.]+)$', text, re.M)
    unbind = re.search(r'^ap_oauth_actions_total\{action="unbind"\} ([0-9.]+)$', text, re.M)
    assert bind and float(bind.group(1)) >= 1.0
    assert unbind and float(unbind.group(1)) >= 1.0


async def test_unbind_manual_local_delete_only_no_revoke(app):
    """终审遗留 6：manual 模式解绑——manual 行无 revoke 端点配置列（§14.4
    「提供方支持时」）→ 仅删本地凭证返回 204，不发任何 revoke；解绑后调用 401。"""
    mid = await _setup_manual_http()
    await _complete_binding(await _authorize(mid))
    revocations_before = len(as_state["revocations"])
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.delete(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding",
                           headers=U888)
    assert r.status_code == 204
    async with app.state.sessionmaker() as session:
        rows = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid))).scalars().all()
    assert rows == []                                     # 本地凭证已删
    assert len(as_state["revocations"]) == revocations_before   # 未发 revoke
    r2 = await _proxy_call(mid, "orders", U888)
    assert r2.status_code == 401 and r2.json()["code"] == "OAUTH_BINDING_REQUIRED"
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        b = await c.get(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "unbound"


async def test_unbind_corrupt_ciphertext_204_reauth_guidance(app):
    """终审遗留 4：解绑前解密失败（密文损坏 / MASTER_KEY 变更）→ 删本地坏行 +
    204 引导重新授权，绝不 500 死局；revoke 无从谈起（明文已不可得）。"""
    mid = await _create_oauth_http()
    await _complete_binding(await _authorize(mid))
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.user_id == 888))).scalar_one()
        row.access_token = "corrupted-not-fernet"
        await session.commit()
    await invalidate_credential(app.state.redis, mid, 888)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.delete(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding",
                           headers=U888)
    assert r.status_code == 204                           # 非 500（恢复路径）
    async with app.state.sessionmaker() as session:
        rows = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid))).scalars().all()
    assert rows == []                                     # 坏行已本地删除
    assert as_state["revocations"] == []                  # 明文不可得，未发 revoke
    r2 = await _proxy_call(mid, "orders", U888)
    assert r2.status_code == 401 and r2.json()["code"] == "OAUTH_BINDING_REQUIRED"
