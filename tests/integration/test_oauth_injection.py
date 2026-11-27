"""按用户注入端到端（真实 TCP 9910）：三形态 token 到达上游断言、未绑定/invalid
401、过期自动刷新、并发刷新单飞（Redis 锁）、刷新失败→invalid→重新授权恢复、
builtin test 本人凭证与失效提示（§14.5 / §6.6）；终审遗留 6 补口：无轮换刷新
分支、等待超时分支、manual basic 过期刷新、builtin test http 形态。"""
import asyncio
import re
from datetime import datetime, timedelta, timezone
from sqlalchemy import select

import httpx

from app.core.models import OAuthClient, OAuthCredential
from app.services.oauth import credential as cred_mod
from app.services.oauth.credential import (invalidate_credential,
                                refresh_credential, refresh_lock_key)
from app.services.oauth.crypto import decrypt_text, encrypt_text
from app.services.mapping_service import load_mapping
from mocks.mcp_sse import mock_state
from mocks.mcp_streamable import secure_state, streamable_state
from mocks.oauth_as import as_state
from tests.utils import make_token

PROXY = "http://127.0.0.1:9910"
AS = "http://127.0.0.1:9904"
FRONT = "http://127.0.0.1:9910/console"
MASTER = "test-master-key"
ADMIN = {"Authorization": f"Bearer {make_token(100, 'admin')}"}
U888 = {"Authorization": f"Bearer {make_token(888)}"}
U999 = {"Authorization": f"Bearer {make_token(999)}"}
TCP_TIMEOUT = httpx.Timeout(connect=5, read=10, write=10, pool=5)

CLIENT_BODY = {"client_id": "manual-cl", "client_secret": "manual-cs-123456",
               "token_auth": "client_secret_post",
               "authorize_url": f"{AS}/oauth/authorize",
               "token_url": f"{AS}/oauth/token", "scopes": "read"}


async def _create_oauth(upstream, type_="http"):
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        resp = await c.post(f"{PROXY}/api/v1/mappings", json={
            "type": type_, "visibility": "public", "auth_mode": "oauth",
            "upstream_url": upstream, "headers": {}}, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()["mapping_id"]


async def _setup_manual(upstream, type_="http", token_auth="client_secret_post"):
    mid = await _create_oauth(upstream, type_)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        resp = await c.put(f"{PROXY}/api/v1/builtin-mappings/{mid}/client",
                           json={**CLIENT_BODY, "token_auth": token_auth}, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return mid


async def _bind(mid, user_headers=U888, front=FRONT):
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/authorize",
                         json={"front_redirect": front}, headers=user_headers)
        assert r.status_code == 200, r.text
        redir = await c.get(r.json()["authorization_url"], follow_redirects=False)
        assert redir.status_code == 302, redir.text
        cb = await c.get(redir.headers["location"], follow_redirects=False)
    assert cb.status_code == 302, cb.text
    assert "binding=success" in cb.headers["location"]


async def _cred_row(app, mid, user_id=888):
    async with app.state.sessionmaker() as session:
        return (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.user_id == user_id))).scalar_one()


async def _cred_token(app, mid, user_id=888) -> str:
    return decrypt_text((await _cred_row(app, mid, user_id)).access_token, MASTER)


async def _set_cred_token_ct(app, mid, user_id, plaintext):
    """直写凭证（模拟 upstream 侧已吊销的 stale token）：密文形态合法、上游不认。
    （落地修正：同一 session 内 SELECT——原稿经 _cred_row 另开 session 取行，
    返回即 detach，本 session commit 无脏对象，stale 直写静默丢失。）"""
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.user_id == user_id))).scalar_one()
        row.access_token = encrypt_text(plaintext, MASTER)
        await session.commit()
    await invalidate_credential(app.state.redis, mid, user_id)


async def test_injection_http_form_token_reaches_upstream(app):
    mid = await _create_oauth(f"{AS}/api")               # DCR 形态（http）
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders?id=7", headers=U888)
    assert r.status_code == 200
    assert r.json()["headers"]["authorization"] == f"Bearer {token}"


async def test_oauth_forced_credential_replaces_caller_ticket(app):
    """设计 v4 forced 语义钉住（单头模式）：调用方的 Authorization: Bearer <票据>
    只用于代理鉴权；oauth 映射出站恒为注入的本人托管凭证（forced 最高优先，
    压过调用方票据与存储头——§14.1 凭证托管不被绕过）。"""
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders?id=7", headers=U888)
    assert r.status_code == 200
    sent = r.json()["headers"]
    assert sent["authorization"] == f"Bearer {token}"    # 托管凭证胜出
    assert "stub." not in r.text                         # 调用方代理票据绝不到上游


async def test_oauth_forced_credential_replaces_caller_streamable_form(app):
    mid = await _setup_manual("http://127.0.0.1:9903/mcp", type_="mcp")
    await _bind(mid)
    token = await _cred_token(app, mid)
    streamable_state["received"].clear()
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"}}, headers=U888)
    assert r.status_code == 200
    rec = streamable_state["received"][-1]
    assert rec["headers"]["authorization"] == f"Bearer {token}"
    assert not any(v.startswith("stub.") for v in rec["headers"].values())


async def test_injection_streamable_form_token_reaches_upstream(app):
    streamable_state["received"].clear()
    mid = await _setup_manual("http://127.0.0.1:9903/mcp", type_="mcp")
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/p/{mid}/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"}}, headers=U888)
    assert r.status_code == 200
    rec = streamable_state["received"][-1]
    assert rec["headers"]["authorization"] == f"Bearer {token}"   # 本人 token 到上游
    assert not any(v.startswith("stub.") for v in rec["headers"].values())  # JWT 不透传


async def test_injection_sse_form_token_reaches_upstream(app):
    mid = await _setup_manual("http://127.0.0.1:9902/sse", type_="mcp")
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        async with c.stream("GET", f"{PROXY}/p/{mid}/sse", headers=U888) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            saw_endpoint = False
            async for line in resp.aiter_lines():
                if line.startswith("data:") and "/messages" in line:
                    saw_endpoint = True                   # endpoint 改写不受注入影响
                    break
    assert saw_endpoint
    assert mock_state["last_sse_headers"]["authorization"] == f"Bearer {token}"


async def test_unbound_call_401_with_authorize_guidance():
    mid = await _create_oauth(f"{AS}/api")
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U999)
    assert r.status_code == 401
    body = r.json()
    assert body["code"] == "OAUTH_BINDING_REQUIRED"
    assert f"/builtin-mappings/{mid}/authorize" in body["message"]  # body 附授权引导（§10）


async def test_invalid_status_call_401(app):
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.user_id == 888))).scalar_one()
        row.status = "invalid"
        await session.commit()
    await invalidate_credential(app.state.redis, mid, 888)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"


async def test_expired_refresh_single(app):
    """§14.5：expires_at - 60s 内即刷新（脚本化 expires_in=2 越线后首个请求触发；
    刷新签发的新 token 改回 3600，避免 60s skew 内二次刷新干扰计数）。"""
    as_state["expires_in"] = 2
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    token1 = await _cred_token(app, mid)
    as_state["expires_in"] = 3600                         # 刷新签发的新 token 走正常有效期
    await asyncio.sleep(2.3)                              # 越过过期线（skew 60s 内）
    events_before = len(as_state["refresh_events"])
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r1 = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
        assert r1.status_code == 200
        assert len(as_state["refresh_events"]) == events_before + 1
        token2 = await _cred_token(app, mid)
        assert token2 != token1                           # 刷新后落库新 token
        r2 = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r2.status_code == 200                          # 新 token 有效期内不再刷新
    assert len(as_state["refresh_events"]) == events_before + 1
    assert r2.json()["headers"]["authorization"] == f"Bearer {token2}"


async def test_concurrent_refresh_lock_single_flight(app):
    """并发刷新锁（§14.5）：6 并发请求越过过期线 → 仅 1 次 refresh（其余轮询等待
    新 token），全部 200 且带同一新 token。refresh_sleep=0.8 拉宽竞态窗口。"""
    as_state["refresh_sleep"] = 0.8
    as_state["expires_in"] = 2
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    token1 = await _cred_token(app, mid)
    as_state["expires_in"] = 3600                         # 刷新签发的新 token 走正常有效期
    await asyncio.sleep(2.3)
    before = len(as_state["refresh_events"])
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        rs = await asyncio.gather(*[c.get(f"{PROXY}/p/{mid}/orders?i={i}", headers=U888)
                                    for i in range(6)])
    assert all(r.status_code == 200 for r in rs), [r.status_code for r in rs]
    assert len(as_state["refresh_events"]) == before + 1  # 锁防并发：仅一次刷新
    token2 = await _cred_token(app, mid)
    assert token2 != token1
    for r in rs:
        assert r.json()["headers"]["authorization"] == f"Bearer {token2}"
    as_state["refresh_sleep"] = 0.0


async def test_refresh_failure_marks_invalid_and_reauth_recovers(app):
    as_state["fail_refresh"] = True
    as_state["expires_in"] = 2
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    as_state["expires_in"] = 3600                         # 恢复后签发的 token 走正常有效期
    await asyncio.sleep(2.3)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"
    row = await _cred_row(app, mid)
    assert row.status == "invalid"                        # 刷新失败 → invalid（§14.4）
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        b = await c.get(f"{PROXY}/api/v1/builtin-mappings/{mid}/binding", headers=U888)
    assert b.json()["binding"] == "invalid"               # 状态机回告，页面引导重新授权
    # 重新授权恢复（upsert 复位 active）
    as_state["fail_refresh"] = False
    as_state["expires_in"] = 3600
    await _bind(mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r2 = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r2.status_code == 200


async def test_refresh_transient_5xx_keeps_credential_and_retries(app):
    """评审修复（Important 2）：瞬时失败（token 端点 503/网络/discovery 抖动）不
    破坏凭证——保持 active，本请求 401，下一请求原样重试刷新成功（scope 保留）。"""
    as_state["expires_in"] = 2
    mid = await _setup_manual(f"{AS}/api")                # 手动 client（scopes=read）→ 绑定凭证带 scope
    await _bind(mid)
    as_state["expires_in"] = 3600
    await asyncio.sleep(2.3)
    as_state["refresh_status"] = 503
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"
    row = await _cred_row(app, mid)
    assert row.status == "active"                         # 瞬时失败不标 invalid
    assert len(as_state["refresh_events"]) == 0           # 未产生刷新事件
    # /metrics 级断言（评审 Minor 5）：瞬时失败独立 transient 标签计数
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        m = await c.get(f"{PROXY}/metrics")
    transient = re.search(r'^ap_oauth_actions_total\{action="transient"\} ([0-9.]+)$',
                          m.text, re.M)
    assert transient and float(transient.group(1)) >= 1.0
    as_state["refresh_status"] = 0                        # AS 恢复
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r2 = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r2.status_code == 200                          # 下一请求重试刷新成功
    assert len(as_state["refresh_events"]) == 1
    row = await _cred_row(app, mid)
    assert row.status == "active" and row.scope == "read"  # scope 保留（RFC 6749 §6）


async def test_refresh_malformed_body_keeps_credential(app):
    """评审修复（Minor c）：token 端点 200 但响应非 JSON object（如数组/字符串）
    → 本请求 401，凭证保持原状——绝不 500，也不破坏性标 invalid。"""
    as_state["expires_in"] = 2
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    as_state["expires_in"] = 3600
    await asyncio.sleep(2.3)
    as_state["refresh_payload"] = ["unexpected-shape"]
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"
    row = await _cred_row(app, mid)
    assert row.status == "active"


async def test_refresh_oversize_token_transient_keeps_credential(app):
    """评审 Important 1/2（精修批）：刷新落库遇 AS 下发超长 token（密文超
    VARCHAR(4096) 列上限 → DataError）→ 按瞬时失败分级（凭证原状保留、不误标
    invalid），本请求 401 绝不 500；下轮 AS 恢复正常载荷即自愈。"""
    as_state["expires_in"] = 2
    mid = await _setup_manual(f"{AS}/api")
    await _bind(mid)
    as_state["expires_in"] = 3600
    await asyncio.sleep(2.3)
    original = await _cred_token(app, mid)                # 原明文（解密面）
    as_state["oversize_token"] = True                     # 刷新签发超大 token
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"
    row = await _cred_row(app, mid)
    assert row.status == "active"                         # 原状保留（不误标 invalid）
    assert decrypt_text(row.access_token, MASTER) == original
    as_state["oversize_token"] = False                    # AS 恢复 → 下轮自愈
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r2 = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r2.status_code == 200


async def test_unreadable_ciphertext_401_reauth_guidance(app):
    """评审修复（Minor c）：凭证密文不可解（MASTER_KEY 变更/行损坏）→ 401
    OAUTH_BINDING_REQUIRED 重授权引导——绝不 500 INTERNAL_ERROR。"""
    mid = await _create_oauth(f"{AS}/api")
    await _bind(mid)
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.user_id == 888))).scalar_one()
        row.access_token = "not-a-fernet-payload"
        await session.commit()
    await invalidate_credential(app.state.redis, mid, 888)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"


async def test_builtin_test_bound_user_uses_own_credential(app):
    """§6.6：已绑定用户 test = 本人凭证执行对应 mcp 验证；uk 每用户一份互不串用。"""
    mid = await _setup_manual("http://127.0.0.1:9903/mcp-secure", type_="mcp")
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=U888)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["status_code"] == 200   # 有效凭证 → initialize 通过
    assert secure_state["received"][-1]["headers"]["authorization"] == f"Bearer {token}"
    await _bind(mid, U999)                                # 第二用户独立绑定
    token999 = await _cred_token(app, mid, 999)
    assert token999 != token
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r999 = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=U999)
    assert r999.json()["ok"] is True
    assert secure_state["received"][-1]["headers"]["authorization"] == f"Bearer {token999}"


async def test_builtin_test_stale_token_hints_reauth(app):
    """§6.6：凭证失效提示重新授权——stale token 被 /mcp-secure 拒绝（401 短路，
    不回落，M4 定稿），detail 追加「重新授权」提示。"""
    mid = await _setup_manual("http://127.0.0.1:9903/mcp-secure", type_="mcp")
    await _bind(mid)
    await _set_cred_token_ct(app, mid, 888, "at-stale-revoked-000000")
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=U888)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and body["status_code"] == 401
    assert body["detail"].startswith("上游拒绝")           # 非 2xx 不回落（M4 语义）
    assert "重新授权" in body["detail"]


async def test_builtin_test_admin_static_no_injection():
    """admin 测静态配置（§6.5）：不注入本人凭证（secure 面 0 访问）。"""
    mid = await _setup_manual("http://127.0.0.1:9903/mcp", type_="mcp")
    secure_state["received"].clear()
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=ADMIN)
    assert r.status_code == 200 and r.json()["ok"] is True
    assert secure_state["received"] == []


async def test_builtin_test_unbound_user_401():
    mid = await _setup_manual("http://127.0.0.1:9903/mcp-secure", type_="mcp")
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=U999)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"


async def test_refresh_corrupt_client_secret_401_not_500(app):
    """评审修复（Critical）：manual 客户端 client_secret 密文不可解（MASTER_KEY
    变更 / 行损坏）+ 凭证已过期（刷新分支不先解 access）→ 401 引导重新授权，
    绝不 500 穿透；凭证行保持原状（配置恢复后仍可用）。"""
    mid = await _setup_manual(f"{AS}/api")
    await _bind(mid)
    async with app.state.sessionmaker() as session:
        cl = (await session.execute(select(OAuthClient).where(
            OAuthClient.mapping_id == mid))).scalar_one()
        cl.client_secret = "corrupted-client-secret-not-fernet"
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.user_id == 888))).scalar_one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=120)
        await session.commit()
    await invalidate_credential(app.state.redis, mid, 888)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 401 and r.json()["code"] == "OAUTH_BINDING_REQUIRED"
    row = await _cred_row(app, mid)
    assert row.status == "active"                         # 凭证未被破坏（不清行）


async def test_refresh_without_rotation_keeps_original_refresh_token(app):
    """终审遗留 6：AS 刷新响应不含 refresh_token（未轮换形态，RFC 6749 rt 可选
    返回）→ 新 access 落库、原 refresh 密文原样保留——缺省不得清空（清空即永久
    失去续期能力）。"""
    as_state["expires_in"] = 2
    mid = await _setup_manual(f"{AS}/api")
    await _bind(mid)
    original_rt_ct = (await _cred_row(app, mid)).refresh_token
    assert original_rt_ct
    as_state["expires_in"] = 3600                         # 刷新响应走正常有效期
    await asyncio.sleep(2.3)
    as_state["refresh_payload"] = {"access_token": "at-no-rotation-000001",
                                   "token_type": "Bearer", "expires_in": 3600}
    try:
        async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
            r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
        assert r.status_code == 200
        assert r.json()["headers"]["authorization"] == "Bearer at-no-rotation-000001"
        row = await _cred_row(app, mid)
        assert decrypt_text(row.access_token, MASTER) == "at-no-rotation-000001"
        assert row.refresh_token == original_rt_ct        # 未轮换：保留原密文
    finally:
        as_state["refresh_payload"] = None


async def test_refresh_wait_timeout_returns_none_then_recovers(app, monkeypatch):
    """终审遗留 6（等待超时分支）：锁被他人持有且轮询超过 REFRESH_WAIT_SECONDS
    → None → 401 语义；凭证保持 active 未破坏，锁释放后下一请求自行刷新成功。
    （进程内直调 refresh_credential：REFRESH_WAIT_SECONDS 是 9910 服务进程的
    模块全局量，TCP 侧 monkeypatch 不可达，等待上限须进程内收缩。）"""
    as_state["expires_in"] = 3600
    mid = await _setup_manual(f"{AS}/api")
    await _bind(mid)
    # 直写过期（免 2.3s 真实等待）：expires_at 拨到 120s 前（skew 60s 内必判过期）
    async with app.state.sessionmaker() as session:
        row = (await session.execute(select(OAuthCredential).where(
            OAuthCredential.mapping_id == mid,
            OAuthCredential.user_id == 888))).scalar_one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=120)
        await session.commit()
    await invalidate_credential(app.state.redis, mid, 888)
    async with app.state.sessionmaker() as session:
        mapping_data = await load_mapping(session, app.state.redis, mid, 60, MASTER)
    monkeypatch.setattr(cred_mod, "REFRESH_WAIT_SECONDS", 0.3)
    lock = refresh_lock_key(mid, 888)
    await app.state.redis.set(lock, "req-other-holder", ex=30)
    async with app.state.sessionmaker() as session:
        got = await refresh_credential(session, app.state.redis, app.state,
                                       mapping_data, 888, MASTER, "req-wait")
    assert got is None                                    # 等待超时 → None（→401）
    row = await _cred_row(app, mid)
    assert row.status == "active"                         # 凭证未被等待路径破坏
    assert len(as_state["refresh_events"]) == 0           # 持锁者从未刷新
    await app.state.redis.delete(lock)
    async with app.state.sessionmaker() as session:
        token = await refresh_credential(session, app.state.redis, app.state,
                                         mapping_data, 888, MASTER, "req-go")
    assert token and token.startswith("at-")              # 锁释放后正常刷新
    assert len(as_state["refresh_events"]) == 1


async def test_manual_basic_auth_expired_refresh_e2e(app):
    """终审遗留 6：manual 客户端（client_secret_basic）过期刷新端到端——refresh
    请求过 AS Basic 认证门（refresh_events.client_auth=basic 记录面），新 token
    落库并到上游。"""
    as_state["expires_in"] = 2
    mid = await _setup_manual(f"{AS}/api", token_auth="client_secret_basic")
    await _bind(mid)
    token1 = await _cred_token(app, mid)
    as_state["expires_in"] = 3600
    await asyncio.sleep(2.3)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.get(f"{PROXY}/p/{mid}/orders", headers=U888)
    assert r.status_code == 200
    assert len(as_state["refresh_events"]) == 1
    assert as_state["refresh_events"][-1]["client_id"] == "manual-cl"
    assert as_state["refresh_events"][-1]["client_auth"] == "basic"   # Basic 认证门
    token2 = await _cred_token(app, mid)
    assert token2 != token1                               # 新 token 落库
    assert r.json()["headers"]["authorization"] == f"Bearer {token2}"


async def test_builtin_test_bound_user_http_form_uses_own_credential(app):
    """终审遗留 6：§6.6 http 形态——已绑定用户 test 以本人凭证执行 http 探测
    （默认 GET 任意响应即可达）；本人 token 到上游（SSE 上游 last_sse_headers
    断言面：http 映射指向 9902 /sse，探测 GET 即建连一次）。"""
    mock_state["last_sse_headers"] = {}
    mid = await _setup_manual("http://127.0.0.1:9902/sse")
    await _bind(mid)
    token = await _cred_token(app, mid)
    async with httpx.AsyncClient(timeout=TCP_TIMEOUT) as c:
        r = await c.post(f"{PROXY}/api/v1/builtin-mappings/{mid}/test", headers=U888)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["status_code"] == 200
    assert mock_state["last_sse_headers"]["authorization"] == f"Bearer {token}"
