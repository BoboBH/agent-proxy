"""OAuth 凭证存取层集成（app 夹具 + 真实 MySQL/Redis，设计 §5.3）：
加密 upsert（uk mapping_id+user_id）/ cred 缓存 cache-aside（密文形态）/ 失效 /
invalid 标记 / 删除 / 并发 upsert 竞态。"""
import json

import pytest
from sqlalchemy import func, select

from agent_proxy.models import OAuthCredential
from agent_proxy.oauth.credential import (cred_cache_key, delete_credential,
                                          decrypt_text, encrypt_text,
                                          invalidate_credential, load_credential,
                                          mark_credential_invalid, save_credential)

MASTER = "test-master-key"
MID = "m1m2m3m4m5m6"
UID = 888


async def _save(app, user_id=UID, expires=None, access="at-plain-123456",
                refresh="rt-plain-123456", mapping_id=MID):
    async with app.state.sessionmaker() as session:
        await save_credential(session, app.state.redis, mapping_id, user_id,
                              access_token_ct=encrypt_text(access, MASTER),
                              refresh_token_ct=(encrypt_text(refresh, MASTER)
                                                if refresh else None),
                              expires_at=expires, scope="read", master_key=MASTER)


async def _raw_row(app, user_id=UID, mapping_id=MID):
    async with app.state.sessionmaker() as session:
        return (await session.execute(
            select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                          OAuthCredential.user_id == user_id))).scalar_one()


async def test_save_stores_ciphertext_and_load_decrypts(app):
    await _save(app)
    row = await _raw_row(app)
    assert row.access_token.startswith("gAAAA")        # 落库密文（§14.6 强制加密）
    assert "at-plain-123456" not in row.access_token
    assert row.refresh_token.startswith("gAAAA")
    async with app.state.sessionmaker() as session:
        cred = await load_credential(session, app.state.redis, MID, UID)
    assert cred["status"] == "active" and cred["scope"] == "read"
    assert cred["access_token"].startswith("gAAAA")    # 缓存同密文形态，读取方负责解密


async def test_load_cache_aside_second_read_survives_db_row_loss(app):
    await _save(app)
    async with app.state.sessionmaker() as session:
        assert await load_credential(session, app.state.redis, MID, UID) is not None
    # 直接删 DB 行：第二次读取仍命中 Redis 缓存（cache-aside 生效面）
    async with app.state.sessionmaker() as session:
        row = await _raw_row(app)
        await session.delete(row)
        await session.commit()
    async with app.state.sessionmaker() as session:
        cached = await load_credential(session, app.state.redis, MID, UID)
    assert cached is not None and cached["scope"] == "read"


async def test_invalidate_forces_db_reload(app):
    await _save(app)
    async with app.state.sessionmaker() as session:
        await load_credential(session, app.state.redis, MID, UID)
    await invalidate_credential(app.state.redis, MID, UID)
    async with app.state.sessionmaker() as session:    # 缓存已删 → 回源 DB
        assert await load_credential(session, app.state.redis, MID, UID) is not None


async def test_upsert_overwrites_and_resets_invalid(app):
    await _save(app)
    async with app.state.sessionmaker() as session:
        await mark_credential_invalid(session, app.state.redis, MID, UID)
    row = await _raw_row(app)
    assert row.status == "invalid"
    await _save(app, access="at-second-token-123456")  # 重新授权 = upsert 覆盖
    rows = await _raw_row(app)
    assert rows.status == "active"
    assert rows.access_token.startswith("gAAAA") and "at-second-token" not in rows.access_token


async def test_delete_removes_row_and_cache(app):
    await _save(app)
    async with app.state.sessionmaker() as session:
        assert await delete_credential(session, app.state.redis, MID, UID) is True
        assert await load_credential(session, app.state.redis, MID, UID) is None
        assert await delete_credential(session, app.state.redis, MID, UID) is False


async def test_save_with_null_refresh_and_expiry(app):
    await _save(app, refresh=None)
    row = await _raw_row(app)
    assert row.refresh_token is None and row.expires_at is None


async def test_save_credential_concurrent_upsert_race_resolves_as_update(app):
    """并发授权同 (mapping_id, user_id) 竞态：A 请求先在其事务里做一次一致性读固定
    REPEATABLE READ 快照（此刻表内无行），B 请求并发完成 INSERT 并提交；A 随后
    save 时 SELECT 仍看不见 B 的行（快照读）→ 走 INSERT 撞 uk → 必须捕获
    IntegrityError 按 uk 重试为 UPDATE（真原子 upsert），而非 IntegrityError→500。"""
    access_a = "at-from-request-a-123456"
    async with app.state.sessionmaker() as sa:
        # A：固定一致性读快照（空表）——事务保持打开直至 save 内部 commit
        assert (await sa.execute(
            select(func.count()).select_from(OAuthCredential))).scalar_one() == 0
        # B：并发请求同 uk 插入并提交
        async with app.state.sessionmaker() as sb:
            await save_credential(sb, app.state.redis, MID, 901,
                                  access_token_ct=encrypt_text("at-from-b-123456", MASTER),
                                  refresh_token_ct=None, expires_at=None,
                                  scope="read", master_key=MASTER)
        # A：此刻才 save——快照里无行 → INSERT → 撞 uk → 回滚重试为 UPDATE
        await save_credential(sa, app.state.redis, MID, 901,
                              access_token_ct=encrypt_text(access_a, MASTER),
                              refresh_token_ct=None, expires_at=None,
                              scope="read", master_key=MASTER)
    row = await _raw_row(app, user_id=901)        # 恰好一行（uk 保证），A 的值胜出
    assert decrypt_text(row.access_token, MASTER) == access_a
    assert row.status == "active"


async def test_delete_false_path_still_invalidates_cache(app):
    """重复解绑（行已不在）同样失效 cred 缓存：过期缓存比消失的行更危险
    （缓存残留 → 已解绑用户仍被注入旧 token）。"""
    await _save(app)
    async with app.state.sessionmaker() as session:
        assert await load_credential(session, app.state.redis, MID, UID) is not None
    async with app.state.sessionmaker() as session:
        assert await delete_credential(session, app.state.redis, MID, UID) is True
    # 模拟竞态窗口：删除后等待方把旧行写回缓存
    await app.state.redis.set(cred_cache_key(MID, UID),
                              json.dumps({"access_token": "gAAAA-stale",
                                          "refresh_token": None, "expires_at": None,
                                          "scope": "read", "status": "active"}))
    async with app.state.sessionmaker() as session:
        assert await delete_credential(session, app.state.redis, MID, UID) is False
    assert await app.state.redis.get(cred_cache_key(MID, UID)) is None


async def test_credential_column_length_limit_rejects_oversize_write(app):
    """评审 Important 2（精修批，schema 边界）：加密列 VARCHAR 定长由 DB 兜底强制
    ——超限密文直写 → DataError（MySQL 1406 fail-fast，严格模式默认开启），
    不存在静默截断；入口层 schemas 上限 256/列 512、token 列 4096 的组合以此收口。"""
    from sqlalchemy import text as sql_text
    from sqlalchemy.exc import DataError
    async with app.state.sessionmaker() as session:
        with pytest.raises(DataError):
            await session.execute(sql_text(
                "INSERT INTO proxy_oauth_credential "
                "(mapping_id, user_id, access_token, status) "
                "VALUES ('m1m2m3m4m5m6', 999, :tok, 'active')"),
                {"tok": "gAAAA" + "x" * 4096})           # 4097 字符 > 列上限
        await session.rollback()                          # 失败事务复位，不污染后续用例
