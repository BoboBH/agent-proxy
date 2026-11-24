"""OAuth 凭证存取层集成（app 夹具 + 真实 MySQL/Redis，设计 §5.3）：
加密 upsert（uk mapping_id+uid）/ cred 缓存 cache-aside（密文形态）/ 失效 /
invalid 标记 / 删除。"""
from datetime import datetime, timedelta

from sqlalchemy import select

from agent_proxy.models import OAuthCredential
from agent_proxy.oauth.credential import (delete_credential, encrypt_text,
                                          invalidate_credential, load_credential,
                                          mark_credential_invalid, save_credential)

MASTER = "test-master-key"
MID = "m1m2m3m4m5m6"
UID = "u888"


async def _save(app, uid=UID, expires=None, access="at-plain-123456",
                refresh="rt-plain-123456", mapping_id=MID):
    async with app.state.sessionmaker() as session:
        await save_credential(session, app.state.redis, mapping_id, uid,
                              access_token_ct=encrypt_text(access, MASTER),
                              refresh_token_ct=(encrypt_text(refresh, MASTER)
                                                if refresh else None),
                              expires_at=expires, scope="read", master_key=MASTER)


async def _raw_row(app, uid=UID, mapping_id=MID):
    async with app.state.sessionmaker() as session:
        return (await session.execute(
            select(OAuthCredential).where(OAuthCredential.mapping_id == mapping_id,
                                          OAuthCredential.uid == uid))).scalar_one()


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
