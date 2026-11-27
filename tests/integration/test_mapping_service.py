import json

from app.services import mapping_id as mid_module
from app.services.mapping_service import (build_proxy_url, create_mapping,
                          delete_mapping, get_owned, list_mappings,
                          load_mapping, row_to_dict, update_mapping)

MASTER = "test-master-key"


async def test_create_and_load_cache_roundtrip(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api/v1",
                                   headers={"Authorization": "Bearer sk-real-key"},
                                   test_request=None)
        cached = await load_mapping(session, app.state.redis, row.mapping_id,
                                    app.state.settings.cache_ttl, MASTER)
        assert cached is not None and cached["owner_uid"] == 888   # owner_uid int（整数化）
        # 调用方拿到的是解密后的明文 dict（读取路径透明，收尾批次强制加密）
        assert cached["upstream_headers"] == {"Authorization": "Bearer sk-real-key"}


async def test_create_and_load_headers_ciphertext_everywhere(app):
    """收尾批次强制加密：DB 行与 Redis 缓存均为 Fernet 密文，明文值两侧都不落。"""
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api/v1",
                                   headers={"Authorization": "Bearer sk-real-key"},
                                   test_request=None)
        await load_mapping(session, app.state.redis, row.mapping_id,
                           app.state.settings.cache_ttl, MASTER)
        # DB 行：upstream_headers 为 gAAAA 密文（TEXT 列），明文值不落库
        await session.refresh(row)
        stored = row.upstream_headers
        assert isinstance(stored, str) and stored.startswith("gAAAA")
        assert "sk-real-key" not in stored
        # Redis 缓存：同存密文形态（ap:cred:* 先例），明文值不进 Redis
        raw = await app.state.redis.get(f"ap:mapping:{row.mapping_id}")
        raw_text = raw.decode() if isinstance(raw, bytes) else raw
        cache_data = json.loads(raw_text)
        assert cache_data["upstream_headers"].startswith("gAAAA")
        assert "sk-real-key" not in raw_text
        assert cache_data["owner_uid"] == 888


async def test_corrupt_headers_ciphertext_fail_closed_db(app):
    """DB 侧损坏密文（MASTER_KEY 变更/行损坏）→ load_mapping None（fail-closed，
    调用方 404「映射不存在」语义），绝不返回部分明文。"""
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api",
                                   headers={"Authorization": "Bearer sk-real-key"},
                                   test_request=None)
        from sqlalchemy import update
        await session.execute(update(row.__class__)
                              .where(row.__class__.id == row.id)
                              .values(upstream_headers="gAAAAbroken-not-fernet"))
        await session.commit()
        await app.state.redis.flushdb()          # 绕过缓存直接走回源路径
        assert await load_mapping(session, app.state.redis, row.mapping_id, 300,
                                  MASTER) is None
        assert await get_owned(session, app.state.redis, row.mapping_id, 888, 300,
                               MASTER) is None


async def test_corrupt_headers_ciphertext_fail_closed_cache(app):
    """缓存侧损坏密文（手工写入/键残留形态）→ None（fail-closed，404 语义），
    不返回部分明文。"""
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api",
                                   headers={}, test_request=None)
        poisoned = json.dumps({"mapping_id": row.mapping_id, "owner_uid": 888,
                               "visibility": "private", "type": "http",
                               "upstream_headers": "not-a-fernet-token"})
        await app.state.redis.set(f"ap:mapping:{row.mapping_id}", poisoned)
        assert await load_mapping(session, app.state.redis, row.mapping_id, 300,
                                  MASTER) is None


async def test_update_invalidates_cache(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="mcp", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/sse", headers={},
                                   test_request=None)
        await load_mapping(session, app.state.redis, row.mapping_id, 300, MASTER)
        updated = await update_mapping(session, app.state.redis, app.state.settings,
                                       row.mapping_id, 888,
                                       upstream_url="http://10.0.0.5/mcp")
        assert updated["upstream_url"] == "http://10.0.0.5/mcp"
        again = await load_mapping(session, app.state.redis, row.mapping_id, 300, MASTER)
        assert again["upstream_url"] == "http://10.0.0.5/mcp"


async def test_update_headers_empty_dict_clears(app):
    """patch 语义：headers={} = 清空；缺省/None = 不更新。"""
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api",
                                   headers={"X-Token": "t1"}, test_request=None)
        await load_mapping(session, app.state.redis, row.mapping_id, 300, MASTER)
        updated = await update_mapping(session, app.state.redis, app.state.settings,
                                       row.mapping_id, 888, headers={})
        assert updated["upstream_headers"] == {}
        again = await load_mapping(session, app.state.redis, row.mapping_id, 300, MASTER)
        assert again["upstream_headers"] == {}
        # 空表也走统一密文形态（"{}" 的密文），不落明文
        await session.refresh(row)
        assert row.upstream_headers.startswith("gAAAA")


async def test_corrupt_cache_self_heals(app):
    """坏缓存（非法 JSON / 非 dict 载荷）视为未命中：回源 DB 并覆盖坏键，不产生粘性 500。"""
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api", headers={},
                                   test_request=None)
        await app.state.redis.set(f"ap:mapping:{row.mapping_id}", "not-json")
        data = await load_mapping(session, app.state.redis, row.mapping_id, 300, MASTER)
        assert data is not None and data["mapping_id"] == row.mapping_id
        # 回填的缓存为密文形态（明文 dict 是返回值，不进 Redis）
        cached_raw = json.loads(await app.state.redis.get(f"ap:mapping:{row.mapping_id}"))
        assert cached_raw["upstream_headers"].startswith("gAAAA")
        await app.state.redis.set(f"ap:mapping:{row.mapping_id}", "[1,2]")  # 合法 JSON 但非 dict
        assert await load_mapping(session, app.state.redis, row.mapping_id, 300, MASTER) == data


async def test_create_retries_on_id_collision(app, monkeypatch):
    """首个生成 mapping_id 撞唯一键 → IntegrityError → 重试成功。"""
    async with app.state.sessionmaker() as session:
        first = await create_mapping(session, app.state.redis, app.state.settings,
                                     888, type_="http", name=None, visibility="private",
                                     upstream_url="http://10.0.0.5/api", headers={},
                                     test_request=None)
        first_id = first.mapping_id  # 预先取出：rollback 会把同会话内已持久化对象置为过期
        calls = {"n": 0}
        real_new = mid_module.new_mapping_id

        def flaky_new():
            calls["n"] += 1
            return first_id if calls["n"] == 1 else real_new()

        monkeypatch.setattr(mid_module, "new_mapping_id", flaky_new)
        second = await create_mapping(session, app.state.redis, app.state.settings,
                                      888, type_="http", name=None, visibility="private",
                                      upstream_url="http://10.0.0.5/api", headers={},
                                      test_request=None)
        assert second.mapping_id != first_id
        assert calls["n"] >= 2


async def test_get_owned_hides_others(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api", headers={},
                                   test_request=None)
        assert await get_owned(session, app.state.redis, row.mapping_id, 888, 300,
                               MASTER) is not None
        assert await get_owned(session, app.state.redis, row.mapping_id, 999, 300,
                               MASTER) is None


async def test_list_only_mine(app):
    async with app.state.sessionmaker() as session:
        await create_mapping(session, app.state.redis, app.state.settings,
                             888, type_="http", name=None, visibility="private",
                             upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
        rows = await list_mappings(session, 888, limit=10, offset=0)
        assert len(rows) == 1
        assert await list_mappings(session, 999, limit=10, offset=0) == []


async def test_delete(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api", headers={},
                                   test_request=None)
        assert await delete_mapping(session, app.state.redis, row.mapping_id, 888)
        assert not await delete_mapping(session, app.state.redis, row.mapping_id, 888)
        assert await load_mapping(session, app.state.redis, row.mapping_id, 300,
                                  MASTER) is None


def test_build_proxy_url():
    from app.env import Settings
    settings = Settings(_env_file=None, mysql_dsn="mysql+aiomysql://x",
                        redis_url="redis://x", external_base="http://testserver",
                        master_key="test-master-key")
    assert build_proxy_url(settings, "aB3xK9mQ2wR4", "http://bobo.com/api/v1", "http") \
        == "http://testserver/p/aB3xK9mQ2wR4"
    assert build_proxy_url(settings, "aB3xK9mQ2wR4", "https://mcp.ex.com/sse", "mcp") \
        == "http://testserver/p/aB3xK9mQ2wR4/sse"


async def test_row_to_dict_serializable(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name="我的接口", visibility="private",
                                   upstream_url="http://10.0.0.5/api", headers={},
                                   test_request=None)
        data = row_to_dict(row, MASTER)
        json.dumps(data, ensure_ascii=False)
        # 明文形态（owner 查看真实值语义不变），owner_uid int（整数化）
        assert data["owner_uid"] == 888 and data["upstream_headers"] == {}


async def test_stale_plaintext_cache_fail_closed_then_self_heals(app):
    """评审 Important 2 配套：迁移前旧明文 dict 形态的缓存残留（headers 为 dict）
    → plain_headers 非密文串守卫 fail-closed（None→404），且缓存坏键即时失效——
    下一请求回源 DB（密文形态健康）自动恢复，不粘性 404。"""
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   888, type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api",
                                   headers={"Authorization": "Bearer sk-real-key"},
                                   test_request=None)
        mid = row.mapping_id
        await load_mapping(session, app.state.redis, mid, 300, MASTER)
        # 模拟迁移前旧形态缓存：headers 为明文 dict 而非密文串
        stale = {"mapping_id": mid, "owner_uid": 888, "visibility": "private",
                 "type": "http", "upstream_url": "http://10.0.0.5/api",
                 "upstream_headers": {"Authorization": "Bearer sk-real-key"}}
        await app.state.redis.set(f"ap:mapping:{mid}", json.dumps(stale))
        assert await load_mapping(session, app.state.redis, mid, 300, MASTER) is None
        # 坏键已被即时失效：下一请求回源 DB 自愈（明文形态返回 + 密文形态回填）
        again = await load_mapping(session, app.state.redis, mid, 300, MASTER)
        assert again is not None
        assert again["upstream_headers"] == {"Authorization": "Bearer sk-real-key"}
        cached_raw = json.loads(await app.state.redis.get(f"ap:mapping:{mid}"))
        assert cached_raw["upstream_headers"].startswith("gAAAA")
