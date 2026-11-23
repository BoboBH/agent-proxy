import json

from agent_proxy import cache, mapping_id as mid_module
from agent_proxy.services import (build_proxy_url, create_mapping, delete_mapping,
                                  get_owned, list_mappings, load_mapping,
                                  row_to_dict, update_mapping)


async def test_create_and_load_cache_roundtrip(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   "u888", type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api/v1",
                                   headers={"Authorization": "Bearer sk-real-key"},
                                   test_request=None)
        cached = await load_mapping(session, app.state.redis, row.mapping_id,
                                    app.state.settings.cache_ttl)
        assert cached is not None and cached["owner_uid"] == "u888"
        assert cached["upstream_headers"] == {"Authorization": "Bearer sk-real-key"}
        assert (await cache.get_mapping(app.state.redis, row.mapping_id)) == cached


async def test_update_invalidates_cache(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   "u888", type_="mcp", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/sse", headers={},
                                   test_request=None)
        await load_mapping(session, app.state.redis, row.mapping_id, 300)
        updated = await update_mapping(session, app.state.redis, app.state.settings,
                                       row.mapping_id, "u888",
                                       upstream_url="http://10.0.0.5/mcp")
        assert updated["upstream_url"] == "http://10.0.0.5/mcp"
        again = await load_mapping(session, app.state.redis, row.mapping_id, 300)
        assert again["upstream_url"] == "http://10.0.0.5/mcp"


async def test_update_headers_empty_dict_clears(app):
    """patch 语义：headers={} = 清空；缺省/None = 不更新。"""
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   "u888", type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api",
                                   headers={"X-Token": "t1"}, test_request=None)
        await load_mapping(session, app.state.redis, row.mapping_id, 300)
        updated = await update_mapping(session, app.state.redis, app.state.settings,
                                       row.mapping_id, "u888", headers={})
        assert updated["upstream_headers"] == {}
        again = await load_mapping(session, app.state.redis, row.mapping_id, 300)
        assert again["upstream_headers"] == {}


async def test_corrupt_cache_self_heals(app):
    """坏缓存（非法 JSON / 非 dict 载荷）视为未命中：回源 DB 并覆盖坏键，不产生粘性 500。"""
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   "u888", type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api", headers={},
                                   test_request=None)
        await app.state.redis.set(f"ap:mapping:{row.mapping_id}", "not-json")
        data = await load_mapping(session, app.state.redis, row.mapping_id, 300)
        assert data is not None and data["mapping_id"] == row.mapping_id
        assert (await cache.get_mapping(app.state.redis, row.mapping_id)) == data
        await app.state.redis.set(f"ap:mapping:{row.mapping_id}", "[1,2]")  # 合法 JSON 但非 dict
        assert await load_mapping(session, app.state.redis, row.mapping_id, 300) == data


async def test_create_retries_on_id_collision(app, monkeypatch):
    """首个生成 mapping_id 撞唯一键 → IntegrityError → 重试成功。"""
    async with app.state.sessionmaker() as session:
        first = await create_mapping(session, app.state.redis, app.state.settings,
                                     "u888", type_="http", name=None, visibility="private",
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
                                      "u888", type_="http", name=None, visibility="private",
                                      upstream_url="http://10.0.0.5/api", headers={},
                                      test_request=None)
        assert second.mapping_id != first_id
        assert calls["n"] >= 2


async def test_get_owned_hides_others(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   "u888", type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api", headers={},
                                   test_request=None)
        assert await get_owned(session, app.state.redis, row.mapping_id, "u888", 300) is not None
        assert await get_owned(session, app.state.redis, row.mapping_id, "u999", 300) is None


async def test_list_only_mine(app):
    async with app.state.sessionmaker() as session:
        await create_mapping(session, app.state.redis, app.state.settings,
                             "u888", type_="http", name=None, visibility="private",
                             upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
        rows = await list_mappings(session, "u888", limit=10, offset=0)
        assert len(rows) == 1
        assert await list_mappings(session, "u999", limit=10, offset=0) == []


async def test_delete(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   "u888", type_="http", name=None, visibility="private",
                                   upstream_url="http://10.0.0.5/api", headers={},
                                   test_request=None)
        assert await delete_mapping(session, app.state.redis, row.mapping_id, "u888")
        assert not await delete_mapping(session, app.state.redis, row.mapping_id, "u888")
        assert await load_mapping(session, app.state.redis, row.mapping_id, 300) is None


def test_build_proxy_url():
    from agent_proxy.config import Settings
    settings = Settings.from_env({"MYSQL_DSN": "mysql+aiomysql://x", "REDIS_URL": "redis://x",
                                  "EXTERNAL_BASE": "http://testserver"})
    assert build_proxy_url(settings, "aB3xK9mQ2wR4", "http://bobo.com/api/v1", "http") \
        == "http://testserver/p/aB3xK9mQ2wR4"
    assert build_proxy_url(settings, "aB3xK9mQ2wR4", "https://mcp.ex.com/sse", "mcp") \
        == "http://testserver/p/aB3xK9mQ2wR4/sse"


async def test_row_to_dict_serializable(app):
    async with app.state.sessionmaker() as session:
        row = await create_mapping(session, app.state.redis, app.state.settings,
                                   "u888", type_="http", name="我的接口", visibility="private",
                                   upstream_url="http://10.0.0.5/api", headers={},
                                   test_request=None)
        data = row_to_dict(row)
        json.dumps(data, ensure_ascii=False)
