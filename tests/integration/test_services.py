import json

from agent_proxy import cache
from agent_proxy.services import (build_proxy_url, create_mapping, delete_mapping,
                                  get_owned, list_mappings, load_mapping,
                                  row_to_dict, update_mapping)


def _mk_body(**overrides):
    body = {"type": "http", "upstream_url": "http://10.0.0.5/api/v1",
            "headers": {"Authorization": "Bearer sk-real-key"}}
    body.update(overrides)
    return body


async def test_create_and_load_cache_roundtrip(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="http", name=None, visibility="private",
                               upstream_url="http://10.0.0.5/api/v1",
                               headers={"Authorization": "Bearer sk-real-key"}, test_request=None)
    cached = await load_mapping(app.state.sessionmaker(), app.state.redis,
                                row.mapping_id, app.state.settings.cache_ttl)
    assert cached is not None and cached["owner_uid"] == "u888"
    assert cached["upstream_headers"] == {"Authorization": "Bearer sk-real-key"}
    assert (await cache.get_mapping(app.state.redis, row.mapping_id)) == cached


async def test_update_invalidates_cache(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="mcp", name=None, visibility="private",
                               upstream_url="http://10.0.0.5/sse", headers={}, test_request=None)
    await load_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, 300)
    updated = await update_mapping(app.state.sessionmaker(), app.state.redis,
                                   app.state.settings, row.mapping_id, "u888",
                                   upstream_url="http://10.0.0.5/mcp")
    assert updated["upstream_url"] == "http://10.0.0.5/mcp"
    again = await load_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, 300)
    assert again["upstream_url"] == "http://10.0.0.5/mcp"


async def test_get_owned_hides_others(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="http", name=None, visibility="private",
                               upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
    assert await get_owned(app.state.sessionmaker(), app.state.redis, row.mapping_id,
                           "u888", 300) is not None
    assert await get_owned(app.state.sessionmaker(), app.state.redis, row.mapping_id,
                           "u999", 300) is None


async def test_list_only_mine(app):
    await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                         "u888", type_="http", name=None, visibility="private",
                         upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
    rows = await list_mappings(app.state.sessionmaker(), "u888", limit=10, offset=0)
    assert len(rows) == 1
    assert await list_mappings(app.state.sessionmaker(), "u999", limit=10, offset=0) == []


async def test_delete(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="http", name=None, visibility="private",
                               upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
    assert await delete_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, "u888")
    assert not await delete_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, "u888")
    assert await load_mapping(app.state.sessionmaker(), app.state.redis, row.mapping_id, 300) is None


def test_build_proxy_url():
    from agent_proxy.config import Settings
    settings = Settings.from_env({"MYSQL_DSN": "mysql+aiomysql://x", "REDIS_URL": "redis://x",
                                  "EXTERNAL_BASE": "http://testserver"})
    assert build_proxy_url(settings, "aB3xK9mQ2wR4", "http://bobo.com/api/v1", "http") \
        == "http://testserver/p/aB3xK9mQ2wR4"
    assert build_proxy_url(settings, "aB3xK9mQ2wR4", "https://mcp.ex.com/sse", "mcp") \
        == "http://testserver/p/aB3xK9mQ2wR4/sse"


async def test_row_to_dict_serializable(app):
    row = await create_mapping(app.state.sessionmaker(), app.state.redis, app.state.settings,
                               "u888", type_="http", name="我的接口", visibility="private",
                               upstream_url="http://10.0.0.5/api", headers={}, test_request=None)
    data = row_to_dict(row)
    json.dumps(data, ensure_ascii=False)
