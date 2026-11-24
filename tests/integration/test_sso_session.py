"""服务端会话 Redis 存取集成（M7，§15.1）：ap:sess:{sid} 写读删 + TTL 语义
（真实 Redis db9）。"""
from agent_proxy.auth import Identity
from agent_proxy.sso.session import (create_session, destroy_session, get_session,
                                     new_sid, session_key)


async def test_create_then_get_roundtrip_with_ttl(app):
    identity = Identity(user_id=888, user_name="张三", role="admin")
    sid = await create_session(app.state.redis, identity, 600)
    assert await get_session(app.state.redis, sid) == identity
    ttl = await app.state.redis.ttl(session_key(sid))
    assert 590 <= ttl <= 600                       # 写入即带 TTL（非持久键）


async def test_get_missing_or_garbage_sid_returns_none(app):
    assert await get_session(app.state.redis, "") is None
    assert await get_session(app.state.redis, new_sid()) is None     # 不存在的 sid
    await app.state.redis.set(session_key("junk"), "not-json")
    assert await get_session(app.state.redis, "junk") is None        # sid 格式非法 → None（不触达载荷）
    sid = "0" * 32                                  # 合法形态 sid + 坏载荷 → 走 decode 分支
    await app.state.redis.set(session_key(sid), "not-json")
    assert await get_session(app.state.redis, sid) is None           # 载荷非法 → None


async def test_destroy_session_removes_key_and_is_idempotent(app):
    sid = await create_session(app.state.redis, Identity(user_id=1), 600)
    await destroy_session(app.state.redis, sid)
    assert await get_session(app.state.redis, sid) is None
    await destroy_session(app.state.redis, sid)                      # 幂等（重放/重复登出安全）


async def test_session_ttl_argument_from_settings(app):
    """接线形态钉住：admin_auth_callback 以 settings.admin_session_ttl 传参。"""
    settings = app.state.settings
    sid = await create_session(app.state.redis, Identity(user_id=2),
                               settings.admin_session_ttl)
    ttl = await app.state.redis.ttl(session_key(sid))
    assert 0 < ttl <= settings.admin_session_ttl
    await destroy_session(app.state.redis, sid)
