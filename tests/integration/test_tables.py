from sqlalchemy import text


async def test_tables_created(app):
    db = app.state.engine.url.database
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=:db"), {"db": db})
        names = {r[0] for r in rows}
    assert {"proxy_mapping", "proxy_oauth_client", "proxy_oauth_credential"} <= names


async def test_mapping_columns(app):
    db = app.state.engine.url.database
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema=:db AND table_name='proxy_mapping'"), {"db": db})
        cols = {r[0] for r in rows}
    assert {"mapping_id", "owner_uid", "name", "type", "visibility", "auth_mode",
            "upstream_url", "upstream_headers", "test_request", "status"} <= cols


async def test_oauth_columns(app):
    db = app.state.engine.url.database
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema=:db AND table_name IN "
            "('proxy_oauth_client', 'proxy_oauth_credential')"), {"db": db})
        cols: dict[str, set[str]] = {}
        for table, column in rows:
            cols.setdefault(table, set()).add(column)
    assert {"mapping_id", "client_id", "client_secret", "token_auth", "authorize_url",
            "token_url", "scopes", "source", "created_at", "updated_at"} <= cols["proxy_oauth_client"]
    assert {"mapping_id", "user_id", "access_token", "refresh_token", "expires_at",
            "scope", "status", "created_at", "updated_at"} <= cols["proxy_oauth_credential"]


async def test_mapping_visibility_index(app):
    db = app.state.engine.url.database
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT index_name FROM information_schema.statistics "
            "WHERE table_schema=:db AND table_name='proxy_mapping' "
            "AND column_name='visibility'"), {"db": db})
        names = {r[0] for r in rows}
    assert "ix_proxy_mapping_visibility" in names


async def test_sensitive_column_types(app):
    """终审后精修 schema 定型：user_id 整数化（owner_uid/user_id BIGINT，索引保留）+
    upstream_headers 强制加密（TEXT 密文列，唯一保留 TEXT——整个 JSON 变长）+
    OAuth 加密列 VARCHAR 化（Fernet base64 膨胀 4/3，定长上限显式 fail-fast，
    避免无界 TEXT）。"""
    db = app.state.engine.url.database
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT table_name, column_name, data_type, character_maximum_length "
            "FROM information_schema.columns "
            "WHERE table_schema=:db AND ((table_name='proxy_mapping' AND column_name IN "
            "('owner_uid','upstream_headers')) OR (table_name='proxy_oauth_credential' "
            "AND column_name IN ('user_id','access_token','refresh_token')) OR "
            "(table_name='proxy_oauth_client' AND column_name='client_secret'))"),
            {"db": db})
        types = {f"{t}.{c}": (d, n) for t, c, d, n in rows}
    assert types["proxy_mapping.owner_uid"] == ("bigint", None)
    assert types["proxy_oauth_credential.user_id"] == ("bigint", None)
    # 精修 1：加密列 VARCHAR 定长（明文 ~3KB 长 JWT 经 Fernet base64 4/3 膨胀后仍覆盖）
    assert types["proxy_oauth_credential.access_token"] == ("varchar", 4096)
    assert types["proxy_oauth_credential.refresh_token"] == ("varchar", 2000)
    assert types["proxy_oauth_client.client_secret"] == ("varchar", 512)
    # upstream_headers 保持 TEXT（整个 JSON 变长，唯一保留；TEXT 上限 65535 字节）
    assert types["proxy_mapping.upstream_headers"] == ("text", 65535)


async def test_user_id_columns_indexed(app):
    """整数化后索引保留（owner_uid / user_id 均有单列索引，归属过滤与 uk 前缀依赖）；
    精修 2：索引名随列名同步（ix_proxy_oauth_credential_user_id / uk_mapping_user_id）。"""
    db = app.state.engine.url.database
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT table_name, index_name FROM information_schema.statistics "
            "WHERE table_schema=:db AND column_name IN ('owner_uid','user_id')"),
            {"db": db})
        indexed = {f"{t}" for t, _ in rows}
        names = await conn.execute(text(
            "SELECT index_name FROM information_schema.statistics "
            "WHERE table_schema=:db AND table_name='proxy_oauth_credential'"),
            {"db": db})
        cred_indexes = {r[0] for r in names}
    assert {"proxy_mapping", "proxy_oauth_credential"} <= indexed
    assert "ix_proxy_oauth_credential_user_id" in cred_indexes
    assert "uk_mapping_user_id" in cred_indexes
