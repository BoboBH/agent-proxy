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
    assert {"mapping_id", "uid", "access_token", "refresh_token", "expires_at",
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
    """收尾批次 schema 定型：user_id 整数化（owner_uid/uid BIGINT，索引保留）+
    upstream_headers 强制加密（TEXT 密文列，JSON 明文列废止）。"""
    db = app.state.engine.url.database
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT table_name, column_name, data_type FROM information_schema.columns "
            "WHERE table_schema=:db AND ((table_name='proxy_mapping' AND column_name IN "
            "('owner_uid','upstream_headers')) OR (table_name='proxy_oauth_credential' "
            "AND column_name='uid'))"), {"db": db})
        types = {f"{t}.{c}": d for t, c, d in rows}
    assert types["proxy_mapping.owner_uid"] == "bigint"
    assert types["proxy_oauth_credential.uid"] == "bigint"
    assert types["proxy_mapping.upstream_headers"] == "text"


async def test_uid_columns_indexed(app):
    """整数化后索引保留（owner_uid / uid 均有单列索引，归属过滤与 uk 前缀依赖）。"""
    db = app.state.engine.url.database
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT table_name, index_name FROM information_schema.statistics "
            "WHERE table_schema=:db AND column_name IN ('owner_uid','uid')"),
            {"db": db})
        indexed = {f"{t}" for t, _ in rows}
    assert {"proxy_mapping", "proxy_oauth_credential"} <= indexed
