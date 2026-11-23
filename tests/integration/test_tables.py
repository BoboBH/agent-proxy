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
