from sqlalchemy import text


async def test_tables_created(app):
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='agent_proxy_test'"
        ))
        names = {r[0] for r in rows}
    assert {"proxy_mapping", "proxy_oauth_client", "proxy_oauth_credential"} <= names


async def test_mapping_columns(app):
    async with app.state.engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='agent_proxy_test' AND table_name='proxy_mapping'"
        ))
        cols = {r[0] for r in rows}
    assert {"mapping_id", "owner_uid", "name", "type", "visibility", "auth_mode",
            "upstream_url", "upstream_headers", "test_request", "status"} <= cols
