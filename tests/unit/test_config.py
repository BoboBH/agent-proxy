import pytest

from agent_proxy.config import ConfigError, Settings

BASE = {
    "MYSQL_DSN": "mysql+aiomysql://root:123456@127.0.0.1:3306/agent_proxy",
    "REDIS_URL": "redis://127.0.0.1:6379/1",
}


def test_defaults():
    s = Settings.from_env(BASE)
    assert s.env == "dev" and s.token_verify_impl == "stub" and s.cache_ttl == 300
    assert s.max_body_size == 10 * 1024 * 1024 and s.trace_body_max_size == 64 * 1024
    assert s.trace_mode == "metadata" and s.upstream_max_redirects == 3


def test_parse_size_and_external_base_strip():
    s = Settings.from_env({**BASE, "MAX_BODY_SIZE": "5MB", "EXTERNAL_BASE": "http://x.com/"})
    assert s.max_body_size == 5 * 1024 * 1024
    assert s.external_base == "http://x.com"


def test_prod_rejects_stub():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "ENV": "prod"})


def test_missing_dsn_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"REDIS_URL": "redis://127.0.0.1:6379/1"})


def test_bad_trace_mode_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "TRACE_MODE": "loud"})


def test_encrypt_requires_master_key():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "ENCRYPT_AT_REST": "true"})
