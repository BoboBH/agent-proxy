import pytest

from agent_proxy.config import ConfigError, Settings, load_dotenv_file

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


def test_prod_with_real_impls_ok():
    s = Settings.from_env(
        {**BASE, "ENV": "prod", "TOKEN_VERIFY_IMPL": "third_party", "LOGIN_IMPL": "company_sso"}
    )
    assert s.env == "prod" and s.token_verify_impl == "third_party" and s.login_impl == "company_sso"


def test_encrypt_with_master_key_ok():
    s = Settings.from_env({**BASE, "ENCRYPT_AT_REST": "true", "MASTER_KEY": "k"})
    assert s.encrypt_at_rest is True and s.master_key == "k"


def test_missing_dsn_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"REDIS_URL": "redis://127.0.0.1:6379/1"})


def test_bad_trace_mode_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "TRACE_MODE": "loud"})


def test_encrypt_requires_master_key():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "ENCRYPT_AT_REST": "true"})


def _write_env(tmp_path, content):
    p = tmp_path / ".env"
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_load_dotenv_strips_inline_comment(tmp_path, monkeypatch):
    monkeypatch.delenv("PX_TRACE_MODE_TEST", raising=False)
    path = _write_env(tmp_path, "PX_TRACE_MODE_TEST=body   # off | metadata | body\n")
    load_dotenv_file(path)
    import os

    assert os.environ["PX_TRACE_MODE_TEST"] == "body"


def test_load_dotenv_keeps_hash_without_space(tmp_path, monkeypatch):
    monkeypatch.delenv("PX_MASTER_KEY_TEST", raising=False)
    path = _write_env(tmp_path, "PX_MASTER_KEY_TEST=abc#def\n")
    load_dotenv_file(path)
    import os

    assert os.environ["PX_MASTER_KEY_TEST"] == "abc#def"


def test_load_dotenv_does_not_override_existing(tmp_path, monkeypatch):
    monkeypatch.setenv("PX_EXISTING_TEST", "from-env")
    path = _write_env(tmp_path, "PX_EXISTING_TEST=from-file\n")
    load_dotenv_file(path)
    import os

    assert os.environ["PX_EXISTING_TEST"] == "from-env"
