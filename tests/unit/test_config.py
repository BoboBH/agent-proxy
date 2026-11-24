import pytest

from agent_proxy.config import ConfigError, Settings, load_dotenv_file

BASE = {
    "MYSQL_DSN": "mysql+aiomysql://root:123456@127.0.0.1:3306/agent_proxy",
    "REDIS_URL": "redis://127.0.0.1:6379/1",
    "MASTER_KEY": "test-master-key",
}


def test_defaults():
    s = Settings.from_env(BASE)
    assert s.env == "dev" and s.token_verify_impl == "stub" and s.cache_ttl == 300
    assert s.max_body_size == 10 * 1024 * 1024 and s.trace_body_max_size == 64 * 1024
    assert s.trace_mode == "metadata" and s.upstream_max_redirects == 3
    assert s.master_key == "test-master-key"     # 收尾批次：MASTER_KEY 必填


def test_parse_size_and_external_base_strip():
    s = Settings.from_env({**BASE, "MAX_BODY_SIZE": "5MB", "EXTERNAL_BASE": "http://x.com/"})
    assert s.max_body_size == 5 * 1024 * 1024
    assert s.external_base == "http://x.com"


def test_prod_rejects_stub():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "ENV": "prod"})


def test_illegal_impl_value_rejected():
    # 未知 impl 值必须在配置期拒绝，而不是首个请求时才 NotImplementedError -> 500
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "TOKEN_VERIFY_IMPL": "banana"})
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "LOGIN_IMPL": "banana"})


def test_prod_with_third_party_rejected_until_impl_lands():
    # third_party/company_sso 尚未实现：prod 下会通过 stub 门禁但请求必 500，故白名单拦截；
    # third_party/company_sso 实现接入后此测试改回构造成功
    with pytest.raises(ConfigError):
        Settings.from_env(
            {**BASE, "ENV": "prod", "TOKEN_VERIFY_IMPL": "third_party", "LOGIN_IMPL": "company_sso"}
        )


def test_missing_dsn_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({"REDIS_URL": "redis://127.0.0.1:6379/1",
                           "MASTER_KEY": "test-master-key"})


def test_missing_master_key_rejected():
    """收尾批次：敏感字段（upstream_headers / OAuth 凭证 / client_secret）强制加密，
    MASTER_KEY 无开关必填；ENCRYPT_AT_REST 可选开关已废止（Setting 无此字段）。"""
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "MASTER_KEY": ""})
    with pytest.raises(ConfigError):
        Settings.from_env({k: v for k, v in BASE.items() if k != "MASTER_KEY"})
    assert not hasattr(Settings(), "encrypt_at_rest")


def test_bad_trace_mode_rejected():
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE, "TRACE_MODE": "loud"})


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


def test_session_cookie_secure_default_false_and_env_on():
    # M7（§15.1 注记）：Secure 在纯 http 的开发/测试环境使浏览器不回传 Cookie，
    # 故配置化——默认 false；https 部署必须显式置 true
    assert Settings.from_env(BASE).session_cookie_secure is False
    assert Settings.from_env(BASE).admin_session_ttl == 28800
    s = Settings.from_env({**BASE, "SESSION_COOKIE_SECURE": "true"})
    assert s.session_cookie_secure is True
