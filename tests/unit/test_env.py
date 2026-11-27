import pytest
from pydantic import ValidationError

from app.env import Settings

BASE = {
    "mysql_dsn": "mysql+aiomysql://root:123456@127.0.0.1:3306/agent_proxy",
    "redis_url": "redis://127.0.0.1:6379/1",
    "master_key": "test-master-key",
}


class HermeticSettings(Settings):
    """单元测试专用：settings_customise_sources 只保留 init kwargs 源——关闭
    环境变量 / .env / secrets 读取，与原 Settings.from_env(dict) 的「传入 dict
    即整体替换环境」封闭语义等价（字段与校验器全部继承自 Settings）。"""

    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, env_settings,
                                   dotenv_settings, file_secret_settings):
        return (init_settings,)


def _settings(**over) -> HermeticSettings:
    return HermeticSettings(**{**BASE, **over})


def test_defaults():
    s = _settings()
    assert s.env == "dev" and s.token_verify_impl == "stub" and s.cache_ttl == 300
    assert s.max_body_size == 10 * 1024 * 1024 and s.trace_body_max_size == 64 * 1024
    assert s.trace_mode == "metadata" and s.upstream_max_redirects == 3
    assert s.master_key == "test-master-key"     # 收尾批次：MASTER_KEY 必填


def test_parse_size_and_external_base_strip():
    s = _settings(max_body_size="5MB", external_base="http://x.com/")
    assert s.max_body_size == 5 * 1024 * 1024
    assert s.external_base == "http://x.com"


def test_prod_rejects_stub():
    with pytest.raises(ValidationError):
        _settings(env="prod")


def test_illegal_impl_value_rejected():
    # 未知 impl 值必须在配置期拒绝（Literal 白名单），而不是首个请求时才 NotImplementedError -> 500
    with pytest.raises(ValidationError):
        _settings(token_verify_impl="banana")
    with pytest.raises(ValidationError):
        _settings(login_impl="banana")


def test_third_party_token_impl_constructs_in_dev():
    """v4.1：third_party 验签已实现，dev 下可构造（默认 beta 基址）。"""
    s = _settings(token_verify_impl="third_party")
    assert s.token_verify_impl == "third_party"
    assert s.verify_api_base == "https://bapal.9m-tec.com/alphapal/api/ai-service"


def test_prod_third_party_token_with_stub_login_rejected():
    """prod 门禁（沿既有语义）：prod 禁 stub 登录实现——company_sso 未接入前，
    third_party token + stub login 的组合在 prod 仍被拒（login 侧门禁）。"""
    with pytest.raises(ValidationError):
        _settings(env="prod", token_verify_impl="third_party")


def test_missing_dsn_rejected():
    with pytest.raises(ValidationError):
        HermeticSettings(redis_url="redis://127.0.0.1:6379/1",
                         master_key="test-master-key")


def test_missing_master_key_rejected():
    """收尾批次：敏感字段（upstream_headers / OAuth 凭证 / client_secret）强制加密，
    MASTER_KEY 无开关必填；ENCRYPT_AT_REST 可选开关已废止（Settings 无此字段）。"""
    with pytest.raises(ValidationError):
        _settings(master_key="")
    with pytest.raises(ValidationError):
        HermeticSettings(**{k: v for k, v in BASE.items() if k != "master_key"})
    assert "encrypt_at_rest" not in Settings.model_fields


def test_bad_trace_mode_rejected():
    with pytest.raises(ValidationError):
        _settings(trace_mode="loud")


def test_proxy_auth_header_blank_falls_back_to_default():
    assert _settings(proxy_auth_header="").proxy_auth_header == "Authorization"
    assert _settings(proxy_auth_header=" X-Proxy-Authorization ").proxy_auth_header \
        == "X-Proxy-Authorization"


def _write_env(tmp_path, content):
    p = tmp_path / ".env"
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_env_file_inline_comment_rules(tmp_path, monkeypatch):
    """pydantic-settings（python-dotenv）的 .env 解析须维持 DEPLOYMENT.md Q4 契约：
    「空格 + #」起按行内注释剥除；# 前无空格保住值（MASTER_KEY=abc#def）。"""
    monkeypatch.delenv("TRACE_MODE", raising=False)
    monkeypatch.delenv("MASTER_KEY", raising=False)
    path = _write_env(tmp_path, "TRACE_MODE=body   # off | metadata | body\n"
                               "MASTER_KEY=abc#def\n")
    base = {k: v for k, v in BASE.items() if k != "master_key"}
    s = Settings(_env_file=path, **base)
    assert s.trace_mode == "body"
    assert s.master_key == "abc#def"


def test_env_var_beats_env_file(tmp_path, monkeypatch):
    """来源优先级：进程环境变量 > .env 文件（compose env_file 注入值优先的部署语义）。"""
    monkeypatch.delenv("CACHE_TTL", raising=False)
    path = _write_env(tmp_path, "CACHE_TTL=120\n")
    s = Settings(_env_file=path, **BASE)
    assert s.cache_ttl == 120
    monkeypatch.setenv("CACHE_TTL", "60")
    s = Settings(_env_file=path, **BASE)
    assert s.cache_ttl == 60


def test_session_cookie_secure_default_false_and_env_on():
    # M7（§15.1 注记）：Secure 在纯 http 的开发/测试环境使浏览器不回传 Cookie，
    # 故配置化——默认 false；https 部署必须显式置 true
    assert _settings().session_cookie_secure is False
    assert _settings().admin_session_ttl == 28800
    assert _settings(session_cookie_secure="true").session_cookie_secure is True
