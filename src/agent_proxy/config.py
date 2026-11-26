"""环境配置：Settings.from_env 纯函数读取；prod 禁止 stub 实现；.env 轻量加载。"""
from __future__ import annotations

import functools
import os
import re
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _to_int(key: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"非法数值: {key}={raw!r}") from None


def _to_float(key: str, raw: str) -> float:
    try:
        return float(raw)
    except ValueError:
        raise ConfigError(f"非法数值: {key}={raw!r}") from None


def _parse_size(key: str, text: str) -> int:
    t = text.strip().upper()
    try:
        for suffix, mult in {"KB": 1024, "MB": 1024**2, "GB": 1024**3}.items():
            if t.endswith(suffix):
                return int(float(t[: -len(suffix)]) * mult)
        return int(t)
    except ValueError:
        raise ConfigError(f"非法大小: {key}={text!r}") from None


@dataclass(frozen=True)
class Settings:
    listen: str = "0.0.0.0:8800"
    external_base: str = "http://127.0.0.1:8800"
    env: str = "dev"
    token_verify_impl: str = "stub"
    login_impl: str = "stub"
    admin_role: str = "admin"
    # 代理身份通道头名（设计 v4，可配置）：默认 Authorization——统一 token 场景下
    # 该头既作代理鉴权又可透传上游；配置为其他名字（如 X-Proxy-Authorization）时
    # 该头纯代理私有、绝不透传（v2 分离模式经配置恢复）
    proxy_auth_header: str = "Authorization"
    # third_party 验签接口基址（docs/auth_verify_token_integration.md）：默认 beta，
    # 生产切 https://app.9m-tec.com/ai-service
    verify_api_base: str = "https://bapal.9m-tec.com/alphapal/api/ai-service"
    mysql_dsn: str = ""
    redis_url: str = ""
    cache_ttl: int = 300
    upstream_connect_timeout: float = 10.0
    upstream_read_timeout: float = 60.0
    upstream_pool_timeout: float = 5.0
    upstream_max_redirects: int = 3
    upstream_max_connections: int = 200
    shutdown_drain_seconds: int = 10
    max_body_size: int = 10 * 1024 * 1024
    ssrf_allow_private: bool = False
    cors_allowed_origins: tuple[str, ...] = ()
    oauth_state_ttl: int = 600
    admin_session_ttl: int = 28800
    session_cookie_secure: bool = False
    master_key: str = ""
    log_dir: str = "logs"
    log_level: str = "INFO"
    trace_mode: str = "metadata"
    trace_body_max_size: int = 64 * 1024

    @staticmethod
    def from_env(env: dict[str, str] | None = None) -> "Settings":
        e = dict(os.environ if env is None else env)
        s = Settings(
            listen=e.get("AGENT_PROXY_LISTEN", "0.0.0.0:8800"),
            external_base=e.get("EXTERNAL_BASE", "http://127.0.0.1:8800").rstrip("/"),
            env=e.get("ENV", "dev"),
            token_verify_impl=e.get("TOKEN_VERIFY_IMPL", "stub"),
            login_impl=e.get("LOGIN_IMPL", "stub"),
            admin_role=e.get("ADMIN_ROLE", "admin"),
            proxy_auth_header=(e.get("PROXY_AUTH_HEADER", "").strip()
                               or "Authorization"),
            verify_api_base=(e.get("VERIFY_API_BASE", "").strip()
                             or "https://bapal.9m-tec.com/alphapal/api/ai-service"),
            mysql_dsn=e.get("MYSQL_DSN", ""),
            redis_url=e.get("REDIS_URL", ""),
            cache_ttl=_to_int("CACHE_TTL", e.get("CACHE_TTL", "300")),
            upstream_connect_timeout=_to_float("UPSTREAM_CONNECT_TIMEOUT", e.get("UPSTREAM_CONNECT_TIMEOUT", "10")),
            upstream_read_timeout=_to_float("UPSTREAM_READ_TIMEOUT", e.get("UPSTREAM_READ_TIMEOUT", "60")),
            upstream_pool_timeout=_to_float("UPSTREAM_POOL_TIMEOUT", e.get("UPSTREAM_POOL_TIMEOUT", "5")),
            upstream_max_redirects=_to_int("UPSTREAM_MAX_REDIRECTS", e.get("UPSTREAM_MAX_REDIRECTS", "3")),
            upstream_max_connections=_to_int("UPSTREAM_MAX_CONNECTIONS", e.get("UPSTREAM_MAX_CONNECTIONS", "200")),
            shutdown_drain_seconds=_to_int("SHUTDOWN_DRAIN_SECONDS", e.get("SHUTDOWN_DRAIN_SECONDS", "10")),
            max_body_size=_parse_size("MAX_BODY_SIZE", e.get("MAX_BODY_SIZE", "10MB")),
            ssrf_allow_private=e.get("SSRF_ALLOW_PRIVATE", "false").lower() == "true",
            cors_allowed_origins=tuple(
                x.strip() for x in e.get("CORS_ALLOWED_ORIGINS", "").split(",") if x.strip()
            ),
            oauth_state_ttl=_to_int("OAUTH_STATE_TTL", e.get("OAUTH_STATE_TTL", "600")),
            admin_session_ttl=_to_int("ADMIN_SESSION_TTL", e.get("ADMIN_SESSION_TTL", "28800")),
            session_cookie_secure=e.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
            master_key=e.get("MASTER_KEY", ""),
            log_dir=e.get("LOG_DIR", "logs"),
            log_level=e.get("LOG_LEVEL", "INFO"),
            trace_mode=e.get("TRACE_MODE", "metadata"),
            trace_body_max_size=_parse_size("TRACE_BODY_MAX_SIZE", e.get("TRACE_BODY_MAX_SIZE", "64KB")),
        )
        s.validate()
        return s

    def validate(self) -> None:
        if self.env.lower() == "prod" and (self.token_verify_impl == "stub" or self.login_impl == "stub"):
            raise ConfigError("prod 环境禁止 stub 校验/登录实现启动")
        if self.token_verify_impl not in ("stub",):
            raise ConfigError(f"非法 TOKEN_VERIFY_IMPL: {self.token_verify_impl!r}（M1 可用：stub；third_party 接入后加入白名单）")
        if self.login_impl not in ("stub",):
            raise ConfigError(f"非法 LOGIN_IMPL: {self.login_impl!r}（M1 可用：stub；company_sso 接入后加入白名单）")
        if self.trace_mode not in ("off", "metadata", "body"):
            raise ConfigError(f"非法 TRACE_MODE: {self.trace_mode}")
        if not self.mysql_dsn or not self.redis_url:
            raise ConfigError("缺少必需配置: MYSQL_DSN / REDIS_URL")
        if not self.master_key:
            # 收尾批次：敏感字段（upstream_headers / OAuth 凭证 / client_secret）强制
            # 加密落库，MASTER_KEY 无开关必填；ENCRYPT_AT_REST 可选开关已废止
            raise ConfigError("缺少必需配置: MASTER_KEY（敏感字段强制加密落库）")


def load_dotenv_file(path: str = ".env") -> None:
    """极简 .env 加载（KEY=VALUE，# 注释，剥离行内注释），不覆盖已有环境变量。"""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            # 剥离行内注释（仅空格分隔的 #，保住 MASTER_KEY=abc#def 这类值）
            value = re.sub(r"\s+#.*$", "", value)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()
