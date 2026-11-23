"""环境配置：Settings.from_env 纯函数读取；prod 禁止 stub 实现；.env 轻量加载。"""
from __future__ import annotations

import functools
import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _parse_size(text: str) -> int:
    t = text.strip().upper()
    for suffix, mult in {"KB": 1024, "MB": 1024**2, "GB": 1024**3}.items():
        if t.endswith(suffix):
            return int(float(t[: -len(suffix)]) * mult)
    return int(t)


@dataclass(frozen=True)
class Settings:
    listen: str = "0.0.0.0:8800"
    external_base: str = "http://127.0.0.1:8800"
    env: str = "dev"
    token_verify_impl: str = "stub"
    login_impl: str = "stub"
    admin_role: str = "admin"
    mysql_dsn: str = ""
    redis_url: str = ""
    cache_ttl: int = 300
    upstream_connect_timeout: float = 10.0
    upstream_read_timeout: float = 60.0
    upstream_max_redirects: int = 3
    upstream_max_connections: int = 200
    shutdown_drain_seconds: int = 10
    max_body_size: int = 10 * 1024 * 1024
    ssrf_allow_private: bool = False
    cors_allowed_origins: tuple[str, ...] = ()
    oauth_state_ttl: int = 600
    admin_session_ttl: int = 28800
    encrypt_at_rest: bool = False
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
            mysql_dsn=e.get("MYSQL_DSN", ""),
            redis_url=e.get("REDIS_URL", ""),
            cache_ttl=int(e.get("CACHE_TTL", "300")),
            upstream_connect_timeout=float(e.get("UPSTREAM_CONNECT_TIMEOUT", "10")),
            upstream_read_timeout=float(e.get("UPSTREAM_READ_TIMEOUT", "60")),
            upstream_max_redirects=int(e.get("UPSTREAM_MAX_REDIRECTS", "3")),
            upstream_max_connections=int(e.get("UPSTREAM_MAX_CONNECTIONS", "200")),
            shutdown_drain_seconds=int(e.get("SHUTDOWN_DRAIN_SECONDS", "10")),
            max_body_size=_parse_size(e.get("MAX_BODY_SIZE", "10MB")),
            ssrf_allow_private=e.get("SSRF_ALLOW_PRIVATE", "false").lower() == "true",
            cors_allowed_origins=tuple(
                x.strip() for x in e.get("CORS_ALLOWED_ORIGINS", "").split(",") if x.strip()
            ),
            oauth_state_ttl=int(e.get("OAUTH_STATE_TTL", "600")),
            admin_session_ttl=int(e.get("ADMIN_SESSION_TTL", "28800")),
            encrypt_at_rest=e.get("ENCRYPT_AT_REST", "false").lower() == "true",
            master_key=e.get("MASTER_KEY", ""),
            log_dir=e.get("LOG_DIR", "logs"),
            log_level=e.get("LOG_LEVEL", "INFO"),
            trace_mode=e.get("TRACE_MODE", "metadata"),
            trace_body_max_size=_parse_size(e.get("TRACE_BODY_MAX_SIZE", "64KB")),
        )
        s.validate()
        return s

    def validate(self) -> None:
        if self.env == "prod" and (self.token_verify_impl == "stub" or self.login_impl == "stub"):
            raise ConfigError("prod 环境禁止 stub 校验/登录实现启动")
        if self.trace_mode not in ("off", "metadata", "body"):
            raise ConfigError(f"非法 TRACE_MODE: {self.trace_mode}")
        if not self.mysql_dsn or not self.redis_url:
            raise ConfigError("缺少必需配置: MYSQL_DSN / REDIS_URL")
        if self.encrypt_at_rest and not self.master_key:
            raise ConfigError("ENCRYPT_AT_REST 开启时必须配置 MASTER_KEY")


def load_dotenv_file(path: str = ".env") -> None:
    """极简 .env 加载（KEY=VALUE，# 注释），不覆盖已有环境变量。"""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()
