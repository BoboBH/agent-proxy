"""环境配置（统一配置体系）：pydantic-settings BaseSettings 声明式读取。

全项目唯一配置入口——任何需要配置的代码一律 `from app.env import get_settings` /
`Settings`，不得直接读 os.environ / 手写解析（测试夹具的 env 注入除外）。

来源优先级：显式构造 kwargs > 进程环境变量 > .env 文件（env_file）> 字段默认值。
校验失败抛 pydantic.ValidationError，进程启动即 fail-fast（不降级运行）。
prod 禁止 stub 校验/登录实现。
"""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# 项目根 = app/env.py 向上一层。.env 定位锚定到此，不随进程 CWD 漂移——
# 服务可在任意工作目录启动（uvicorn / 脚本 / 测试），读到的都是同一份 .env。
# 测试/脚本需要定位项目内文件时也从这里取（from app.env import BASE_DIR）。
BASE_DIR = Path(__file__).resolve().parent.parent


def _parse_size(text: str) -> int:
    """'10MB' / '64KB' / '1GB' / 纯数字 → 字节数；非法值抛 ValueError。"""
    t = text.strip().upper()
    try:
        for suffix, mult in {"KB": 1024, "MB": 1024**2, "GB": 1024**3}.items():
            if t.endswith(suffix):
                return int(float(t[: -len(suffix)]) * mult)
        return int(t)
    except ValueError:
        raise ValueError(f"非法大小: {text!r}") from None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env", env_file_encoding="utf-8", extra="ignore")

    external_base: str = "http://127.0.0.1:8800"
    env: str = "dev"
    token_verify_impl: Literal["stub", "third_party"] = "stub"
    login_impl: Literal["stub"] = "stub"
    admin_user_type: str = "admin"   # 管理员 user_type（v4.3：验签响应 user_type 与之相等 且 org_id==admin_org_id 才是管理员）；部署 .env 覆盖为 org_member
    # 管理员组织 ID（v4.3）：third_party 验签响应 org_id 与之相等 且 user_type==admin_user_type
    # 才是管理员（双匹配）；stub 身份 org_id=None 放行（开发模式不受组织约束）
    admin_org_id: int = 7
    # 代理身份通道头名（设计 v4，可配置）：默认 Authorization——统一 token 场景下
    # 该头既作代理鉴权又可透传上游；配置为其他名字（如 X-Proxy-Authorization）时
    # 该头纯代理私有、绝不透传（v2 分离模式经配置恢复）
    proxy_auth_header: str = "Authorization"
    # third_party 验签接口基址（docs/auth_verify_token_integration.md）：默认 beta，
    # 生产切 https://app.9m-tec.com/ai-service
    verify_api_base: str = "https://bapal.9m-tec.com/alphapal/api/ai-service"
    mysql_dsn: str = Field(min_length=1)
    redis_url: str = Field(min_length=1)
    cache_ttl: int = 300
    upstream_connect_timeout: float = 10.0
    upstream_read_timeout: float = 60.0
    upstream_pool_timeout: float = 5.0
    upstream_max_redirects: int = 3
    upstream_max_connections: int = 200
    max_body_size: int = 10 * 1024 * 1024
    ssrf_allow_private: bool = False
    # 按映射并发上限（设计 v4.2，慢上游隔离）：单个映射的同时在途上游请求数上限，
    # 超限该映射自己的请求 503 PROXY_BUSY——其他映射不受影响；0 = 关闭隔离
    mapping_max_concurrency: int = 20
    # NoDecode：pydantic-settings 默认对复杂类型按 JSON 解析环境变量——本项目
    # 契约是逗号分隔（CORS_ALLOWED_ORIGINS=a,b），以 NoDecode 跳过 JSON 解码，
    # 由 _split_origins before-validator 处理
    cors_allowed_origins: Annotated[tuple[str, ...], NoDecode] = ()
    oauth_state_ttl: int = 600
    admin_session_ttl: int = 28800
    session_cookie_secure: bool = False
    # 收尾批次：敏感字段（upstream_headers / OAuth 凭证 / client_secret）强制
    # 加密落库，MASTER_KEY 无开关必填；ENCRYPT_AT_REST 可选开关已废止
    master_key: str = Field(min_length=1)
    # log_dir 保持「相对 CWD」语义（容器 WORKDIR=/app + compose 卷挂载 /app/logs；
    # 本地仓库根启动 → ./logs）。不可锚定 BASE_DIR：容器内包已装进 site-packages，
    # 锚定会写进 site-packages 且卷落空。需要绝对路径时直接配绝对路径即可
    log_dir: str = str(BASE_DIR / "logs")
    log_level: str = "INFO"
    trace_mode: Literal["off", "metadata", "body"] = "metadata"
    trace_body_max_size: int = 64 * 1024

    @field_validator("external_base")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @field_validator("proxy_auth_header")
    @classmethod
    def _proxy_auth_header_default(cls, v: str) -> str:
        return v.strip() or "Authorization"

    @field_validator("verify_api_base")
    @classmethod
    def _verify_api_base_default(cls, v: str) -> str:
        return (v.strip()
                or "https://bapal.9m-tec.com/alphapal/api/ai-service")

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            return tuple(x.strip() for x in v.split(",") if x.strip())
        return v

    @field_validator("max_body_size", "trace_body_max_size", mode="before")
    @classmethod
    def _coerce_size(cls, v: object) -> object:
        if isinstance(v, str):
            return _parse_size(v)
        return v

    @model_validator(mode="after")
    def _prod_gate(self) -> "Settings":
        if self.env.lower() == "prod" and ("stub" in (self.token_verify_impl, self.login_impl)):
            raise ValueError("prod 环境禁止 stub 校验/登录实现启动")
        return self


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
