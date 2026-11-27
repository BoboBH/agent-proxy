"""请求/响应模型（Pydantic v2）。"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


_TEST_REQUEST_METHODS = ("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT")
_TEST_REQUEST_KEYS = ("method", "path", "expect_status")


def _require_method_path(v: dict | None) -> dict | None:
    """共享校验（Create/Update 共用，保持不变量）：

    - test_request 必须包含 method/path；method 必须为合法 HTTP 动词白名单
      （M2 遗留 Minor 5：拒绝 TRACE/CONNECT 及任意 token，防探测滥用；大小写
      不敏感接受，probe 侧统一 upper）；
    - 含 expect_status 时必须是 100-599 的整数（bool 除外）——注册时即拒绝畸形值，
      不留 /test 500 隐患（评审修复）。严格模式缺失 expect_status 的语义：
      /test 一律判失败（见 probe_http_mapping docstring），不当作「任意状态码皆可」。
    - 键白名单（部署前安全评审 Minor 7，部署批次落地）：method/path/expect_status
      之外的多余键注册即拒（此前原样入库并在详情回显、probe 不消费——多余键无
      消费面即无合法用途，白名单比回显面钉住更稳；probe 未来要消费新键先扩白名单）。
    """
    if v is not None:
        if not {"method", "path"} <= set(v.keys()):
            raise ValueError("test_request 需包含 method/path")
        extra = sorted(set(v.keys()) - set(_TEST_REQUEST_KEYS))
        if extra:
            raise ValueError("test_request 仅支持 "
                             f"{'/'.join(_TEST_REQUEST_KEYS)} 键，多余键: {', '.join(extra)}")
        method = v.get("method")
        if not isinstance(method, str) or method.upper() not in _TEST_REQUEST_METHODS:
            raise ValueError("test_request.method 必须为合法 HTTP 动词"
                             "（GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS）")
        expect = v.get("expect_status")
        if expect is not None and (isinstance(expect, bool) or not isinstance(expect, int)
                                   or not 100 <= expect <= 599):
            raise ValueError("test_request.expect_status 必须为 100-599 的整数")
    return v


class MappingCreate(BaseModel):
    type: Literal["http", "mcp"]
    name: str | None = Field(default=None, max_length=128)
    visibility: Literal["private", "public"] = "private"
    auth_mode: Literal["static", "oauth"] = "static"
    upstream_url: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    test_request: dict | None = None

    @field_validator("test_request")
    @classmethod
    def _validate_test_request(cls, v: dict | None) -> dict | None:
        return _require_method_path(v)


class MappingUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    visibility: Literal["private", "public"] | None = None
    auth_mode: Literal["static", "oauth"] | None = None
    upstream_url: str | None = Field(default=None, min_length=1, max_length=2048)
    headers: dict[str, str] | None = None
    test_request: dict | None = None
    status: Literal["active", "disabled"] | None = None

    @field_validator("test_request")
    @classmethod
    def _validate_test_request(cls, v: dict | None) -> dict | None:
        return _require_method_path(v)


class RegisteredOut(BaseModel):
    """POST/PUT 响应：代理地址 + 占位符 header（页面据此保存到 Agent）。"""
    mapping_id: str
    name: str | None = None
    type: str
    visibility: str
    auth_mode: str = "static"
    proxy_url: str
    headers: dict[str, str]
    status: str


class MappingDetailOut(RegisteredOut):
    upstream_url: str
    test_request: dict | None = None
    created_at: str | None = None
    updated_at: str | None = None


class ListItemOut(BaseModel):
    """列表项：不含真实 headers。"""
    mapping_id: str
    name: str | None = None
    type: str
    upstream_url: str
    proxy_url: str
    status: str
    created_at: str | None = None
    updated_at: str | None = None


class MappingTestOut(BaseModel):
    """POST /api/v1/mappings/{id}/test 响应（设计 §6.6）。"""
    ok: bool
    status_code: int | None = None
    latency_ms: int
    detail: str


class OAuthClientSet(BaseModel):
    """PUT /api/v1/builtin-mappings/{id}/client 请求（admin，手动模式，§14.3）。
    client_secret 可空（公共客户端 token_auth=none）。"""
    client_id: str = Field(min_length=1, max_length=256)
    # 评审 Important 1（精修批）：入口上限收敛 256——Fernet base64 4/3 膨胀后
    # （256B 明文 → ~418 字符密文）必落存储列 VARCHAR(512) 内；原 1024 会让
    # 320+ 字符 secret 放行到落库撞 1406 DataError → 500
    client_secret: str | None = Field(default=None, max_length=256)
    token_auth: Literal["client_secret_basic", "client_secret_post", "none"] = \
        "client_secret_post"
    authorize_url: str = Field(min_length=1, max_length=2048)
    token_url: str = Field(min_length=1, max_length=2048)
    scopes: str | None = Field(default=None, max_length=512)


class OAuthClientOut(BaseModel):
    """GET/PUT client 响应：secret 只回是否已配置，永不回显值（§14.6）。"""
    mapping_id: str
    client_id: str
    client_secret_configured: bool
    token_auth: str
    authorize_url: str | None = None
    token_url: str | None = None
    scopes: str | None = None
    source: str


class AuthorizeIn(BaseModel):
    """POST /{id}/authorize 请求：回跳页面地址（域白名单校验，§14.6）。"""
    front_redirect: str = Field(min_length=1, max_length=2048)


class AuthorizeOut(BaseModel):
    authorization_url: str


class BindingOut(BaseModel):
    """GET /{id}/binding 响应：binding ∈ unbound/authorizing/bound/invalid（§14.4）。"""
    mapping_id: str
    auth_mode: str
    binding: str
    expires_at: str | None = None
    scope: str | None = None


class BuiltinItemOut(BaseModel):
    """GET /api/v1/builtin-mappings 列表项：占位符 headers，不含真实值（§6.5）；
    binding 仅 auth_mode=oauth 有值（static 为 None）。"""
    mapping_id: str
    name: str | None = None
    type: str
    proxy_url: str
    headers: dict[str, str]
    auth_mode: str
    binding: str | None = None
    status: str
