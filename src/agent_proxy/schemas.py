"""请求/响应模型（Pydantic v2）。"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


def _require_method_path(v: dict | None) -> dict | None:
    """共享校验：test_request 必须包含 method/path（Create/Update 共用，保持不变量）。"""
    if v is not None and not {"method", "path"} <= set(v.keys()):
        raise ValueError("test_request 需包含 method/path")
    return v


class MappingCreate(BaseModel):
    type: Literal["http", "mcp"]
    name: str | None = Field(default=None, max_length=128)
    visibility: Literal["private", "public"] = "private"
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
