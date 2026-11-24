"""ORM：proxy_mapping / proxy_oauth_client / proxy_oauth_credential（M6 表 M1 一并建）。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, BigInteger, DateTime, Enum, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class ProxyMapping(Base):
    __tablename__ = "proxy_mapping"
    __table_args__ = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    mapping_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    # 收尾批次整数化：内部系统 user_id 为整数（BIGINT，索引保留）
    owner_uid: Mapped[int] = mapped_column(BigInteger, index=True)
    name: Mapped[str | None] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(Enum("http", "mcp", name="mapping_type"))
    visibility: Mapped[str] = mapped_column(
        Enum("private", "public", name="mapping_visibility"), default="private", index=True)
    auth_mode: Mapped[str] = mapped_column(
        Enum("static", "oauth", name="mapping_auth_mode"), default="static")
    upstream_url: Mapped[str] = mapped_column(String(2048))
    # 收尾批次强制加密：headers 落库为 Fernet(MASTER_KEY) 密文 TEXT（JSON 明文列废止，
    # 由 services 层 encrypt/decrypt 转换，读取方拿到的恒为解密后的 dict）
    upstream_headers: Mapped[str] = mapped_column(Text)
    test_request: Mapped[dict[str, str] | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(
        Enum("active", "disabled", name="mapping_status"), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now())


class OAuthClient(Base):
    __tablename__ = "proxy_oauth_client"
    __table_args__ = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    mapping_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    client_id: Mapped[str] = mapped_column(String(256))
    client_secret: Mapped[str | None] = mapped_column(Text)
    token_auth: Mapped[str] = mapped_column(
        Enum("client_secret_basic", "client_secret_post", "none", name="oauth_token_auth"),
        default="client_secret_post")
    authorize_url: Mapped[str | None] = mapped_column(String(2048))
    token_url: Mapped[str | None] = mapped_column(String(2048))
    scopes: Mapped[str | None] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(Enum("dcr", "manual", name="oauth_client_source"))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now())


class OAuthCredential(Base):
    __tablename__ = "proxy_oauth_credential"
    __table_args__ = (
        UniqueConstraint("mapping_id", "uid", name="uk_mapping_uid"),
        {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    mapping_id: Mapped[str] = mapped_column(String(16))
    # 收尾批次整数化：与 proxy_mapping.owner_uid 同型（BIGINT，索引保留）
    uid: Mapped[int] = mapped_column(BigInteger, index=True)
    access_token: Mapped[str] = mapped_column(Text)
    refresh_token: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    scope: Mapped[str | None] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(
        Enum("active", "invalid", name="oauth_cred_status"), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now())
