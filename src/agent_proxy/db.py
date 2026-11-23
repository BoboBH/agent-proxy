"""MySQL 异步 engine / session（Task 7 完善注释）。"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def build_engine(mysql_dsn: str, pool_size: int = 10):
    return create_async_engine(mysql_dsn, pool_size=pool_size, pool_recycle=1800, pool_pre_ping=True)


def build_sessionmaker(engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
