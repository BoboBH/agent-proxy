"""FastAPI 依赖。"""
from __future__ import annotations

from fastapi import Request


async def get_db(request: Request):
    async with request.app.state.sessionmaker() as session:
        yield session
