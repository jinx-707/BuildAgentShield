"""
Async SQLAlchemy engine and session factory.

The engine is created once per process from the DATABASE_URL setting.
For testing, call get_async_engine(url=...) with an in-memory SQLite URL
and pass the resulting engine to get_async_session().
"""
from __future__ import annotations

from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


def get_async_engine(url: str | None = None) -> AsyncEngine:
    from config.settings import get_settings

    effective_url = url or get_settings().database_url
    connect_args: dict = {}
    if effective_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    return create_async_engine(
        effective_url,
        echo=False,
        future=True,
        connect_args=connect_args,
    )


def get_async_session(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
