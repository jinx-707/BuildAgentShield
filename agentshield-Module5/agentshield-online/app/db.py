"""
Database setup — SQLAlchemy async engine and session factory.
Creates tables on startup (dev mode). Use Alembic for production migrations.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import text

from app.core.configuration import get_settings

logger = logging.getLogger(__name__)


def create_engine():
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        echo=False,
        future=True,
        connect_args={"check_same_thread": False}
        if "sqlite" in settings.database_url else {},
    )


_engine = None
_session_factory = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine()
    return _engine


def get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(), expire_on_commit=False, class_=AsyncSession
        )
    return _session_factory


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory()
    async with factory() as session:
        yield session


CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS payment_transactions (
    payment_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    merchant_id TEXT NOT NULL,
    amount_minor INTEGER NOT NULL,
    currency TEXT NOT NULL,
    purpose TEXT NOT NULL,
    order_reference TEXT NOT NULL,
    provider TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'CREATED',
    provider_order_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_daily_spending (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    currency TEXT NOT NULL,
    spend_date TEXT NOT NULL,
    total_spent_minor INTEGER NOT NULL DEFAULT 0,
    UNIQUE(agent_id, tenant_id, currency, spend_date)
);

CREATE TABLE IF NOT EXISTS payment_idempotency (
    idempotency_key TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    payment_id TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (idempotency_key, agent_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS processed_webhooks (
    event_id TEXT PRIMARY KEY,
    payment_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    processed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS download_records (
    download_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    url TEXT NOT NULL,
    filename TEXT,
    file_size INTEGER,
    sha256 TEXT,
    mime_type TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    scan_result TEXT,
    quarantine_reason TEXT,
    created_at TEXT NOT NULL
);
"""


async def init_db() -> None:
    """Create all tables. Uses SQLite for local dev."""
    engine = get_engine()
    async with engine.begin() as conn:
        for stmt in CREATE_TABLES_SQL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                await conn.execute(text(stmt))
    logger.info("Database initialized")
