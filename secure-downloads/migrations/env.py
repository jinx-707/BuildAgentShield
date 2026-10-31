"""Alembic migration environment for AgentShield Secure Downloads."""
from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

# Make sure project root is on the path when running alembic CLI.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models.database import Base  # noqa: E402  (must come after sys.path update)
from models.analysis import DocumentAnalysis  # noqa: E402, F401
from models.download import Download  # noqa: E402, F401  (ensure table is registered)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    # Prefer DATABASE_URL env var; fall back to alembic.ini sqlalchemy.url.
    url = os.environ.get("DATABASE_URL") or config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError(
            "No database URL configured.  Set DATABASE_URL env var or "
            "sqlalchemy.url in alembic.ini."
        )
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (no DB connection needed for SQL dump)."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations against a live async engine."""
    connectable = create_async_engine(get_url())
    async with connectable.connect() as connection:
        await connection.run_sync(
            lambda sync_conn: context.configure(
                connection=sync_conn, target_metadata=target_metadata
            )
        )
        await connection.run_sync(lambda _: context.run_migrations())
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
