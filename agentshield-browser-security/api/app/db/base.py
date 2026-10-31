"""Database base and session management for AgentShield enterprise platform."""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from app.config import Settings

Base = declarative_base()

_engine = None
_SessionLocal = None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default="now()",
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        server_default="now()",
    )


def init_db(settings: Settings) -> None:
    """Initialize the SQLAlchemy engine and session factory."""
    global _engine, _SessionLocal
    database_url = settings.database_url
    if not database_url:
        raise ValueError("DATABASE_URL must be configured")
    _engine = create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
    )
    _SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=_engine,
    )


def get_db_session() -> Session:
    """Return a new SQLAlchemy session."""
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _SessionLocal()


def get_engine():
    """Return the SQLAlchemy engine."""
    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _engine


def create_all() -> None:
    """Create all tables (for dev/test only; Alembic is used for migrations)."""
    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    Base.metadata.create_all(bind=_engine)


def drop_all() -> None:
    """Drop all tables (for dev/test only)."""
    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    Base.metadata.drop_all(bind=_engine)
