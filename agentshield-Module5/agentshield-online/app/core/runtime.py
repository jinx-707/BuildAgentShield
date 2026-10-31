"""
AgentShield Online — Application runtime state.
Holds shared resources (DB engine, Redis, adapters) for dependency injection.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
    from redis.asyncio import Redis
    from app.integrations.ports import (
        ContentInspectionPort,
        DataInspectionPort,
        PolicyPort,
        ApprovalPort,
        AuditPort,
        SecretProviderPort,
    )


class AppRuntime:
    """Singleton runtime container."""

    def __init__(self) -> None:
        self.db_engine: "AsyncEngine | None" = None
        self.redis: "Redis | None" = None
        self.content_inspector: "ContentInspectionPort | None" = None
        self.data_inspector: "DataInspectionPort | None" = None
        self.policy: "PolicyPort | None" = None
        self.approval: "ApprovalPort | None" = None
        self.audit: "AuditPort | None" = None
        self.secret_provider: "SecretProviderPort | None" = None
        self._ready: bool = False

    def mark_ready(self) -> None:
        self._ready = True

    def is_ready(self) -> bool:
        return self._ready


# Global runtime instance — populated during app lifespan startup
runtime = AppRuntime()
