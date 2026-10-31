"""
Browser session manager — tracks active Puppeteer sessions.
Each session is isolated and cleaned up after use or on timeout.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


class BrowserSession:
    def __init__(self, session_id: str, agent_id: str, timeout_seconds: int = 120) -> None:
        self.session_id = session_id
        self.agent_id = agent_id
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.timeout_seconds = timeout_seconds
        self.active = True
        self.page_count = 0

    def touch(self) -> None:
        self.last_activity = datetime.utcnow()

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.last_activity + timedelta(seconds=self.timeout_seconds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "active": self.active,
            "page_count": self.page_count,
        }


class SessionManager:
    """Manages browser sessions — enforces max sessions and timeouts."""

    def __init__(self, max_sessions: int = 10, session_timeout: int = 120) -> None:
        self._sessions: dict[str, BrowserSession] = {}
        self._max_sessions = max_sessions
        self._session_timeout = session_timeout
        self._lock = asyncio.Lock()

    async def create_session(self, agent_id: str) -> BrowserSession:
        async with self._lock:
            self._cleanup_expired()
            if len(self._sessions) >= self._max_sessions:
                raise RuntimeError(
                    f"Maximum browser sessions ({self._max_sessions}) reached. "
                    "Close existing sessions before creating new ones."
                )
            session_id = f"sess_{uuid.uuid4().hex[:12]}"
            session = BrowserSession(
                session_id=session_id,
                agent_id=agent_id,
                timeout_seconds=self._session_timeout,
            )
            self._sessions[session_id] = session
            logger.info("Browser session created: %s for agent %s", session_id, agent_id)
            return session

    async def get_session(self, session_id: str) -> BrowserSession | None:
        session = self._sessions.get(session_id)
        if session and session.is_expired():
            await self.close_session(session_id)
            return None
        return session

    async def close_session(self, session_id: str) -> None:
        async with self._lock:
            session = self._sessions.pop(session_id, None)
            if session:
                session.active = False
                logger.info("Browser session closed: %s", session_id)

    def _cleanup_expired(self) -> None:
        expired = [sid for sid, s in self._sessions.items() if s.is_expired()]
        for sid in expired:
            self._sessions.pop(sid, None)
            logger.info("Browser session expired and cleaned up: %s", sid)

    def active_count(self) -> int:
        self._cleanup_expired()
        return len(self._sessions)

    def get_all(self) -> list[dict[str, Any]]:
        self._cleanup_expired()
        return [s.to_dict() for s in self._sessions.values()]
