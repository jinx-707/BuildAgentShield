"""Caller identity parsing for session-owned operations.

The API authenticates the caller with its Bearer token. The agent identity is
the caller's logical tenant/agent identity, presented in X-Agent-ID, and is the
value the worker binds a session to. It is validated here with exactly the same
shape the worker uses so the two boundaries cannot disagree.
"""

from __future__ import annotations

import re

from app.schemas.browser import SESSION_ID_PATTERN

_AGENT_ID_RE = re.compile(SESSION_ID_PATTERN)


class InvalidAgentIdError(Exception):
    def __init__(self, message: str = "agent id is invalid") -> None:
        super().__init__(message)
        self.code = "INVALID_AGENT_ID"
        self.status_code = 400


def parse_agent_id(raw_value: str | None) -> str:
    if not raw_value:
        raise InvalidAgentIdError("agent id is required for session operations")
    if not _AGENT_ID_RE.fullmatch(raw_value):
        raise InvalidAgentIdError()
    return raw_value


def parse_optional_agent_id(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    if not _AGENT_ID_RE.fullmatch(raw_value):
        raise InvalidAgentIdError()
    return raw_value
