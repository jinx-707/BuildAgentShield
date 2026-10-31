from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.browser import SESSION_ID_PATTERN


class SessionCreateRequest(BaseModel):
    # The worker enforces the authoritative ceilings from its own configuration,
    # so the API only rejects values that cannot be valid anywhere. A value the
    # worker considers too large is refused there with a precise 400.
    idle_timeout_ms: int | None = Field(default=None, ge=30000)
    max_age_ms: int | None = Field(default=None, ge=60000)


class SessionStatus(BaseModel):
    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    state: str
    status: str
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    idle_timeout_ms: int
    max_age_ms: int
    active_requests: int
    closing_requested: bool
    current_url: str | None = None


class SessionCloseResponse(BaseModel):
    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    closed: bool
    closing: bool
    request_id: str
