from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    service: str
    version: str
    checks: dict[str, str] = Field(default_factory=dict)
    detail: str | None = None


class WorkerHealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    service: str
    version: str
    checks: dict[str, str] = Field(default_factory=dict)
