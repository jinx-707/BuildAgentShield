"""
Request and response schemas for the Secure Downloads API.

Security notes
--------------
- No internal filesystem paths are ever included in any response.
- storage_ref is excluded from all API responses.
- file_sha256 is included (read-only metadata useful for integrity checks).
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


# ── Requests ──────────────────────────────────────────────────────────────────

class CreateDownloadRequest(BaseModel):
    url: HttpUrl = Field(
        description="The HTTPS URL of the file to download. Must be reachable "
                    "through the configured egress proxy."
    )
    agent_id: str = Field(
        min_length=1,
        max_length=128,
        description="The agent requesting the download.",
    )


# ── Response bodies ───────────────────────────────────────────────────────────

DownloadStateValue = Literal[
    "PENDING",
    "VALIDATING",
    "DOWNLOADING",
    "DOWNLOADED",
    "VERIFYING",
    "SCANNING",
    "APPROVED",
    "QUARANTINED",
    "REJECTED",
    "FAILED",
    "EXPIRED",
]

AnalysisStateValue = Literal[
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
]


class DownloadStatusResponse(BaseModel):
    download_id: str
    tenant_id: str
    agent_id: str
    state: DownloadStateValue
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    failure_reason: str | None = None

    model_config = {"from_attributes": True}


class DownloadMetadataResponse(BaseModel):
    download_id: str
    tenant_id: str
    agent_id: str
    original_url: str
    state: DownloadStateValue
    original_filename: str | None = None
    detected_mime_type: str | None = None
    file_size: int | None = None
    file_sha256: str | None = None    # Included — integrity metadata, not a path
    scan_result: str | None = None
    scan_detail: str | None = None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    failure_reason: str | None = None
    handoff_completed: bool = False
    # Analysis job summary (no result content — see the dedicated result route).
    analysis_id: str | None = None
    analysis_state: AnalysisStateValue | None = None
    analysis_provider: str | None = None
    # storage_ref is intentionally excluded.

    model_config = {"from_attributes": True}


class ScanStatusResponse(BaseModel):
    download_id: str
    state: DownloadStateValue
    scan_result: str | None = None
    scan_detail: str | None = None
    message: str

    model_config = {"from_attributes": True}


class AnalysisJobResponse(BaseModel):
    """
    Analysis job status.

    Never contains document content, storage references or provider output.
    `error_detail` is a fixed, content-free description written by this
    service, never raw provider text.
    """

    analysis_id: str = Field(validation_alias="id")
    download_id: str
    tenant_id: str
    state: AnalysisStateValue
    provider: str
    correlation_id: str
    attempts: int = 0
    retryable: bool | None = None
    error_code: str | None = None
    error_detail: str | None = None
    provider_analysis_id: str | None = None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


# ── Error body ────────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error: str
    code: str
    message: str
    download_id: str | None = None
