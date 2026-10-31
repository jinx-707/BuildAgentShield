"""Pydantic contracts for download records.

Response schemas expose metadata only: no file bytes, no filesystem paths,
and no credentials. Public download endpoints are out of scope for Phase B.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.downloads.enums import DownloadStatus, HandoffStatus, PolicyDecision, StorageZone


class DownloadRecordResponse(BaseModel):
    """Tenant-visible download metadata. Storage is referenced by opaque id only."""

    model_config = ConfigDict(from_attributes=True, extra="ignore", populate_by_name=True)

    id: UUID
    tenant_id: str
    agent_id: str
    original_url: str
    source_hostname: str
    status: DownloadStatus
    storage_zone: StorageZone
    storage_ref: Optional[str] = None
    original_filename: Optional[str] = None
    detected_mime: Optional[str] = None
    size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    scan_verdict: Optional[str] = None
    scanner_version: Optional[str] = None
    threat_name: Optional[str] = None
    findings: Dict[str, Any] = Field(default_factory=dict, validation_alias="findings_json")
    policy_decision: PolicyDecision
    handoff_status: HandoffStatus
    failure_code: Optional[str] = None
    failure_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None


class DownloadStatusChange(BaseModel):
    """Internal contract for applying a lifecycle change without exposing paths."""

    model_config = ConfigDict(extra="forbid")

    status: DownloadStatus
    storage_zone: Optional[StorageZone] = None
    failure_reason: Optional[str] = None
