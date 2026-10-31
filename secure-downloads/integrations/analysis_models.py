"""
Document-analysis request/response schemas (provider contract v1) and the
normalized result persisted by this service.

Provider contract v1 (the "AgentShield Document Analysis API")
-------------------------------------------------------------
No external vendor has been selected for this deployment, so this module
defines the versioned contract that a concrete provider (or the local
integration test server) implements.  It is deliberately small:

    POST <ANALYSIS_ENDPOINT_URL>
    Authorization: Bearer <ANALYSIS_API_TOKEN>
    Content-Type: application/json
    X-Correlation-ID: <uuid>
    Idempotency-Key: "<download_id>:<sha256>"

    {
      "schema_version": "1",
      "correlation_id": "<uuid>",
      "document": {
        "download_id": "...", "tenant_id": "...", "agent_id": "...",
        "sha256": "...", "mime_type": "application/pdf",
        "size_bytes": 1234, "page_count": 3, "text_truncated": false,
        "extracted_text": "...", "warnings": ["..."]
      },
      "content_base64": "<approved file bytes>"
    }

    200 application/json
    {
      "schema_version": "1",
      "analysis_id": "...", "correlation_id": "...",
      "status": "completed" | "failed",
      "document": {"document_type": "pdf", "page_count": 3},
      "summary": "..." | null,
      "findings": [{"id": "...", "severity": "info|low|medium|high|critical",
                    "title": "...", "detail": "..."}],
      "confidence": {"overall": 0.8} | null,
      "metadata": {"key": "scalar"},
      "warnings": ["..."],
      "processed_at": "2026-01-01T00:00:00Z",
      "error": {"code": "...", "message": "...", "retryable": false}
    }

Safety rules applied to responses
---------------------------------
* Unknown fields are ignored; extra data cannot reach the database.
* Every string is stripped of control characters and length-capped.
* Findings, metadata, confidence and warning collections are count-capped.
* `confidence` is provider-supplied only.  This service never computes,
  infers or defaults a score.
* A response that does not validate is rejected wholesale
  (ANALYSIS_INVALID_RESPONSE); nothing is partially stored.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ANALYSIS_SCHEMA_VERSION = "1"

CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

MAX_FINDINGS = 50
MAX_WARNINGS = 20
MAX_CONFIDENCE_KEYS = 10
MAX_METADATA_KEYS = 20


def clean_text(value: str, limit: int) -> str:
    """Remove control characters, collapse horizontal whitespace, cap length."""
    cleaned = CONTROL_CHARS.sub("", value)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    return cleaned[:limit]


def _bounded_str(limit: int):
    def _validate(value: str) -> str:
        return clean_text(value, limit)

    return _validate


# ── Provider-facing models ────────────────────────────────────────────────────

Severity = Literal["info", "low", "medium", "high", "critical"]


class ProviderFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default="", max_length=64)
    severity: Severity = "info"
    title: str = Field(default="", max_length=200)
    detail: str = Field(default="", max_length=2_000)

    @field_validator("id", mode="before")
    @classmethod
    def _clean_id(cls, value: object) -> str:
        return clean_text(str(value), 64)

    @field_validator("title", mode="before")
    @classmethod
    def _clean_title(cls, value: object) -> str:
        return clean_text(str(value), 200)

    @field_validator("detail", mode="before")
    @classmethod
    def _clean_detail(cls, value: object) -> str:
        return clean_text(str(value), 2_000)


class ProviderDocumentInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    document_type: str = Field(default="unknown", max_length=64)
    page_count: int | None = Field(default=None, ge=0, le=1_000_000)

    @field_validator("document_type", mode="before")
    @classmethod
    def _clean_type(cls, value: object) -> str:
        return clean_text(str(value), 64) or "unknown"


class ProviderErrorDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")

    code: str = Field(default="", max_length=64)
    message: str = Field(default="", max_length=500)
    retryable: bool = False

    @field_validator("code", mode="before")
    @classmethod
    def _clean_code(cls, value: object) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]", "", str(value))[:64]

    @field_validator("message", mode="before")
    @classmethod
    def _clean_message(cls, value: object) -> str:
        return clean_text(str(value), 500)


class ProviderAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: str = ANALYSIS_SCHEMA_VERSION
    analysis_id: str = Field(min_length=1, max_length=128)
    correlation_id: str | None = Field(default=None, max_length=64)
    status: Literal["completed", "failed"]
    document: ProviderDocumentInfo = Field(default_factory=ProviderDocumentInfo)
    summary: str | None = None
    findings: list[ProviderFinding] = Field(default_factory=list, max_length=MAX_FINDINGS)
    confidence: dict[str, float] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list, max_length=MAX_WARNINGS)
    processed_at: datetime | None = None
    error: ProviderErrorDetail | None = None

    @field_validator("analysis_id", mode="before")
    @classmethod
    def _clean_analysis_id(cls, value: object) -> str:
        return clean_text(str(value), 128)

    @field_validator("summary", mode="before")
    @classmethod
    def _clean_summary(cls, value: object) -> str | None:
        if value is None:
            return None
        return clean_text(str(value), 4_000) or None

    @field_validator("warnings", mode="before")
    @classmethod
    def _clean_warnings(cls, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [clean_text(str(item), 200) for item in value[:MAX_WARNINGS] if str(item)]

    @field_validator("confidence", mode="before")
    @classmethod
    def _clean_confidence(cls, value: object) -> dict[str, float] | None:
        if value is None:
            return None
        if not isinstance(value, dict) or len(value) > MAX_CONFIDENCE_KEYS:
            raise ValueError("confidence must be an object with at most "
                             f"{MAX_CONFIDENCE_KEYS} entries")
        cleaned: dict[str, float] = {}
        for key, raw in value.items():
            name = clean_text(str(key), 32)
            if not name:
                raise ValueError("confidence keys must be non-empty")
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise ValueError("confidence values must be numbers")
            number = float(raw)
            if not (0.0 <= number <= 1.0):
                raise ValueError("confidence values must be within [0, 1]")
            cleaned[name] = number
        return cleaned

    @field_validator("metadata", mode="before")
    @classmethod
    def _clean_metadata(cls, value: object) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict) or len(value) > MAX_METADATA_KEYS:
            raise ValueError(f"metadata must be an object with at most "
                             f"{MAX_METADATA_KEYS} entries")
        cleaned: dict[str, Any] = {}
        for key, raw in value.items():
            name = clean_text(str(key), 64)
            if not name:
                continue
            if isinstance(raw, bool) or raw is None:
                continue
            if isinstance(raw, (int, float)):
                cleaned[name] = raw
            elif isinstance(raw, str):
                cleaned[name] = clean_text(raw, 500)
            else:
                raise ValueError("metadata values must be scalar")
        return cleaned

    @field_validator("processed_at", mode="before")
    @classmethod
    def _parse_processed_at(cls, value: object) -> datetime | None:
        if value is None or isinstance(value, datetime):
            return value
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("processed_at must be an ISO-8601 timestamp") from exc
        return parsed

    @model_validator(mode="after")
    def _failure_requires_error(self) -> "ProviderAnalysisResponse":
        if self.status == "failed" and self.error is None:
            # A failure without a structured reason is not usable; treat it as
            # an invalid response rather than guessing.
            raise ValueError("status='failed' requires an error object")
        return self


# ── Request sent to the provider ──────────────────────────────────────────────

class AnalysisRequestDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    download_id: str
    tenant_id: str
    agent_id: str
    sha256: str
    mime_type: str
    size_bytes: int
    page_count: int
    text_truncated: bool
    extracted_text: str
    warnings: list[str] = Field(default_factory=list)


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = ANALYSIS_SCHEMA_VERSION
    correlation_id: str
    document: AnalysisRequestDocument
    content_base64: str


# ── Normalized result stored by this service ─────────────────────────────────

class NormalizedAnalysisResult(BaseModel):
    """
    The stable result contract returned by the API.

    Provenance is explicit: locally derived fields (`document_type`,
    `page_count`, `extracted_text`, `warnings`) and provider-supplied fields
    (`summary`, `findings`, `confidence`, `provider_metadata`,
    `provider_document_type`) are kept separate so a caller can tell what the
    provider actually reported.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = ANALYSIS_SCHEMA_VERSION
    download_id: str
    analysis_id: str
    provider: str
    status: Literal["completed"] = "completed"

    # Locally derived (trusted, bounded) — never provider text.
    document_type: str
    page_count: int
    extracted_text: str
    text_truncated: bool

    # Provider-supplied, validated and sanitized.
    summary: str | None = None
    findings: list[ProviderFinding] = Field(default_factory=list)
    confidence: dict[str, float] | None = None
    provider_metadata: dict[str, Any] = Field(default_factory=dict)
    provider_document_type: str | None = None

    warnings: list[str] = Field(default_factory=list)
    provider_analysis_id: str
    provider_correlation_id: str | None = None
    processed_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    sha256: str


def build_normalized_result(
    *,
    download_id: str,
    analysis_id: str,
    provider: str,
    document_type: str,
    page_count: int,
    extracted_text: str,
    text_truncated: bool,
    sha256: str,
    response: ProviderAnalysisResponse,
    local_warnings: list[str],
) -> NormalizedAnalysisResult:
    """Combine local extraction facts with a validated provider response."""
    warnings: list[str] = []
    for warning in [*local_warnings, *response.warnings]:
        cleaned = clean_text(warning, 200)
        if cleaned and cleaned not in warnings:
            warnings.append(cleaned)
    warnings = warnings[:MAX_WARNINGS]

    return NormalizedAnalysisResult(
        download_id=download_id,
        analysis_id=analysis_id,
        provider=provider,
        document_type=document_type,
        page_count=page_count,
        extracted_text=extracted_text,
        text_truncated=text_truncated,
        summary=response.summary,
        findings=response.findings,
        confidence=response.confidence,
        provider_metadata=response.metadata,
        provider_document_type=(
            response.document.document_type
            if response.document.document_type != "unknown"
            else None
        ),
        warnings=warnings,
        provider_analysis_id=response.analysis_id,
        provider_correlation_id=response.correlation_id,
        processed_at=response.processed_at,
        sha256=sha256,
    )
