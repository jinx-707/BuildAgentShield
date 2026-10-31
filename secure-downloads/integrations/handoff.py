"""
Document-analysis integration: adapter interface, mock adapter and the
approved-only handoff gate.

CONTRACT (v1)
=============

Only APPROVED files are ever handed off, and the bytes sent to a provider are
read from approved storage only (enforced by DocumentHandoffService.verify()
and by AnalysisService reading through StorageManager.get_approved_path()).

Handoff payload (metadata — opaque, no filesystem paths)
--------------------------------------------------------
{
  "download_id":  str,   # UUID of the approved download
  "tenant_id":    str,
  "agent_id":     str,
  "file_ref":     str,   # opaque internal reference — NOT a filesystem path
  "mime_type":    str,   # verified MIME type
  "file_size":    int,
  "sha256":       str,   # hex SHA-256 of the approved bytes
}

Adapter contract
----------------
`DocumentAnalysisAdapter.analyze(document, correlation_id=...)` submits one
document (metadata + bounded extracted text + the approved bytes) and returns
a validated `ProviderAnalysisResponse`.  Implementations must:

1. Be idempotent for the same download_id + sha256 (the HTTP adapter sends an
   Idempotency-Key derived from both).
2. Raise HandoffError(code=..., retriable=...) on failure; retriable=True only
   for transient conditions (timeouts, 5xx, 429, connection failures).
3. Never log document content, credentials or raw provider responses.

Adapters
--------
- HttpDocumentAnalysisAdapter — real provider integration (contract v1).
- MockDocumentAnalysisAdapter — explicit local testing only; marked with a
  MOCK_ANALYSIS_PROVIDER warning and refused in production-like environments
  by configuration validation.
- DisabledAnalysisAdapter — the feature is off; requests fail with
  ANALYSIS_DISABLED.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from integrations.analysis_models import ProviderAnalysisResponse, ProviderDocumentInfo
from services.document_processor import ProcessedDocument

logger = logging.getLogger(__name__)


class HandoffError(Exception):
    """Raised when a handoff/analysis attempt fails."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "HANDOFF_ERROR",
        retriable: bool = True,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.retriable = retriable
        self.retry_after = retry_after


@dataclass(frozen=True)
class DocumentHandoffPayload:
    download_id: str
    tenant_id: str
    agent_id: str
    file_ref: str       # opaque — never a raw filesystem path
    mime_type: str
    file_size: int
    sha256: str


@dataclass(frozen=True)
class AnalysisDocument:
    """One document submitted for analysis."""

    payload: DocumentHandoffPayload
    content: bytes
    document_type: str
    page_count: int
    extracted_text: str
    text_truncated: bool
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedDocument:
    """Result of the approved-only gate."""

    payload: DocumentHandoffPayload
    storage_ref: str
    file_sha256: str


@runtime_checkable
class DocumentAnalysisAdapter(Protocol):
    """
    Structural protocol a concrete analysis adapter satisfies.

    `provider_name` is stored on the job and in the normalized result so the
    provenance of every result is explicit.
    """

    provider_name: str

    async def analyze(
        self,
        document: AnalysisDocument,
        *,
        correlation_id: str,
    ) -> ProviderAnalysisResponse:
        """Analyze one document.  Raises HandoffError on failure."""
        ...


class MockDocumentAnalysisAdapter:
    """
    Local-only adapter.  Never selected in production (refused by Settings).

    It echoes fixed metadata and marks every result with
    MOCK_ANALYSIS_PROVIDER so results cannot be mistaken for real analysis.
    """

    provider_name = "mock"

    def __init__(
        self,
        *,
        should_fail: bool = False,
        fail_message: str = "mock failure",
        fail_code: str = "ANALYSIS_UNAVAILABLE",
        fail_retriable: bool = True,
    ) -> None:
        self.should_fail = should_fail
        self.fail_message = fail_message
        self.fail_code = fail_code
        self.fail_retriable = fail_retriable
        self.submissions: list[AnalysisDocument] = []

    async def analyze(
        self,
        document: AnalysisDocument,
        *,
        correlation_id: str,
    ) -> ProviderAnalysisResponse:
        if self.should_fail:
            raise HandoffError(
                self.fail_message,
                code=self.fail_code,
                retriable=self.fail_retriable,
            )
        self.submissions.append(document)
        logger.info(
            "mock_document_analysis",
            extra={
                "download_id": document.payload.download_id,
                "tenant_id": document.payload.tenant_id,
                "mime_type": document.payload.mime_type,
                "file_size": document.payload.file_size,
                "correlation_id": correlation_id,
            },
        )
        return ProviderAnalysisResponse(
            analysis_id=str(uuid.uuid4()),
            correlation_id=correlation_id,
            status="completed",
            document=ProviderDocumentInfo(
                document_type=document.document_type,
                page_count=document.page_count,
            ),
            warnings=["MOCK_ANALYSIS_PROVIDER"],
        )


class DisabledAnalysisAdapter:
    """The analysis feature is disabled by configuration."""

    provider_name = "disabled"

    async def analyze(
        self,
        document: AnalysisDocument,
        *,
        correlation_id: str,
    ) -> ProviderAnalysisResponse:
        raise HandoffError(
            "Document analysis is disabled.",
            code="ANALYSIS_DISABLED",
            retriable=False,
        )


class DocumentHandoffService:
    """
    The approved-only gate between storage and any analysis adapter.

    verify()   — record must be APPROVED, storage ref must be in the approved
                 zone, the file must exist, and the SHA-256 must match the
                 recorded hash.
    submit()   — wraps the adapter call; the adapter receives only a verified
                 document plus already-bounded processed text.
    complete() — marks handoff_completed after a provider response was
                 validated and stored.
    """

    def __init__(
        self,
        *,
        adapter: DocumentAnalysisAdapter,
        storage_manager: object,  # StorageManager — avoid circular import
        repository: object,       # DownloadRepository — avoid circular import
    ) -> None:
        self._adapter = adapter
        self._storage = storage_manager
        self._repo = repository

    @property
    def provider_name(self) -> str:
        return self._adapter.provider_name

    async def verify(
        self, *, download_id: str, tenant_id: str
    ) -> VerifiedDocument:
        from models.download import DownloadState
        from security.errors import HANDOFF_ERROR, INVALID_STATE, DownloadSecurityError
        from storage.manager import StorageRef, StorageZone

        record = await self._repo.get(download_id=download_id, tenant_id=tenant_id)

        if record.state != DownloadState.APPROVED:
            # Covers QUARANTINED, REJECTED, FAILED, EXPIRED and every
            # in-flight state: nothing unapproved can be handed off.
            raise DownloadSecurityError(
                INVALID_STATE,
                f"Only APPROVED files can be analyzed. "
                f"Current state: {record.state.value}.",
                http_status=409,
            )

        if not record.storage_ref:
            raise DownloadSecurityError(
                HANDOFF_ERROR,
                "APPROVED download has no storage reference.",
                http_status=500,
            )

        ref = StorageRef.parse(record.storage_ref)
        if ref.zone is not StorageZone.APPROVED:
            raise DownloadSecurityError(
                HANDOFF_ERROR,
                "The storage reference is not in the approved zone.",
                http_status=500,
            )

        # get_approved_path is the only approved-zone accessor.
        path = self._storage.get_approved_path(ref)
        if not path.exists():
            raise DownloadSecurityError(
                HANDOFF_ERROR,
                "The approved file no longer exists in storage. It may have expired.",
                http_status=404,
            )

        actual_sha = self._storage.compute_sha256(ref)
        if actual_sha != record.file_sha256:
            raise DownloadSecurityError(
                HANDOFF_ERROR,
                f"Pre-handoff checksum mismatch for download {download_id!r}. "
                "File may have been tampered with.",
                http_status=500,
            )

        payload = DocumentHandoffPayload(
            download_id=record.id,
            tenant_id=record.tenant_id,
            agent_id=record.agent_id,
            file_ref=record.storage_ref,   # opaque ref, not a filesystem path
            mime_type=record.detected_mime_type or "",
            file_size=record.file_size or 0,
            sha256=record.file_sha256 or "",
        )
        return VerifiedDocument(
            payload=payload,
            storage_ref=record.storage_ref,
            file_sha256=record.file_sha256 or "",
        )

    async def submit(
        self,
        verified: VerifiedDocument,
        *,
        content: bytes,
        processed: ProcessedDocument,
        correlation_id: str,
    ) -> ProviderAnalysisResponse:
        document = AnalysisDocument(
            payload=verified.payload,
            content=content,
            document_type=processed.document_type,
            page_count=processed.page_count,
            extracted_text=processed.text,
            text_truncated=processed.text_truncated,
            warnings=tuple(processed.warnings),
        )
        return await self._adapter.analyze(
            document, correlation_id=correlation_id
        )

    async def complete(self, verified: VerifiedDocument) -> None:
        await self._repo.mark_handoff_completed(
            download_id=verified.payload.download_id,
            tenant_id=verified.payload.tenant_id,
        )
