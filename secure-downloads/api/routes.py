"""
FastAPI route handlers for Secure Downloads.

Endpoints
---------
POST /online/downloads                                  — initiate a download
GET  /online/downloads/{download_id}/status             — lifecycle state
GET  /online/downloads/{download_id}/metadata           — full metadata
POST /online/downloads/{download_id}/scan               — trigger scan (idempotent)
POST /online/downloads/{download_id}/analysis           — initiate analysis
GET  /online/downloads/{download_id}/analysis           — analysis job status
GET  /online/downloads/{download_id}/analysis/result    — normalized result
POST /online/downloads/{download_id}/analysis/retry     — retry an eligible failure

Authentication
--------------
All endpoints require the X-Tenant-ID header.  Bearer token auth is enforced
by ApiAuthMiddleware (applied at app level).

Tenant isolation
----------------
Every query is scoped by tenant_id extracted from X-Tenant-ID.  A caller
cannot access downloads or analyses belonging to a different tenant.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from api.schemas import (
    AnalysisJobResponse,
    CreateDownloadRequest,
    DownloadMetadataResponse,
    DownloadStatusResponse,
    ScanStatusResponse,
)
from models.analysis import AnalysisState
from security.errors import (
    ANALYSIS_NOT_COMPLETED,
    DownloadSecurityError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/online/downloads", tags=["downloads"])

_TENANT_ID_HEADER = "X-Tenant-ID"


def _get_tenant(x_tenant_id: str = Header(alias="X-Tenant-ID", min_length=1, max_length=128)) -> str:
    return x_tenant_id


def _security_error_response(exc: DownloadSecurityError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "error": "download_error",
            "code": exc.code,
            "message": exc.message,
        },
    )


def _status_response(record) -> DownloadStatusResponse:
    # Built explicitly: the ORM attribute is `id`, the public field is
    # `download_id`, so model_validate(record) would fail.
    return DownloadStatusResponse(
        download_id=record.id,
        tenant_id=record.tenant_id,
        agent_id=record.agent_id,
        state=record.state.value,
        created_at=record.created_at,
        updated_at=record.updated_at,
        expires_at=record.expires_at,
        failure_reason=record.failure_reason,
    )


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_download(
    body: CreateDownloadRequest,
    request: Request,
    x_tenant_id: str = Header(alias="X-Tenant-ID", min_length=1, max_length=128),
) -> DownloadStatusResponse:
    """
    Initiate a new secure file download.

    The download runs asynchronously.  Poll GET /status for progress.
    Returns HTTP 202 with the initial PENDING record.
    """
    orchestrator = request.app.state.orchestrator
    try:
        record = await orchestrator.initiate_download(
            tenant_id=x_tenant_id,
            agent_id=body.agent_id,
            url=str(body.url),
        )
    except DownloadSecurityError as exc:
        return _security_error_response(exc)
    except Exception as exc:
        logger.error(
            "create_download_error", extra={"error_type": type(exc).__name__}
        )
        raise HTTPException(status_code=500, detail="Internal error initiating download.")

    return _status_response(record)


@router.get("/{download_id}/status")
async def get_download_status(
    download_id: str,
    request: Request,
    x_tenant_id: str = Header(alias="X-Tenant-ID", min_length=1, max_length=128),
) -> DownloadStatusResponse:
    """Return the current lifecycle state of a download."""
    orchestrator = request.app.state.orchestrator
    try:
        record = await orchestrator.get_status(
            download_id=download_id, tenant_id=x_tenant_id
        )
    except DownloadSecurityError as exc:
        return _security_error_response(exc)

    return DownloadStatusResponse(
        download_id=record.id,
        tenant_id=record.tenant_id,
        agent_id=record.agent_id,
        state=record.state.value,
        created_at=record.created_at,
        updated_at=record.updated_at,
        expires_at=record.expires_at,
        failure_reason=record.failure_reason,
    )


@router.get("/{download_id}/metadata")
async def get_download_metadata(
    download_id: str,
    request: Request,
    x_tenant_id: str = Header(alias="X-Tenant-ID", min_length=1, max_length=128),
) -> DownloadMetadataResponse:
    """Return full metadata for a download, excluding storage paths."""
    orchestrator = request.app.state.orchestrator
    try:
        record = await orchestrator.get_metadata(
            download_id=download_id, tenant_id=x_tenant_id
        )
    except DownloadSecurityError as exc:
        return _security_error_response(exc)

    analysis_job = await request.app.state.analysis_service.get_job_optional(
        download_id=download_id, tenant_id=x_tenant_id
    )

    return DownloadMetadataResponse(
        download_id=record.id,
        tenant_id=record.tenant_id,
        agent_id=record.agent_id,
        original_url=record.original_url,
        state=record.state.value,
        original_filename=record.original_filename,
        detected_mime_type=record.detected_mime_type,
        file_size=record.file_size,
        file_sha256=record.file_sha256,
        scan_result=record.scan_result,
        scan_detail=record.scan_detail,
        created_at=record.created_at,
        updated_at=record.updated_at,
        expires_at=record.expires_at,
        failure_reason=record.failure_reason,
        handoff_completed=record.handoff_completed,
        analysis_id=analysis_job.id if analysis_job else None,
        analysis_state=analysis_job.state.value if analysis_job else None,
        analysis_provider=analysis_job.provider if analysis_job else None,
    )


@router.post("/{download_id}/scan")
async def trigger_scan(
    download_id: str,
    request: Request,
    x_tenant_id: str = Header(alias="X-Tenant-ID", min_length=1, max_length=128),
) -> ScanStatusResponse:
    """
    Trigger a scan for a download in DOWNLOADED state.

    Idempotent: if the download has already progressed past DOWNLOADED,
    the current record is returned without error.
    """
    orchestrator = request.app.state.orchestrator
    try:
        record = await orchestrator.request_scan(
            download_id=download_id, tenant_id=x_tenant_id
        )
    except DownloadSecurityError as exc:
        return _security_error_response(exc)

    return ScanStatusResponse(
        download_id=record.id,
        state=record.state.value,
        scan_result=record.scan_result,
        scan_detail=record.scan_detail,
        message="Scan triggered." if record.state.value == "DOWNLOADED" else "Already processed.",
    )


# ── Document analysis ─────────────────────────────────────────────────────────

@router.post("/{download_id}/analysis", status_code=status.HTTP_202_ACCEPTED)
async def initiate_analysis(
    download_id: str,
    request: Request,
    x_tenant_id: str = Header(alias="X-Tenant-ID", min_length=1, max_length=128),
) -> AnalysisJobResponse:
    """
    Initiate document analysis for an APPROVED download.

    Idempotent per download: a second request returns the existing job
    (COMPLETED, RUNNING, or queued) instead of creating a duplicate.
    Quarantined, rejected, failed or in-flight downloads are refused.
    """
    service = request.app.state.analysis_service
    try:
        job = await service.request(download_id=download_id, tenant_id=x_tenant_id)
    except DownloadSecurityError as exc:
        return _security_error_response(exc)

    return AnalysisJobResponse.model_validate(job)


@router.get("/{download_id}/analysis")
async def get_analysis_status(
    download_id: str,
    request: Request,
    x_tenant_id: str = Header(alias="X-Tenant-ID", min_length=1, max_length=128),
) -> AnalysisJobResponse:
    """Return the analysis job state (never document content or results)."""
    service = request.app.state.analysis_service
    try:
        job = await service.get_job(
            download_id=download_id, tenant_id=x_tenant_id
        )
    except DownloadSecurityError as exc:
        return _security_error_response(exc)

    return AnalysisJobResponse.model_validate(job)


@router.get("/{download_id}/analysis/result")
async def get_analysis_result(
    download_id: str,
    request: Request,
    x_tenant_id: str = Header(alias="X-Tenant-ID", min_length=1, max_length=128),
) -> JSONResponse:
    """
    Return the normalized analysis result for a COMPLETED job.

    Analysis only runs on APPROVED files, so no quarantined or rejected
    document can ever be served here.
    """
    service = request.app.state.analysis_service
    try:
        job = await service.get_job(
            download_id=download_id, tenant_id=x_tenant_id
        )
    except DownloadSecurityError as exc:
        return _security_error_response(exc)

    if job.state is not AnalysisState.COMPLETED or not job.result_json:
        return _security_error_response(
            DownloadSecurityError(
                ANALYSIS_NOT_COMPLETED,
                f"Analysis is not complete (current state: {job.state.value}).",
                http_status=409,
            )
        )

    try:
        result = json.loads(job.result_json)
    except ValueError:
        logger.error(
            "analysis_result_unparseable",
            extra={"analysis_id": job.id, "tenant_id": job.tenant_id},
        )
        raise HTTPException(
            status_code=500, detail="Stored analysis result is unreadable."
        )

    return JSONResponse(status_code=200, content=result)


@router.post("/{download_id}/analysis/retry", status_code=status.HTTP_202_ACCEPTED)
async def retry_analysis(
    download_id: str,
    request: Request,
    x_tenant_id: str = Header(alias="X-Tenant-ID", min_length=1, max_length=128),
) -> AnalysisJobResponse:
    """Retry a FAILED analysis whose failure class is retryable."""
    service = request.app.state.analysis_service
    try:
        job = await service.retry(download_id=download_id, tenant_id=x_tenant_id)
    except DownloadSecurityError as exc:
        return _security_error_response(exc)

    return AnalysisJobResponse.model_validate(job)
