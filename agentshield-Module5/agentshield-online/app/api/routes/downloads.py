"""Downloads API routes."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.dependencies import AuthContext
from app.capabilities.online.downloads.download_gateway import DownloadGateway
from app.core.configuration import get_settings
from app.core.contracts import GatewayResponse
from app.core.runtime import runtime
from app.core.security_context import build_security_context

router = APIRouter(prefix="/downloads", tags=["downloads"])


def _get_gateway() -> DownloadGateway:
    settings = get_settings()
    return DownloadGateway.from_config(
        policy=runtime.policy,
        audit=runtime.audit,
        use_mock_scanner=settings.app_env == "development",
        base_dir=settings.download_base_dir,
        quarantine_dir=settings.quarantine_base_dir,
        clamav_host=settings.clamav_host,
        clamav_port=settings.clamav_port,
        fail_closed=settings.clamav_fail_closed,
    )


class DownloadRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    filename: str | None = None


@router.post("/request", response_model=GatewayResponse)
async def request_download(body: DownloadRequest, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="downloads", operation="request", resource=body.url,
    )
    return await _get_gateway().request_download(ctx=ctx, url=body.url, filename=body.filename)


@router.get("/{download_id}/status", response_model=GatewayResponse)
async def download_status(download_id: str, auth: AuthContext):
    ctx = build_security_context(
        agent_id=auth.agent_id, tenant_id=auth.tenant_id,
        capability="downloads", operation="status", resource=download_id,
    )
    return await _get_gateway().get_status(ctx=ctx, download_id=download_id)
