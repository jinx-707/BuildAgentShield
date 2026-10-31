"""
AgentShield Offline — Document Analysis API Routes.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_runtime, verify_api_key
from app.core.contracts import BaseOfflineResponse, DocumentAnalysisRequest
from app.core.runtime import OfflineSecurityRuntime

router = APIRouter(prefix="/documents", tags=["Document Analysis"])


@router.post(
    "/analyze",
    response_model=BaseOfflineResponse,
    summary="Analyze a document securely",
    description=(
        "Validates, malware-scans, parses, and content-inspects a local document file. "
        "Extracted content is always treated as UNTRUSTED. "
        "Requires an authenticated agent security context."
    ),
)
async def analyze_document(
    request: DocumentAnalysisRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.analyze_document(request)
