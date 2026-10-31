"""
AgentShield Offline — Environment & Secret Protection API Routes.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_runtime, verify_api_key
from app.core.contracts import BaseOfflineResponse, EnvironmentInspectRequest, SecretAccessRequest
from app.core.runtime import OfflineSecurityRuntime

router = APIRouter(prefix="/environment", tags=["Environment Protection"])


@router.post(
    "/inspect",
    response_model=BaseOfflineResponse,
    summary="Inspect environment variable accessibility",
    description=(
        "Checks which of the requested environment variables are permitted. "
        "NEVER returns variable values — only access decisions. "
        "Host secrets are never exposed."
    ),
)
async def inspect_environment(
    request: EnvironmentInspectRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.inspect_environment(request)


@router.post(
    "/secret",
    response_model=BaseOfflineResponse,
    summary="Request a secret via the broker",
    description=(
        "Retrieves a secret through the permission-gated broker. "
        "The secret value is NEVER included in the API response."
    ),
)
async def access_secret(
    request: SecretAccessRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.access_secret(request)
