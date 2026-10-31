"""
AgentShield Offline — System File Access API Routes.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_runtime, verify_api_key
from app.core.contracts import BaseOfflineResponse, SystemFileInspectRequest
from app.core.runtime import OfflineSecurityRuntime

router = APIRouter(prefix="/system", tags=["System File Protection"])


@router.post(
    "/inspect",
    response_model=BaseOfflineResponse,
    summary="Inspect a system path",
    description=(
        "Checks whether a given path is a protected system resource. "
        "Access to protected OS paths is always denied."
    ),
)
async def inspect_system_path(
    request: SystemFileInspectRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.inspect_system_path(request)
