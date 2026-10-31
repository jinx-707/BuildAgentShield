"""
AgentShield Offline — Terminal Execution API Routes.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_runtime, verify_api_key
from app.core.contracts import BaseOfflineResponse, CommandRequest
from app.core.runtime import OfflineSecurityRuntime

router = APIRouter(prefix="/terminal", tags=["Terminal Execution"])


@router.post(
    "/execute",
    response_model=BaseOfflineResponse,
    summary="Execute a command in the secure sandbox",
    description=(
        "Executes a structured command request in an isolated Docker sandbox. "
        "Commands must be structured (executable + arguments array), NOT raw shell strings. "
        "Denied commands and sandbox failures never fall back to host execution. "
        "Output is inspected and redacted before delivery."
    ),
)
async def execute_command(
    request: CommandRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.execute_command(request)
