"""
AgentShield Offline — NeMo Guardrails Health & Status Routes.

GET /offline/security/nemo/health   — runtime health of the NeMo integration
GET /offline/security/nemo/config   — active configuration (no secrets)

These endpoints are safe to expose to operators. They never return:
  - API keys or model credentials
  - Document contents or terminal output
  - Sensitive filesystem paths
  - Secret values of any kind
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_app_settings, get_nemo_engine, verify_api_key
from app.integrations.nemo.nemo_health import get_nemo_health

router = APIRouter(prefix="/security/nemo", tags=["NeMo Guardrails"])


@router.get(
    "/health",
    summary="NeMo Guardrails integration health",
    description=(
        "Returns the health and configuration status of the NeMo Guardrails integration. "
        "Safe for operators — never includes credentials or content."
    ),
)
async def nemo_health(
    _key: Annotated[str, Depends(verify_api_key)],
) -> dict:
    engine = get_nemo_engine()
    settings = get_app_settings()
    health = get_nemo_health(engine)
    health["inspect_documents"] = settings.nemo_inspect_documents
    health["inspect_terminal_output"] = settings.nemo_inspect_terminal_output
    health["max_content_chars"] = settings.nemo_max_content_chars
    return health


@router.get(
    "/config",
    summary="NeMo active configuration (no secrets)",
    description="Returns the active NeMo profile and feature flags — no credentials included.",
)
async def nemo_config(
    _key: Annotated[str, Depends(verify_api_key)],
) -> dict:
    settings = get_app_settings()
    return {
        "nemo_enabled": settings.nemo_enabled,
        "profile": settings.nemo_profile,
        "config_path": settings.nemo_config_path,
        "timeout_seconds": settings.nemo_timeout,
        "fail_closed": settings.nemo_fail_closed,
        "inspect_documents": settings.nemo_inspect_documents,
        "inspect_terminal_output": settings.nemo_inspect_terminal_output,
        "max_content_chars": settings.nemo_max_content_chars,
        "telemetry_disabled": settings.nemo_telemetry_disabled,
        # Never include: model provider URLs, API keys, or any secret values
    }
