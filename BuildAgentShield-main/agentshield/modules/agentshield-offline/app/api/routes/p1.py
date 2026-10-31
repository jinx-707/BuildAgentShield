"""
AgentShield Offline — Person 1 Integration Health & Status Routes.

GET /offline/security/p1/health  — P1 engine availability and status
GET /offline/security/p1/config  — Active P1 feature flags (no secrets)
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_app_settings, get_p1_content_adapter, get_p1_data_adapter, verify_api_key

router = APIRouter(prefix="/security/p1", tags=["Person 1 Security Engine"])


@router.get("/health", summary="P1 security engine integration health")
async def p1_health(
    _key: Annotated[str, Depends(verify_api_key)],
) -> dict:
    settings = get_app_settings()

    # Check import availability without crashing
    p1_importable = False
    p1_version = "not_installed"
    try:
        from app.integrations.p1.p1_loader import ensure_p1_importable, load_p1_classes
        ensure_p1_importable()
        p1_importable = True
        # Try to get version from P1's config module
        try:
            classes = load_p1_classes()
            cfg_cls = classes.get("AgentShieldConfig")
            if cfg_cls:
                p1_version = "available"
        except Exception:
            pass
    except Exception:
        pass

    content_adapter = get_p1_content_adapter()
    data_adapter = get_p1_data_adapter()

    return {
        "p1_enabled": settings.p1_enabled,
        "p1_importable": p1_importable,
        "p1_version": p1_version,
        "p1_module_path": settings.p1_module_path or "(auto-detected)",
        "p1_fail_closed": settings.p1_fail_closed,
        "content_inspector_active": content_adapter is not None,
        "data_inspector_active": data_adapter is not None,
        "detectors_provided": [
            "injection_detector",
            "pii_detector",
            "secret_scanner",
            "dlp_engine",
            "risk_engine",
            "provenance_engine",
        ] if p1_importable else [],
        "note": (
            "P1 active — Person 1's SecurityEngine is providing injection, PII, secret, and DLP inspection."
            if (settings.p1_enabled and content_adapter is not None)
            else "P1 disabled or unavailable — local dev inspector active."
        ),
    }


@router.get("/config", summary="P1 active configuration (no secrets)")
async def p1_config(
    _key: Annotated[str, Depends(verify_api_key)],
) -> dict:
    settings = get_app_settings()
    return {
        "p1_enabled": settings.p1_enabled,
        "p1_fail_closed": settings.p1_fail_closed,
        "p1_module_path": settings.p1_module_path or "(auto-detected)",
        # Never include HMAC keys, PII model paths, or any secret values
    }
