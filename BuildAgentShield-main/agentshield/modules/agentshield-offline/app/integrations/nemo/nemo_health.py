"""
AgentShield Offline — NeMo health and capability reporting.

Returns safe status information for the health endpoint.
Never exposes API keys, credentials, file contents or config secrets.
"""

from __future__ import annotations

from typing import Any, Optional

import structlog

log = structlog.get_logger(__name__)


def get_nemo_health(engine: Optional[Any]) -> dict:
    """
    Return NeMo health status for the /offline/security/nemo/health endpoint.
    Safe to return to callers — no secrets included.
    """
    if engine is None:
        return {
            "nemo_enabled": False,
            "nemo_status": "disabled",
            "message": "NeMo Guardrails is disabled. Set AGENTSHIELD_NEMO_ENABLED=true to enable.",
        }

    status = engine.status()

    # Check package install status
    try:
        import nemoguardrails  # type: ignore[import]
        pkg_installed = True
        pkg_version = nemoguardrails.__version__
    except ImportError:
        pkg_installed = False
        pkg_version = None

    return {
        "nemo_enabled": status.get("enabled", False),
        "nemo_status": "ready" if status.get("initialized") else "not_initialized",
        "package_installed": pkg_installed,
        "package_version": pkg_version,
        "profile": status.get("profile"),
        "config_loaded": status.get("initialized", False),
        "init_error": status.get("init_error"),
        "timeout_seconds": status.get("timeout_seconds"),
        "fail_closed": status.get("fail_closed"),
        "telemetry_disabled": status.get("telemetry_disabled"),
        "inspect_documents": None,  # populated by caller from settings
        "inspect_terminal_output": None,
        # Active rail types would require a config introspection call;
        # omit here to avoid triggering initialisation side effects
        "active_rail_types": _probe_configured_rails(engine),
    }


def _probe_configured_rails(engine: Any) -> list[str]:
    """
    Return a list of configured rail type names without running any content.
    Returns an empty list if the engine is not initialised or NeMo is absent.
    """
    if not engine.is_available():
        return []
    try:
        rails = engine._rails
        if rails is None:
            return []
        config = getattr(rails, "config", None)
        if config is None:
            return []
        configured = []
        if getattr(config, "input_flows", None):
            configured.append("input")
        if getattr(config, "output_flows", None):
            configured.append("output")
        # Fallback: check rails attribute names
        if not configured:
            for attr in ("rails",):
                r = getattr(config, attr, None)
                if r:
                    if getattr(r, "input", None):
                        configured.append("input")
                    if getattr(r, "output", None):
                        configured.append("output")
        return configured
    except Exception:  # noqa: BLE001
        return []
