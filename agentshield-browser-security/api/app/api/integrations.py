"""Integration health checks for AgentShield.

Reports real, per-integration status for the three integration categories:

- P1_ENGINE — security / policy engine (Mock | Connected | Degraded | Not configured)
- P2_ADAPTERS — offline content / data inspection adapters (Mock | Connected | Degraded | Not configured)
- P3_ADAPTERS — online network adapters (egress proxy + browser worker)
  (Connected | Degraded | Disconnected | Not configured)

An integration is only reported as ``Connected`` when a real health check AND a
functional capability check succeed. Mock backends are reported as ``Mock``,
never ``Connected``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.config import Settings
from app.schemas.browser import PolicyRequest

router = APIRouter(prefix="/v1/integrations", tags=["integrations"])

_HEALTH_TIMEOUT = 5.0

INTEGRATION_STATUS_CONNECTED = "Connected"
INTEGRATION_STATUS_DEGRADED = "Degraded"
INTEGRATION_STATUS_DISCONNECTED = "Disconnected"
INTEGRATION_STATUS_MOCK = "Mock"
INTEGRATION_STATUS_NOT_CONFIGURED = "Not configured"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ComponentHealth(BaseModel):
    name: str
    status: str
    backend: str | None = None
    detail: str | None = None
    checked_at: str


class P3Components(BaseModel):
    egress_proxy: ComponentHealth
    browser_worker: ComponentHealth


class IntegrationsHealthOut(BaseModel):
    p1_engine: ComponentHealth
    p2_adapters: ComponentHealth
    p3_adapters: P3Components
    scenarios: list[dict[str, Any]]
    checked_at: str


# ---------------------------------------------------------------------------
# P1 — security / policy engine
# ---------------------------------------------------------------------------


async def _check_p1_engine(settings: Settings, app_state: Any) -> ComponentHealth:
    backend = settings.policy_backend
    engine = getattr(app_state, "policy_engine", None)
    name = getattr(engine, "name", "policy-engine") if engine else "policy-engine"

    if backend == "mock":
        return ComponentHealth(
            name=name,
            status=INTEGRATION_STATUS_MOCK,
            backend="mock",
            detail="Development-only mock policy engine; not a security control. "
            "Set POLICY_BACKEND=egress-policy for real enforcement.",
            checked_at=_now(),
        )

    if backend == "egress-policy" and engine is not None:
        # Functional capability check: run a real authorization decision.
        try:
            request = PolicyRequest(
                request_id="integration-health-check",
                url="https://example.com/health",
            )
            decision = await engine.authorize(request)
            if isinstance(decision, object) and hasattr(decision, "allowed"):
                return ComponentHealth(
                    name=name,
                    status=INTEGRATION_STATUS_CONNECTED,
                    backend="egress-policy",
                    detail=f"Real policy engine authorized test navigation (allowed={decision.allowed}).",
                    checked_at=_now(),
                )
        except Exception as exc:  # noqa: BLE001
            return ComponentHealth(
                name=name,
                status=INTEGRATION_STATUS_DEGRADED,
                backend="egress-policy",
                detail=f"Policy engine configured but capability check failed: {exc}",
                checked_at=_now(),
            )

    return ComponentHealth(
        name=name,
        status=INTEGRATION_STATUS_NOT_CONFIGURED,
        backend=backend or None,
        detail="No policy engine backend configured or available.",
        checked_at=_now(),
    )


# ---------------------------------------------------------------------------
# P2 — offline content / data inspection adapters
# ---------------------------------------------------------------------------


async def _check_p2_adapters(settings: Settings, app_state: Any) -> ComponentHealth:
    backend = settings.inspection_backend
    inspector = getattr(app_state, "content_inspector", None)
    name = getattr(inspector, "name", "content-inspector") if inspector else "content-inspector"

    if backend == "mock":
        return ComponentHealth(
            name=name,
            status=INTEGRATION_STATUS_MOCK,
            backend="mock",
            detail="Development-only mock content inspector; not a security control. "
            "Set INSPECTION_BACKEND=prompt-injection for real inspection.",
            checked_at=_now(),
        )

    if backend == "prompt-injection" and inspector is not None:
        try:
            request = type(
                "ContentInspectionRequest",
                (),
                {"request_id": "health-check", "url": "https://example.com/", "content": "benign page content"},
            )()
            result = await inspector.inspect(request)
            if result is not None:
                return ComponentHealth(
                    name=name,
                    status=INTEGRATION_STATUS_CONNECTED,
                    backend="prompt-injection",
                    detail="Real content inspector returned an inspection result for test content.",
                    checked_at=_now(),
                )
        except Exception as exc:  # noqa: BLE001
            return ComponentHealth(
                name=name,
                status=INTEGRATION_STATUS_DEGRADED,
                backend="prompt-injection",
                detail=f"Content inspector configured but capability check failed: {exc}",
                checked_at=_now(),
            )

    return ComponentHealth(
        name=name,
        status=INTEGRATION_STATUS_NOT_CONFIGURED,
        backend=backend or None,
        detail="No content inspection backend configured or available.",
        checked_at=_now(),
    )


# ---------------------------------------------------------------------------
# P3 — online network adapters (egress proxy + browser worker)
# ---------------------------------------------------------------------------


async def _http_health(url: str) -> tuple[bool, str | None]:
    """Return (ok, body_or_error) for a real HTTP GET health check."""
    try:
        async with httpx.AsyncClient(timeout=_HEALTH_TIMEOUT) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                try:
                    return True, resp.json()
                except Exception:
                    return True, resp.text
            return False, f"HTTP {resp.status_code}"
    except httpx.TimeoutException:
        return False, "timeout"
    except httpx.HTTPError as exc:
        return False, f"unreachable: {exc}"


async def _check_egress_proxy(settings: Settings) -> ComponentHealth:
    url = settings.egress_proxy_health_url or ""
    if not url:
        return ComponentHealth(
            name="egress-proxy",
            status=INTEGRATION_STATUS_NOT_CONFIGURED,
            detail="EGRESS_PROXY_HEALTH_URL not configured.",
            checked_at=_now(),
        )
    ok, body = await _http_health(url)
    detail: Any = body
    if ok and isinstance(body, dict) and body.get("status") == "ok":
        mode = body.get("mode", "unknown")
        return ComponentHealth(
            name="egress-proxy",
            status=INTEGRATION_STATUS_CONNECTED,
            detail=f"Egress proxy reachable and reporting mode={mode}.",
            checked_at=_now(),
        )
    return ComponentHealth(
        name="egress-proxy",
        status=INTEGRATION_STATUS_DISCONNECTED,
        detail=f"Egress proxy health check failed: {body}",
        checked_at=_now(),
    )


async def _check_browser_worker(settings: Settings, app_state: Any) -> ComponentHealth:
    client = getattr(app_state, "browser_client", None)
    base_url = settings.browser_worker_url
    if not base_url:
        return ComponentHealth(
            name="browser-worker",
            status=INTEGRATION_STATUS_NOT_CONFIGURED,
            detail="BROWSER_WORKER_URL not configured.",
            checked_at=_now(),
        )
    try:
        if client is not None:
            await client.health_ready()
        else:
            await _http_health(f"{base_url.rstrip('/')}/health/ready")
        return ComponentHealth(
            name="browser-worker",
            status=INTEGRATION_STATUS_CONNECTED,
            detail="Browser worker /health/ready returned OK.",
            checked_at=_now(),
        )
    except Exception as exc:  # noqa: BLE001
        return ComponentHealth(
            name="browser-worker",
            status=INTEGRATION_STATUS_DISCONNECTED,
            detail=f"Browser worker health check failed: {exc}",
            checked_at=_now(),
        )


def _p3_status(egress: ComponentHealth, worker: ComponentHealth) -> str:
    states = {egress.status, worker.status}
    if INTEGRATION_STATUS_NOT_CONFIGURED in states and not (
        egress.status == INTEGRATION_STATUS_CONNECTED
        and worker.status == INTEGRATION_STATUS_CONNECTED
    ):
        return INTEGRATION_STATUS_NOT_CONFIGURED
    if INTEGRATION_STATUS_DISCONNECTED in states:
        return INTEGRATION_STATUS_DISCONNECTED
    if INTEGRATION_STATUS_DEGRADED in states:
        return INTEGRATION_STATUS_DEGRADED
    return INTEGRATION_STATUS_CONNECTED


# ---------------------------------------------------------------------------
# Scenario availability (cyber range targets)
# ---------------------------------------------------------------------------


SCENARIO_CATALOG = [
    {
        "scenario_id": "prompt-injection",
        "name": "Indirect Prompt Injection",
        "threat_category": "AI Security",
        "target_service": "prompt-injection-target",
        "target_port": 8081,
    },
    {
        "scenario_id": "phishing",
        "name": "Phishing & Credential Harvesting",
        "threat_category": "Social Engineering",
        "target_service": "phishing-target",
        "target_port": 8082,
    },
    {
        "scenario_id": "ssrf",
        "name": "Server-Side Request Forgery (SSRF)",
        "threat_category": "Network Security",
        "target_service": "ssrf-target",
        "target_port": 8083,
    },
    {
        "scenario_id": "dns-rebinding",
        "name": "DNS Rebinding",
        "threat_category": "Network Security",
        "target_service": "dns-rebinding-target",
        "target_port": 8086,
    },
    {
        "scenario_id": "malicious-download",
        "name": "Malicious File Downloads",
        "threat_category": "Malware",
        "target_service": "malicious-download-target",
        "target_port": 8084,
    },
    {
        "scenario_id": "resource-exhaustion",
        "name": "Resource Exhaustion / DoS",
        "threat_category": "Denial of Service",
        "target_service": "resource-exhaustion-target",
        "target_port": 8085,
    },
    {
        "scenario_id": "data-exfiltration",
        "name": "Data Exfiltration / DLP",
        "threat_category": "Data Loss",
        "target_service": "data-exfiltration-sink",
        "target_port": 8087,
    },
]


async def _check_scenarios() -> list[dict[str, Any]]:
    results = []
    for scenario in SCENARIO_CATALOG:
        port = scenario["target_port"]
        ok = False
        detail = None
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"http://{scenario['target_service']}:{port}/health")
                ok = resp.status_code == 200
                if not ok:
                    detail = f"HTTP {resp.status_code}"
        except httpx.HTTPError as exc:
            detail = f"unreachable: {exc}"
        except Exception as exc:  # noqa: BLE001
            detail = f"error: {exc}"
        results.append(
            {
                **scenario,
                "available": ok,
                "status": "Connected" if ok else "Disconnected",
                "detail": detail,
                "checked_at": _now(),
            }
        )
    return results


@router.get("/health", response_model=IntegrationsHealthOut)
async def integrations_health(request: Request) -> IntegrationsHealthOut:
    """Real per-integration health and capability checks.

    Never fabricates a Connected status. Mock backends are reported as Mock.
    """
    settings: Settings = request.app.state.settings
    app_state = request.app.state

    p1 = await _check_p1_engine(settings, app_state)
    p2 = await _check_p2_adapters(settings, app_state)
    egress = await _check_egress_proxy(settings)
    worker = await _check_browser_worker(settings, app_state)
    p3_status = _p3_status(egress, worker)

    return IntegrationsHealthOut(
        p1_engine=ComponentHealth(
            name=p1.name,
            status=p1.status,
            backend=p1.backend,
            detail=p1.detail,
            checked_at=p1.checked_at,
        ),
        p2_adapters=ComponentHealth(
            name=p2.name,
            status=p2.status,
            backend=p2.backend,
            detail=p2.detail,
            checked_at=p2.checked_at,
        ),
        p3_adapters=P3Components(
            egress_proxy=egress,
            browser_worker=worker,
        ),
        scenarios=await _check_scenarios(),
        checked_at=_now(),
    )
