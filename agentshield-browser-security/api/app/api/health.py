import logging

import httpx
from fastapi import APIRouter, Request, Response

from app import __version__
from app.clients.browser_worker import BrowserWorkerError
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)


@router.get("/health/live", response_model=HealthResponse)
async def live(request: Request) -> HealthResponse:
    settings = request.app.state.settings
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=__version__,
        checks={"process": "ok"},
    )


async def _check_proxy_health(health_url: str, timeout: float = 3.0) -> str:
    """Return 'ok', 'degraded', or 'unavailable'."""
    if not health_url:
        return "unconfigured"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(health_url)
        if not resp.is_success:
            return "unavailable"
        body = resp.json()
        if body.get("status") != "ok":
            return "degraded"
        if body.get("mode") and body["mode"] != "enforcing":
            return "degraded"
        return "ok"
    except Exception:
        return "unavailable"


@router.get(
    "/health",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse}},
    include_in_schema=False,
)
@router.get(
    "/health/ready",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse}},
)
async def ready(request: Request, response: Response) -> HealthResponse:
    settings = request.app.state.settings
    client = request.app.state.browser_client

    checks: dict[str, str] = {}
    degraded = False

    # Check worker readiness
    try:
        worker_health = await client.health_ready()
        checks["browser_worker"] = "ok" if worker_health.status == "ok" else "degraded"
        if worker_health.status != "ok":
            degraded = True
    except BrowserWorkerError as exc:
        logger.warning(
            "browser_worker_readiness_check_failed",
            extra={"error": str(exc), "error_type": type(exc).__name__},
        )
        checks["browser_worker"] = "unavailable"
        degraded = True
        detail_override = "browser worker readiness check failed"

    # Check proxy health when configured
    if settings.require_egress_proxy and settings.egress_proxy_health_url:
        proxy_status = await _check_proxy_health(
            settings.egress_proxy_health_url,
            timeout=settings.browser_worker_health_timeout_seconds,
        )
        checks["egress_proxy"] = proxy_status
        if proxy_status != "ok":
            degraded = True
            logger.warning(
                "egress_proxy_readiness_check_failed",
                extra={"status": proxy_status, "url": settings.egress_proxy_health_url},
            )

    if degraded:
        response.status_code = 503
        detail = locals().get("detail_override", "one or more required dependencies are not ready")
        return HealthResponse(
            status="degraded",
            service=settings.app_name,
            version=__version__,
            checks=checks,
            detail=detail,
        )

    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=__version__,
        checks=checks,
    )
