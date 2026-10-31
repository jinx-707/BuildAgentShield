import logging

from fastapi import APIRouter, HTTPException, Path, Request, Response

from app.clients.browser_worker import (
    BrowserWorkerPolicyError,
    BrowserWorkerResponseError,
    BrowserWorkerTimeout,
    BrowserWorkerUnavailable,
)
from app.clients.search_provider import (
    SearchProviderAuthError,
    SearchProviderError,
    SearchProviderNotConfigured,
    SearchProviderRateLimited,
    SearchProviderResponseError,
    SearchProviderTimeout,
    SearchProviderUnavailable,
)
from app.middleware import AGENT_ID_HEADER, enforce_category_rate_limit
from app.schemas.action import ActionResponse, BrowserActionRequest
from app.schemas.browser import (
    SESSION_ID_PATTERN,
    BrowserNavigateRequest,
    BrowserNavigateResponse,
)
from app.schemas.extract import ExtractRequest, ExtractResponse
from app.schemas.screenshot import ScreenshotRequest
from app.schemas.search import SearchRequest, SearchResponse
from app.schemas.session import SessionCreateRequest, SessionCloseResponse, SessionStatus
from app.security.errors import SecurityViolation
from app.services.action_service import ActionService
from app.services.extract_service import ExtractService
from app.services.identity import (
    InvalidAgentIdError,
    parse_agent_id,
    parse_optional_agent_id,
)
from app.services.orchestrator import (
    BrowserSecurityOrchestrator,
    PolicyDeniedError,
    RedirectDestinationBlockedError,
)
from app.services.screenshot_service import ScreenshotService
from app.services.search_orchestrator import SearchOrchestrator
from app.services.session_service import SessionService

router = APIRouter(prefix="/v1/browser", tags=["browser"])
logger = logging.getLogger(__name__)


def _required_agent_id(request: Request) -> str:
    try:
        return parse_agent_id(request.headers.get(AGENT_ID_HEADER))
    except InvalidAgentIdError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def _optional_agent_id(request: Request) -> str | None:
    try:
        return parse_optional_agent_id(request.headers.get(AGENT_ID_HEADER))
    except InvalidAgentIdError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


def _raise_worker_policy_error(exc: BrowserWorkerPolicyError) -> None:
    if exc.status_code == 401:
        raise HTTPException(
            status_code=502,
            detail={
                "code": "WORKER_AUTH_FAILED",
                "message": "The browser worker rejected the API credentials.",
            },
        ) from exc

    status_map = {
        400: 400,
        403: 403,
        404: 404,
        409: 409,
        413: 413,
        422: 422,
        429: 429,
        502: 502,
        503: 503,
        504: 504,
    }
    status_code = status_map.get(exc.status_code, 403)
    raise HTTPException(
        status_code=status_code,
        detail={"code": exc.code, "message": exc.message},
    ) from exc


def _raise_worker_failure(exc: Exception) -> None:
    if isinstance(exc, BrowserWorkerTimeout):
        logger.warning("browser_worker_timeout", extra={"error": str(exc)})
        raise HTTPException(
            status_code=504,
            detail={"code": "browser_worker_timeout", "message": str(exc)},
        ) from exc
    if isinstance(exc, (BrowserWorkerUnavailable, BrowserWorkerResponseError)):
        logger.warning(
            "browser_worker_failure",
            extra={"error": str(exc), "error_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=502,
            detail={"code": "browser_worker_failure", "message": str(exc)},
        ) from exc
    raise exc


@router.post("/navigate", response_model=BrowserNavigateResponse)
async def navigate(
    payload: BrowserNavigateRequest, request: Request
) -> BrowserNavigateResponse:
    orchestrator = BrowserSecurityOrchestrator(
        policy_engine=request.app.state.policy_engine,
        content_inspector=request.app.state.content_inspector,
        worker_client=request.app.state.browser_client,
        network_preflight=request.app.state.network_preflight,
    )
    request_id = request.state.request_id
    agent_id = _optional_agent_id(request)
    await enforce_category_rate_limit(
        request, "navigation", session_id=payload.session_id
    )

    try:
        return await orchestrator.navigate(
            payload, request_id=request_id, agent_id=agent_id
        )
    except SecurityViolation as exc:
        logger.info(
            "browser_navigation_blocked",
            extra={"code": exc.code, "reason": exc.message},
        )
        raise HTTPException(
            status_code=exc.http_status,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    except PolicyDeniedError as exc:
        logger.info(
            "browser_navigation_denied",
            extra={"policy_name": exc.policy_name, "reason": exc.reason},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "code": "policy_denied",
                "message": exc.reason,
                "policy_name": exc.policy_name,
            },
        ) from exc
    except RedirectDestinationBlockedError as exc:
        logger.warning(
            "redirect_destination_blocked",
            extra={"final_url": exc.final_url},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "code": "REDIRECT_DESTINATION_BLOCKED",
                "message": str(exc),
            },
        ) from exc
    except BrowserWorkerPolicyError as exc:
        logger.info(
            "browser_worker_navigation_blocked",
            extra={"code": exc.code, "worker_status": exc.status_code},
        )
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.post("/session", response_model=SessionStatus, status_code=201)
async def create_session(
    request: Request, payload: SessionCreateRequest | None = None
) -> SessionStatus:
    agent_id = _required_agent_id(request)
    await enforce_category_rate_limit(request, "session_create")
    service = SessionService(request.app.state.browser_client)
    try:
        return await service.create(
            payload or SessionCreateRequest(),
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
    except BrowserWorkerPolicyError as exc:
        logger.info(
            "browser_session_create_refused",
            extra={"code": exc.code, "worker_status": exc.status_code},
        )
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.get("/session/{session_id}", response_model=SessionStatus)
async def get_session(
    request: Request,
    session_id: str = Path(pattern=SESSION_ID_PATTERN),
) -> SessionStatus:
    agent_id = _required_agent_id(request)
    service = SessionService(request.app.state.browser_client)
    try:
        return await service.get(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
    except BrowserWorkerPolicyError as exc:
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.delete("/session/{session_id}", response_model=SessionCloseResponse)
async def close_session(
    request: Request,
    session_id: str = Path(pattern=SESSION_ID_PATTERN),
) -> SessionCloseResponse:
    agent_id = _required_agent_id(request)
    service = SessionService(request.app.state.browser_client)
    try:
        return await service.close(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
    except BrowserWorkerPolicyError as exc:
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.post("/action", response_model=ActionResponse)
async def action(
    payload: BrowserActionRequest, request: Request
) -> ActionResponse:
    agent_id = _required_agent_id(request)
    await enforce_category_rate_limit(request, "action", session_id=payload.session_id)
    service = ActionService(
        request.app.state.browser_client,
        request.app.state.content_inspector,
    )
    try:
        return await service.act(
            payload,
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
    except BrowserWorkerPolicyError as exc:
        logger.info(
            "browser_action_refused",
            extra={"code": exc.code, "worker_status": exc.status_code},
        )
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.post("/screenshot")
async def screenshot(payload: ScreenshotRequest, request: Request) -> Response:
    agent_id = _required_agent_id(request)
    await enforce_category_rate_limit(
        request, "screenshot", session_id=payload.session_id
    )
    service = ScreenshotService(request.app.state.browser_client)
    try:
        result = await service.capture(
            payload,
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
    except BrowserWorkerPolicyError as exc:
        logger.info(
            "browser_screenshot_refused",
            extra={"code": exc.code, "worker_status": exc.status_code},
        )
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)

    return Response(
        content=result.content,
        media_type="image/png",
        headers={
            "Content-Disposition": 'inline; filename="screenshot.png"',
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "X-Screenshot-Width": str(result.width),
            "X-Screenshot-Height": str(result.height),
            "X-Screenshot-Bytes": str(result.bytes),
            "X-Screenshot-Full-Page": "true" if result.full_page else "false",
            "X-Screenshot-Elapsed-Ms": str(result.elapsed_ms),
        },
    )


@router.post("/extract", response_model=ExtractResponse)
async def extract(payload: ExtractRequest, request: Request) -> ExtractResponse:
    agent_id = _required_agent_id(request)
    await enforce_category_rate_limit(
        request, "extract", session_id=payload.session_id
    )
    service = ExtractService(
        request.app.state.browser_client,
        request.app.state.content_inspector,
    )
    try:
        return await service.extract(
            payload,
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
    except BrowserWorkerPolicyError as exc:
        logger.info(
            "browser_extract_refused",
            extra={"code": exc.code, "worker_status": exc.status_code},
        )
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.post("/search", response_model=SearchResponse)
async def search(payload: SearchRequest, request: Request) -> SearchResponse:
    await enforce_category_rate_limit(request, "search")
    settings = request.app.state.settings
    orchestrator = SearchOrchestrator(
        provider=request.app.state.search_provider,
        network_preflight=request.app.state.network_preflight,
        policy_engine=request.app.state.policy_engine,
        content_inspector=request.app.state.content_inspector,
        max_results=settings.search_max_results,
    )
    try:
        return await orchestrator.search(
            payload, request_id=request.state.request_id
        )
    except SearchProviderNotConfigured as exc:
        logger.warning("search_provider_not_configured")
        raise HTTPException(
            status_code=503,
            detail={"code": "SEARCH_NOT_CONFIGURED", "message": str(exc)},
        ) from exc
    except SearchProviderTimeout as exc:
        logger.warning("search_provider_timeout")
        raise HTTPException(
            status_code=504,
            detail={"code": "SEARCH_PROVIDER_TIMEOUT", "message": str(exc)},
        ) from exc
    except SearchProviderRateLimited as exc:
        logger.warning("search_provider_rate_limited")
        headers = (
            {"Retry-After": str(exc.retry_after)}
            if exc.retry_after is not None
            else None
        )
        raise HTTPException(
            status_code=429,
            detail={"code": "SEARCH_PROVIDER_RATE_LIMITED", "message": str(exc)},
            headers=headers,
        ) from exc
    except SearchProviderAuthError as exc:
        logger.warning("search_provider_auth_failed")
        raise HTTPException(
            status_code=502,
            detail={"code": "SEARCH_PROVIDER_AUTH_FAILED", "message": str(exc)},
        ) from exc
    except SearchProviderUnavailable as exc:
        logger.warning("search_provider_unavailable")
        raise HTTPException(
            status_code=503,
            detail={"code": "SEARCH_PROVIDER_UNAVAILABLE", "message": str(exc)},
        ) from exc
    except SearchProviderResponseError as exc:
        logger.warning("search_provider_invalid_response")
        raise HTTPException(
            status_code=502,
            detail={"code": "SEARCH_PROVIDER_INVALID_RESPONSE", "message": str(exc)},
        ) from exc
    except SearchProviderError as exc:
        logger.warning("search_provider_error")
        raise HTTPException(
            status_code=502,
            detail={"code": "SEARCH_PROVIDER_ERROR", "message": str(exc)},
        ) from exc
