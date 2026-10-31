import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status

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
from app.db.models import Agent
from app.enterprise.deps import (
    get_current_principal_optional,
    get_db,
    Principal,
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
from app.services.audit import AuditStore
from app.services.capability_service import CapabilityService
from app.services.extract_service import ExtractService
from app.services.identity import (
    InvalidAgentIdError,
    parse_agent_id,
)
from app.services.orchestrator import (
    BrowserSecurityOrchestrator,
    PolicyDeniedError,
    RedirectDestinationBlockedError,
)
from app.services.screenshot_service import ScreenshotService
from app.services.search_orchestrator import SearchOrchestrator
from app.services.session_service import SessionService
from sqlalchemy.orm import Session

router = APIRouter(prefix="/v1/browser", tags=["browser"])
logger = logging.getLogger(__name__)


def _resolve_agent_id(
    request: Request,
    db: Session | None,
    principal: Principal | None = None,
    *,
    required: bool = False,
) -> str | None:
    """Resolve the X-Agent-ID agent and enforce organization membership.

    Returns the validated agent_id string, or None when no X-Agent-ID header is
    present and no enterprise principal requires one.

    When an enterprise principal is present, the agent must exist in the
    database and belong to the principal's organization (tenant isolation). When
    no principal is present (legacy API_AUTH_TOKEN mode), the raw X-Agent-ID
    value is used directly without database validation, preserving existing
    browser API behavior.

    When ``required`` is true (session/action/screenshot/extract endpoints), a
    missing X-Agent-ID is rejected with 400. Navigation allows it to be absent.
    """
    raw_agent_id = request.headers.get(AGENT_ID_HEADER)
    if not raw_agent_id:
        if principal is not None:
            raise HTTPException(
                status_code=401,
                detail={"code": "AGENT_ID_REQUIRED", "message": "X-Agent-ID is required"},
            )
        if required:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "INVALID_AGENT_ID",
                    "message": "agent id is required for session operations",
                },
            )
        return None
    try:
        agent_id = parse_agent_id(raw_agent_id)
    except InvalidAgentIdError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc

    # Legacy mode (no principal): accept the caller-supplied agent id directly.
    if principal is None or db is None:
        return agent_id

    # Enterprise mode: validate the agent exists and belongs to the org.
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        raise HTTPException(
            status_code=404,
            detail={"code": "AGENT_NOT_FOUND", "message": "agent not found"},
        )
    if str(agent.organization_id) != principal.organization_id:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "CROSS_TENANT_ACCESS",
                "message": "agent does not belong to your organization",
            },
        )
    if agent.status != "active":
        raise HTTPException(
            status_code=403,
            detail={"code": "AGENT_INACTIVE", "message": "agent is not active"},
        )
    return agent.agent_id


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
    payload: BrowserNavigateRequest,
    request: Request,
    db: Optional[Session] = Depends(get_db),
    principal: Principal | None = Depends(get_current_principal_optional),
) -> BrowserNavigateResponse:
    agent_id = _resolve_agent_id(request, db, principal)
    orchestrator = BrowserSecurityOrchestrator(
        policy_engine=request.app.state.policy_engine,
        content_inspector=request.app.state.content_inspector,
        worker_client=request.app.state.browser_client,
        network_preflight=request.app.state.network_preflight,
    )
    request_id = request.state.request_id
    await enforce_category_rate_limit(
        request, "navigation", session_id=payload.session_id
    )

    try:
        result = await orchestrator.navigate(
            payload,
            request_id=request_id,
            agent_id=agent_id,
            organization_id=principal.organization_id if principal else None,
        )
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="navigation.allow",
            actor=agent_id,
            target=result.final_url,
            decision="allow",
            reason="navigation permitted by policy",
            request_id=request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
        )
        return result
    except SecurityViolation as exc:
        logger.info(
            "browser_navigation_blocked",
            extra={"code": exc.code, "reason": exc.message},
        )
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="navigation.deny",
            actor=agent_id,
            target=str(payload.url),
            decision="deny",
            reason=exc.message,
            request_id=request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
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
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="navigation.deny",
            actor=agent_id,
            target=str(payload.url),
            decision="deny",
            reason=exc.reason,
            request_id=request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
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
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="navigation.blocked_redirect",
            actor=agent_id,
            target=exc.final_url,
            decision="deny",
            reason="redirect destination blocked by policy",
            request_id=request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
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
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="navigation.deny",
            actor=agent_id,
            target=str(payload.url),
            decision="deny",
            reason=exc.message,
            request_id=request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
        )
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.post("/session", response_model=SessionStatus, status_code=201)
async def create_session(
    request: Request,
    payload: SessionCreateRequest | None = None,
    db: Optional[Session] = Depends(get_db),
    principal: Principal | None = Depends(get_current_principal_optional),
) -> SessionStatus:
    agent_id = _resolve_agent_id(request, db, principal, required=True)
    await enforce_category_rate_limit(request, "session_create")
    service = SessionService(request.app.state.browser_client)
    try:
        result = await service.create(
            payload or SessionCreateRequest(),
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="session.create",
            actor=agent_id,
            session_id=result.session_id,
            decision="allow",
            reason="session created",
            request_id=request.state.request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
        )
        return result
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
    db: Optional[Session] = Depends(get_db),
    principal: Principal | None = Depends(get_current_principal_optional),
) -> SessionStatus:
    agent_id = _resolve_agent_id(request, db, principal, required=True)
    service = SessionService(request.app.state.browser_client)
    try:
        result = await service.get(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="session.read",
            actor=agent_id,
            session_id=session_id,
            decision="allow",
            reason="session read",
            request_id=request.state.request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
        )
        return result
    except BrowserWorkerPolicyError as exc:
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.delete("/session/{session_id}", response_model=SessionCloseResponse)
async def close_session(
    request: Request,
    session_id: str = Path(pattern=SESSION_ID_PATTERN),
    db: Optional[Session] = Depends(get_db),
    principal: Principal | None = Depends(get_current_principal_optional),
) -> SessionCloseResponse:
    agent_id = _resolve_agent_id(request, db, principal, required=True)
    service = SessionService(request.app.state.browser_client)
    try:
        result = await service.close(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="session.close",
            actor=agent_id,
            session_id=session_id,
            decision="allow",
            reason="session closed",
            request_id=request.state.request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
        )
        return result
    except BrowserWorkerPolicyError as exc:
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.post("/action", response_model=ActionResponse)
async def action(
    payload: BrowserActionRequest, request: Request,
    db: Optional[Session] = Depends(get_db),
    principal: Principal | None = Depends(get_current_principal_optional),
) -> ActionResponse:
    agent_id = _resolve_agent_id(request, db, principal, required=True)
    await enforce_category_rate_limit(request, "action", session_id=payload.session_id)

    # --- Capability enforcement (skipped when no database configured) ---
    if db is not None:
        agent = (
            db.query(Agent)
            .filter(
                Agent.agent_id == agent_id,
                Agent.organization_id == (principal.organization_id if principal else None),
            )
            .first()
        )
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "AGENT_IDENTIFICATION_REQUIRED", "message": "agent identification required"},
            )

        org_id = principal.organization_id if principal else None
        cap_svc = CapabilityService(db=db)
        # Browser actions: tool_name is the action type (click, type, scroll, etc.)
        tool_name = payload.action
        target_str = None
        if payload.target is not None:
            target_str = payload.target.selector or payload.target.role or payload.target.name or ""
        elif payload.selector:
            target_str = payload.selector
        cap_decision = cap_svc.check_capability(
            agent=agent,
            organization_id=org_id or str(agent.organization_id),
            capability_key=None,
            tool_name=tool_name,
            target=target_str or None,
            tool_args={},
        )
        if not cap_decision.allowed:
            if cap_decision.require_approval:
                from app.db.ai_models import ApprovalRequest as ApprovalRequestModel
                from app.db.models import Capability as CapabilityModel
                cap_row = (
                    db.query(CapabilityModel)
                    .filter(
                        CapabilityModel.organization_id == agent.organization_id,
                    )
                    .first()
                )
                if cap_row is not None:
                    approval = ApprovalRequestModel(
                        organization_id=agent.organization_id,
                        agent_id=agent.id,
                        capability_id=cap_row.id,
                        tool_name=tool_name,
                        tool_args={},
                        target=target_str,
                        status="pending",
                        requested_by=str(principal.user_id or principal.agent_id or "system") if principal else "system",
                    )
                    db.add(approval)
                    db.commit()
            audit_store = request.app.state.audit_store
            audit_store.add(
                type="action.refuse",
                actor=agent_id,
                session_id=payload.session_id,
                target=target_str,
                decision="deny",
                reason=cap_decision.reason or "capability check failed",
                request_id=request.state.request_id,
                organization_id=org_id,
                agent_id=agent_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "CAPABILITY_DENIED", "message": cap_decision.reason or "capability check failed"},
            )

    service = ActionService(
        request.app.state.browser_client,
        request.app.state.content_inspector,
    )
    try:
        result = await service.act(
            payload,
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="action.execute",
            actor=agent_id,
            session_id=payload.session_id,
            target=result.final_url,
            decision="allow" if result.success else "deny",
            reason="browser action executed",
            request_id=request.state.request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
        )
        return result
    except BrowserWorkerPolicyError as exc:
        logger.info(
            "browser_action_refused",
            extra={"code": exc.code, "worker_status": exc.status_code},
        )
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="action.refuse",
            actor=agent_id,
            session_id=payload.session_id,
            decision="deny",
            reason=exc.message,
            request_id=request.state.request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
        )
        _raise_worker_policy_error(exc)
    except (BrowserWorkerTimeout, BrowserWorkerUnavailable, BrowserWorkerResponseError) as exc:
        _raise_worker_failure(exc)


@router.post("/screenshot")
async def screenshot(
    payload: ScreenshotRequest, request: Request,
    db: Optional[Session] = Depends(get_db),
    principal: Principal | None = Depends(get_current_principal_optional),
) -> Response:
    agent_id = _resolve_agent_id(request, db, principal, required=True)
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
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="screenshot.capture",
            actor=agent_id,
            session_id=payload.session_id,
            decision="allow",
            reason="screenshot captured",
            request_id=request.state.request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
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
async def extract(
    payload: ExtractRequest, request: Request,
    db: Optional[Session] = Depends(get_db),
    principal: Principal | None = Depends(get_current_principal_optional),
) -> ExtractResponse:
    agent_id = _resolve_agent_id(request, db, principal, required=True)
    await enforce_category_rate_limit(
        request, "extract", session_id=payload.session_id
    )
    service = ExtractService(
        request.app.state.browser_client,
        request.app.state.content_inspector,
    )
    try:
        result = await service.extract(
            payload,
            agent_id=agent_id,
            request_id=request.state.request_id,
        )
        audit_store = request.app.state.audit_store
        audit_store.add(
            type="extract.read",
            actor=agent_id,
            session_id=payload.session_id,
            decision="allow",
            reason="content extracted",
            request_id=request.state.request_id,
            organization_id=principal.organization_id if principal else None,
            agent_id=agent_id,
        )
        return result
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
