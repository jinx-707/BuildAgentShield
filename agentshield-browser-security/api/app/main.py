import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app import __version__
from app.api.browser import router as browser_router
from app.api.health import router as health_router
from app.clients.browser_worker import BrowserWorkerClient
from app.clients.search_provider import SearchProvider, build_search_provider
from app.config import Settings, get_settings
from app.factories import (
    build_content_inspector,
    build_network_preflight,
    build_policy_engine,
    compute_policy_fingerprint,
)
from app.interfaces.inspection import ContentInspector
from app.interfaces.policy import PolicyEngine
from app.logging_config import configure_logging
from app.middleware import (
    ApiAuthMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
    rate_limit_backend_response,
    rate_limit_response,
)
from app.security.preflight import NetworkPreflight
from app.security.rate_limit import (
    RateLimitBackendUnavailable,
    RateLimitExceeded,
    RateLimiter,
    build_rate_limiter,
    validate_rate_limit_settings,
)
from app.security.trusted_proxy import parse_trusted_proxies

logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    *,
    policy_engine: PolicyEngine | None = None,
    content_inspector: ContentInspector | None = None,
    browser_client: BrowserWorkerClient | None = None,
    network_preflight: NetworkPreflight | None = None,
    search_provider: SearchProvider | None = None,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.log_level)

    validate_rate_limit_settings(resolved_settings)
    trusted_proxies = parse_trusted_proxies(
        resolved_settings.rate_limit_trusted_proxies
    )
    resolved_rate_limiter = rate_limiter or build_rate_limiter(resolved_settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = resolved_settings
        app.state.rate_limiter = resolved_rate_limiter
        app.state.rate_limit_enabled = resolved_settings.rate_limit_enabled
        app.state.rate_limit_backend = resolved_settings.rate_limit_backend
        app.state.policy_engine = policy_engine or build_policy_engine(
            resolved_settings
        )
        app.state.content_inspector = content_inspector or build_content_inspector(
            resolved_settings
        )
        app.state.browser_client = browser_client or BrowserWorkerClient(
            resolved_settings
        )
        app.state.network_preflight = network_preflight or build_network_preflight(
            resolved_settings
        )
        app.state.search_provider = search_provider or build_search_provider(
            resolved_settings
        )
        logger.info(
            "application_started",
            extra={
                "service": resolved_settings.app_name,
                "environment": resolved_settings.environment,
                "browser_worker_url": resolved_settings.browser_worker_url,
                "policy_fingerprint": compute_policy_fingerprint(resolved_settings),
                "rate_limit_backend": resolved_settings.rate_limit_backend,
                "rate_limit_fail_open": resolved_settings.rate_limit_fail_open,
                "trusted_proxy_count": len(trusted_proxies),
            },
        )
        try:
            yield
        finally:
            await resolved_rate_limiter.aclose()
            await app.state.browser_client.aclose()
            close_search = getattr(app.state.search_provider, "aclose", None)
            if close_search is not None:
                await close_search()
            logger.info("application_stopped", extra={"service": resolved_settings.app_name})

    app = FastAPI(
        title="AgentShield Browser Security API",
        version=__version__,
        lifespan=lifespan,
    )
    # Last added is outermost: request IDs and timing cover auth and rate-limit
    # rejections as well as application responses.
    app.add_middleware(
        RateLimitMiddleware,
        limiter=resolved_rate_limiter,
        trusted_proxies=trusted_proxies,
        max_hops=resolved_settings.rate_limit_trusted_proxy_max_hops,
        enabled=resolved_settings.rate_limit_enabled,
    )
    app.add_middleware(
        ApiAuthMiddleware,
        api_auth_token=resolved_settings.api_auth_token,
    )
    app.add_middleware(RequestContextMiddleware)

    async def _rate_limited(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return rate_limit_response(exc)

    async def _rate_limit_unavailable(
        request: Request, exc: RateLimitBackendUnavailable
    ) -> JSONResponse:
        return rate_limit_backend_response(exc)

    app.add_exception_handler(RateLimitExceeded, _rate_limited)
    app.add_exception_handler(RateLimitBackendUnavailable, _rate_limit_unavailable)
    app.include_router(health_router)
    app.include_router(browser_router)
    return app


app = create_app()
