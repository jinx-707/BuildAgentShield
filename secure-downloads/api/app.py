"""
FastAPI application factory for AgentShield Secure Downloads.

Startup sequence
----------------
1. Configure logging.
2. Build the storage manager and initialise zone directories.
3. Run Alembic migrations to bring the database up to date.
4. Build the security pipeline (URL validator, SSRF guard, preflight).
5. Build the download streamer (proxy-enforced HTTP client).
6. Build the ClamAV scanner.
7. Build the orchestrator.
8. Build the handoff service.
9. Run startup security validation (fail closed in production-like
   environments when configuration is unsafe).
10. Register routes and middleware.

Fail-closed guarantees
----------------------
- ENVIRONMENT must be set explicitly; unknown/empty/missing values are
  rejected by Settings construction (config/settings.py).
- Production (and staging) requires API_AUTH_TOKEN.
- Production (and staging) requires EGRESS_PROXY_URL and
  EGRESS_PROXY_HEALTH_URL; the REQUIRE_EGRESS_PROXY opt-out is not honoured
  there.
- Production (and staging) requires DNS_PREFLIGHT_ENABLED and rejects
  ALLOW_PRIVATE_NETWORKS.
- Settings raises ValidationError at construction if these are absent, and
  the lifespan re-checks security_issues() as a safety net.

Health endpoints
----------------
Three distinct signals — never conflate them:
- GET /health/live   — process liveness only: the event loop answers.
  Always 200 if the process is up, even when the configuration is unsafe or
  dependencies are down.
- GET /health/ready  — dependency readiness + security configuration
  readiness.  200 only when the database and storage are healthy AND the
  egress proxy is attested as enforcing (when required) AND the ClamAV
  scanner is reachable AND there are no outstanding security-configuration
  issues.  503 otherwise, with per-check statuses.  The payload lists
  configuration variable *names* and dependency states only — never values,
  so it leaks no secrets.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api.middleware import ApiAuthMiddleware, RateLimitMiddleware, RequestContextMiddleware
from api.routes import router as download_router
from config.logging_setup import configure_logging
from config.settings import Settings, get_settings, security_issues
from security.errors import DownloadSecurityError

logger = logging.getLogger(__name__)

_READY_CHECK_TIMEOUT_SECONDS = 3.0


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    configure_logging(resolved.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        from models.database import get_async_engine, get_async_session
        from security.domain_policy import DomainPolicy, PortPolicy
        from security.mime_validator import MimeValidator
        from security.preflight import DownloadPreflight
        from security.ssrf import SsrfGuard, SystemDnsResolver
        from security.url_validator import DownloadUrlValidator
        from services.downloader import DownloadStreamer
        from services.orchestrator import DownloadOrchestrator
        from services.repository import DownloadRepository
        from services.scanner import ClamAvScanner
        from storage.manager import StorageManager
        from integrations.analysis_adapter import build_analysis_adapter
        from integrations.handoff import DocumentHandoffService
        from services.analysis_repository import AnalysisRepository
        from services.analysis_service import AnalysisRunner, AnalysisService
        from services.document_processor import PdfDocumentProcessor
        from alembic.config import Config
        from alembic import command
        import os

        # ── Storage ───────────────────────────────────────────────────────
        storage = StorageManager(resolved.storage_root)
        storage.initialize()

        # ── Database + migrations ─────────────────────────────────────────
        engine = get_async_engine(resolved.database_url)
        session_factory = get_async_session(engine)

        # Run Alembic migrations on startup.  The Config is built without a
        # config file on purpose: env.py calls fileConfig() for the Alembic
        # CLI, and doing that here would replace the process's logging config
        # (and historically disabled the application's loggers).
        alembic_cfg = Config()
        alembic_cfg.set_main_option("sqlalchemy.url", resolved.database_url)
        alembic_cfg.set_main_option(
            "script_location",
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations"),
        )
        import asyncio
        await asyncio.to_thread(command.upgrade, alembic_cfg, "head")

        # ── Security pipeline ─────────────────────────────────────────────
        url_validator = DownloadUrlValidator(
            allowed_ports=resolved.allowed_ports,
            allowed_domains=resolved.allowed_domains,
            blocked_domains=resolved.blocked_domains,
            default_domain_policy=resolved.default_domain_policy,
            allow_private_networks=resolved.allow_private_networks,
            https_only=True,
        )
        ssrf_guard = SsrfGuard(
            resolver=SystemDnsResolver(),
            allow_private_networks=resolved.allow_private_networks,
        )
        preflight = DownloadPreflight(
            url_validator=url_validator,
            ssrf_guard=ssrf_guard,
            dns_enabled=resolved.dns_preflight_enabled,
        )

        # ── Streamer ──────────────────────────────────────────────────────
        streamer = DownloadStreamer(
            preflight=preflight,
            storage_manager=storage,
            ssrf_guard=ssrf_guard,
            allow_private_networks=resolved.allow_private_networks,
            egress_proxy_url=resolved.egress_proxy_url,
            egress_health_url=resolved.egress_proxy_health_url,
            proxy_auth_token=resolved.proxy_auth_token,
            max_size_bytes=resolved.max_file_size_bytes,
            connect_timeout_s=resolved.download_connect_timeout_seconds,
            read_timeout_s=resolved.download_read_timeout_seconds,
            total_timeout_s=resolved.download_total_timeout_seconds,
            max_redirects=resolved.max_redirects,
            require_proxy=resolved.require_egress_proxy,
        )

        # ── Scanner ───────────────────────────────────────────────────────
        scanner = ClamAvScanner(
            host=resolved.clamav_host,
            port=resolved.clamav_port,
            timeout_seconds=resolved.clamav_timeout_seconds,
            fail_closed=resolved.clamav_fail_closed,
        )

        # ── Repository + Orchestrator ─────────────────────────────────────
        repository = DownloadRepository(session_factory)
        orchestrator = DownloadOrchestrator(
            repository=repository,
            streamer=streamer,
            scanner=scanner,
            storage_manager=storage,
            max_concurrent_per_tenant=resolved.max_concurrent_downloads_per_tenant,
            approved_ttl_seconds=resolved.approved_file_ttl_seconds,
        )

        # ── Document analysis (handoff + durable job runner) ──────────────
        # The adapter is selected explicitly from configuration; there is no
        # silent mock fallback.  'disabled' builds the disabled adapter and
        # the API returns ANALYSIS_DISABLED for analysis requests; downloads
        # are unaffected.
        analysis_adapter = build_analysis_adapter(resolved)
        handoff_service = DocumentHandoffService(
            adapter=analysis_adapter,
            storage_manager=storage,
            repository=repository,
        )
        analysis_service = AnalysisService(
            downloads=repository,
            analyses=AnalysisRepository(session_factory),
            handoff=handoff_service,
            processor=PdfDocumentProcessor(
                max_pages=resolved.analysis_max_pages,
                max_text_chars=resolved.analysis_max_extracted_chars,
                processing_timeout_seconds=resolved.analysis_processing_timeout_seconds,
            ),
            storage=storage,
            enabled=resolved.analysis_provider != "disabled",
            max_payload_bytes=resolved.analysis_max_payload_bytes,
            job_timeout_seconds=resolved.analysis_job_timeout_seconds,
            max_attempts=resolved.analysis_max_attempts,
        )
        analysis_runner = AnalysisRunner(
            service=analysis_service,
            concurrency=resolved.analysis_worker_concurrency,
        )

        # ── Store on app state ────────────────────────────────────────────
        app.state.settings = resolved
        app.state.orchestrator = orchestrator
        app.state.handoff_service = handoff_service
        app.state.analysis_service = analysis_service
        app.state.analysis_runner = analysis_runner
        app.state.storage = storage
        app.state.engine = engine
        app.state.scanner = scanner

        # ── Startup security validation ──────────────────────────────────
        # Settings construction already refuses unsafe production-like
        # configurations; this is the safety net (and the readiness signal)
        # for any drift between the two validators, and it surfaces the same
        # issues in non-production environments without blocking boot.
        issues = security_issues(resolved)
        app.state.security_issues = issues
        if issues and resolved.is_production_like:
            # Fail closed: an unsafe production-like configuration must not
            # start, regardless of how it got past Settings validation.
            raise RuntimeError(
                "Refusing to start with unsafe production configuration: "
                + "; ".join(issues)
            )
        if issues:
            logger.warning(
                "security_configuration_issues",
                extra={
                    "environment": resolved.environment,
                    "issue_count": len(issues),
                    "issues": issues,
                },
            )

        from security.proxy_auth import redact_proxy_url

        logger.info(
            "secure_downloads_started",
            extra={
                "service": resolved.app_name,
                "environment": resolved.environment,
                "storage_root": resolved.storage_root,
                # Never log proxy userinfo — a token embedded in the URL (or
                # added from PROXY_AUTH_TOKEN) must not reach the log stream.
                "egress_proxy": redact_proxy_url(resolved.egress_proxy_url) or "none",
                "require_proxy": resolved.require_egress_proxy,
                # Provider mode only — never the endpoint token.
                "analysis_provider": resolved.analysis_provider,
            },
        )

        # ── Startup recovery ─────────────────────────────────────────────
        # No download can be in flight yet: every non-terminal record was
        # abandoned by a previous process, and every temporary file is an
        # orphan.  Fail the records and reclaim the files before accepting
        # traffic so the API never reports a stale in-progress download.
        await orchestrator.recover_interrupted_downloads()
        swept = storage.sweep_temporary(older_than_seconds=0)
        if swept:
            logger.info("orphan_temp_files_removed", extra={"count": swept})

        async def _ttl_sweeper() -> None:
            while True:
                await asyncio.sleep(resolved.cleanup_interval_seconds)
                try:
                    expired = await orchestrator.expire_old_downloads()
                    if expired:
                        logger.info(
                            "downloads_expired", extra={"count": expired}
                        )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.error(
                        "ttl_sweeper_error",
                        extra={"error_type": type(exc).__name__},
                    )

        sweeper_task = asyncio.create_task(
            _ttl_sweeper(), name="download-ttl-sweeper"
        )

        # Start the analysis worker pool only after configuration has been
        # validated, so a failing startup cannot leave orphaned workers.
        # recovery re-enqueues persisted PENDING/RUNNING jobs.
        await analysis_runner.start()

        yield

        # ── Shutdown ──────────────────────────────────────────────────────
        sweeper_task.cancel()
        try:
            await sweeper_task
        except asyncio.CancelledError:
            pass
        await orchestrator.shutdown()
        await analysis_runner.stop()
        await engine.dispose()
        logger.info("secure_downloads_stopped", extra={"service": resolved.app_name})

    app = FastAPI(
        title="AgentShield Secure Downloads",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Middleware is applied last-added-first (outermost).  RequestContext is
    # outermost so every response — including 401 and 429 — carries the
    # request ID and is logged; rate limiting wraps auth so failed auth
    # attempts are still budgeted.
    app.add_middleware(
        RateLimitMiddleware,
        max_per_minute=resolved.rate_limit_per_minute,
        enabled=resolved.rate_limit_enabled,
    )
    app.add_middleware(ApiAuthMiddleware, api_auth_token=resolved.api_auth_token)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(download_router)

    # Health endpoints (exempt from auth and rate limiting).
    #
    # /health/live answers whenever the process and event loop are up.  It is
    # deliberately blind to configuration and dependency state so a broken
    # proxy or database never causes liveness restarts of a healthy process.
    @app.get("/health/live", include_in_schema=False)
    async def health_live():
        return {"status": "ok"}

    # /health/ready answers 200 only when every gate below passes:
    #   - security configuration has no outstanding issues,
    #   - the database is reachable,
    #   - the storage temporary zone is writable,
    #   - the egress proxy is attested as enforcing (when one is required),
    #   - the ClamAV scanner is reachable (nothing can be approved without it).
    # The payload contains check states and configuration-variable names and
    # dependency conditions only — never tokens or other secret values.
    @app.get("/health/ready", include_in_schema=False)
    async def health_ready(request: Request):
        resolved_s: Settings = request.app.state.settings
        checks: dict[str, str] = {}
        issues: list[str] = []

        # 1. Security configuration readiness.
        cfg_issues = security_issues(resolved_s)
        checks["security_configuration"] = "ok" if not cfg_issues else "not_ready"
        issues.extend(cfg_issues)

        # 2. Egress proxy attestation (dependency outage must be visible).
        if resolved_s.egress_proxy_url:
            if not resolved_s.egress_proxy_health_url:
                checks["egress_proxy"] = "unattestable"
                issues.append(
                    "Egress proxy has no health endpoint, so enforcement "
                    "mode cannot be verified."
                )
            else:
                from security.proxy_enforcement import assert_proxy_enforcing

                try:
                    await assert_proxy_enforcing(resolved_s.egress_proxy_health_url)
                    checks["egress_proxy"] = "enforcing"
                except DownloadSecurityError as exc:
                    checks["egress_proxy"] = "not_enforcing"
                    # Fixed text: never echo exc.message, which can contain
                    # endpoint details, only the condition.
                    issues.append(
                        "Egress proxy attestation failed "
                        f"(error code {exc.code}); downloads are blocked."
                    )
        elif resolved_s.require_egress_proxy:
            checks["egress_proxy"] = "not_configured"
            issues.append(
                "REQUIRE_EGRESS_PROXY is true but no egress proxy is configured."
            )
        else:
            checks["egress_proxy"] = "not_required"

        # 3. Database.
        from sqlalchemy import text

        try:
            async def _db_probe() -> None:
                async with request.app.state.engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))

            await asyncio.wait_for(_db_probe(), timeout=_READY_CHECK_TIMEOUT_SECONDS)
            checks["database"] = "ok"
        except Exception:
            checks["database"] = "unreachable"
            issues.append("Database is unreachable.")

        # 4. Storage temporary zone writability.
        try:
            storage: object = request.app.state.storage
            probe_path, _probe_ref = storage.allocate_temp_path()  # type: ignore[attr-defined]
            probe_path.write_bytes(b"probe")
            probe_path.unlink(missing_ok=True)
            checks["storage"] = "ok"
        except Exception:
            checks["storage"] = "error"
            issues.append("Storage temporary zone is not writable.")

        # 5. Scanner dependency (fail-closed policy makes it gating).
        try:
            scanner_available = await request.app.state.scanner.is_available()
        except Exception:
            scanner_available = False
        checks["scanner"] = "available" if scanner_available else "unavailable"
        if not scanner_available:
            issues.append(
                "ClamAV scanner is unreachable; with fail-closed scanning no "
                "download can reach APPROVED."
            )

        ready = (
            not cfg_issues
            and checks["egress_proxy"] in {"enforcing", "not_required"}
            and checks["database"] == "ok"
            and checks["storage"] == "ok"
            and scanner_available
        )
        return JSONResponse(
            status_code=200 if ready else 503,
            content={
                "status": "ready" if ready else "not_ready",
                "service": "agentshield-secure-downloads",
                "checks": checks,
                "issues": issues,
            },
        )

    # Global exception handler — never surface internal details.
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logger.error(
            "unhandled_exception",
            extra={"error_type": type(exc).__name__},
            exc_info=True,
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred.",
            },
        )

    return app


app = create_app()
