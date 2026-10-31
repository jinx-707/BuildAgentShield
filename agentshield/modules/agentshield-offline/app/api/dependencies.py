"""
AgentShield Offline — FastAPI Dependency Injection Container.

All capability gateways and adapters are constructed here and injected
into route handlers. To replace any adapter (local dev, NeMo, Person 1,
Person 4), change the relevant factory function in this file only.

NeMo integration
----------------
When AGENTSHIELD_NEMO_ENABLED=true the content and data inspector factories
return NeMo-backed adapters (optionally chained with the local dev inspector
as a fallback). When AGENTSHIELD_NEMO_ENABLED=false (default) the existing
local development inspectors are used unchanged — full backward compatibility.

Swap hierarchy (configured here only):
  get_content_inspector() → LocalDev | NemoContentInspector (chained)
  get_data_inspector()    → LocalDev | NemoDataInspector    (chained)
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Optional

import structlog
from fastapi import Depends, Header, HTTPException, status

from app.capabilities.offline.documents.document_inspector import DocumentInspector
from app.capabilities.offline.documents.gateway import DocumentGateway
from app.capabilities.offline.documents.malware_scanner import ClamAVScanner
from app.capabilities.offline.documents.quarantine import QuarantineManager
from app.capabilities.offline.environment.environment_guard import EnvironmentGuard
from app.capabilities.offline.environment.environment_policy import EnvironmentPolicy
from app.capabilities.offline.environment.gateway import EnvironmentGateway
from app.capabilities.offline.environment.secret_broker import SecretBroker
from app.capabilities.offline.environment.secret_provider import MockSecretProvider
from app.capabilities.offline.local_files.directory_scopes import DirectoryScopeRegistry
from app.capabilities.offline.local_files.filesystem_gateway import LocalFilesystemGateway
from app.capabilities.offline.system_files.gateway import SystemFileGateway
from app.capabilities.offline.terminal.command_policy import CommandPolicy
from app.capabilities.offline.terminal.execution_worker import ExecutionWorker
from app.capabilities.offline.terminal.gateway import TerminalGateway
from app.capabilities.offline.terminal.output_inspector import TerminalOutputInspector
from app.capabilities.offline.terminal.sandbox_manager import DockerSandboxManager
from app.core.configuration import OfflineSettings, get_settings
from app.core.runtime import OfflineSecurityRuntime
from app.integrations.local_audit_adapter import LocalAuditAdapter
from app.integrations.local_content_inspector import (
    LocalDevelopmentContentInspector,
    LocalDevelopmentDataInspector,
)

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def get_app_settings() -> OfflineSettings:
    return get_settings()


# ---------------------------------------------------------------------------
# Audit adapter — replace with Person 4's adapter in production
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_audit_adapter() -> LocalAuditAdapter:
    settings = get_settings()
    return LocalAuditAdapter(log_path=settings.audit_log_path)


# ---------------------------------------------------------------------------
# P1 adapters — wired when AGENTSHIELD_P1_ENABLED=true
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_p1_content_adapter():
    """
    Returns a P1ContentInspectionAdapter when P1 is enabled and available.
    On any failure: logs a warning and returns None (caller falls back to local).
    """
    settings = get_settings()
    if not settings.p1_enabled:
        return None
    try:
        from app.integrations.p1.p1_adapters import P1ContentInspectionAdapter
        adapter = P1ContentInspectionAdapter(fail_closed=settings.p1_fail_closed)
        adapter._ensure_initialized()          # validate import works now
        log.info("p1_content_adapter_active")
        return adapter
    except Exception as exc:
        log.warning("p1_content_adapter_unavailable", error=str(exc))
        return None


@lru_cache(maxsize=1)
def get_p1_data_adapter():
    """
    Returns a P1DataInspectionAdapter when P1 is enabled and available.
    """
    settings = get_settings()
    if not settings.p1_enabled:
        return None
    try:
        from app.integrations.p1.p1_adapters import P1DataInspectionAdapter
        adapter = P1DataInspectionAdapter(fail_closed=settings.p1_fail_closed)
        adapter._ensure_initialized()
        log.info("p1_data_adapter_active")
        return adapter
    except Exception as exc:
        log.warning("p1_data_adapter_unavailable", error=str(exc))
        return None


# ---------------------------------------------------------------------------
# NeMo Engine — singleton, only created when nemo_enabled=True
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_nemo_engine() -> Optional[object]:
    """
    Return the NemoEngine singleton when NeMo is enabled, otherwise None.
    Errors during initialisation are logged but do not crash the application —
    the engine is marked unavailable and the fallback inspector is used.
    """
    settings = get_settings()
    if not settings.nemo_enabled:
        log.debug("nemo_disabled_by_configuration")
        return None

    from app.integrations.nemo.nemo_engine import NemoEngine
    from app.integrations.nemo.exceptions import (
        NemoConfigError,
        NemoEngineError,
        NemoNotInstalledError,
    )

    engine = NemoEngine(settings)
    try:
        engine.initialize()
        log.info("nemo_engine_ready", profile=settings.nemo_profile)
    except NemoNotInstalledError as exc:
        log.warning("nemo_not_installed_skipping", detail=str(exc))
    except NemoConfigError as exc:
        log.error("nemo_config_error_skipping", detail=str(exc))
    except NemoEngineError as exc:
        log.error("nemo_engine_error_skipping", detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        log.error("nemo_unexpected_init_error", detail=str(exc))
    return engine


# ---------------------------------------------------------------------------
# Content inspection adapters
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_content_inspector():
    """
    Returns the active ContentInspectionPort implementation.

    Inspector selection priority (highest to lowest):
      1. P1 + NeMo chained  (both enabled and available)
      2. P1 only            (P1 enabled, NeMo disabled/unavailable)
      3. NeMo + local chain (NeMo enabled, P1 disabled/unavailable)
      4. Local dev only     (fallback — always available)

    Chaining order: LocalDev (fast regex) → P1 (ML-grade) → NeMo (configurable rails)
    The first BLOCKED result short-circuits — subsequent inspectors are skipped.

    To use Person 1's engine: AGENTSHIELD_P1_ENABLED=true
    To use NeMo:              AGENTSHIELD_NEMO_ENABLED=true
    To use both:              both flags true
    """
    settings = get_settings()
    local_inspector = LocalDevelopmentContentInspector()

    p1_adapter = get_p1_content_adapter()
    nemo_engine = get_nemo_engine()
    nemo_available = nemo_engine is not None and nemo_engine.is_available()

    # Build the chain based on what's available
    inspectors = [local_inspector]

    if p1_adapter is not None:
        inspectors.append(p1_adapter)
        log.info("p1_content_inspector_in_chain")

    if nemo_available:
        from app.integrations.nemo.nemo_inspector import NemoContentInspector
        nemo_inspector = NemoContentInspector(
            engine=nemo_engine,
            fail_closed=settings.nemo_fail_closed,
            fallback_inspector=local_inspector,
        )
        inspectors.append(nemo_inspector)
        log.info("nemo_content_inspector_in_chain", profile=settings.nemo_profile)

    if len(inspectors) == 1:
        # Only local — no chaining overhead
        if settings.p1_enabled:
            log.warning("p1_enabled_but_unavailable_using_local_inspector")
        if settings.nemo_enabled:
            log.warning("nemo_enabled_but_unavailable_using_local_inspector",
                        fail_closed=settings.nemo_fail_closed)
        return local_inspector

    from app.integrations.nemo.nemo_inspector import ChainedContentInspector
    log.info("chained_content_inspector_active", chain_length=len(inspectors))
    return ChainedContentInspector(*inspectors)


@lru_cache(maxsize=1)
def get_data_inspector():
    """
    Returns the active DataInspectionPort implementation.

    Selection priority:
      1. P1 DataInspector (if P1 enabled and available) — deepest secret/DLP scan
      2. NeMo DataInspector (if NeMo enabled and available) — output rails
      3. Local dev DataInspector (always available)

    IMPORTANT: Whichever adapter is active, the local secret redaction pass
    runs FIRST in TerminalOutputInspector (hardcoded ordering), so raw
    secrets never reach P1 or NeMo if they are remote providers.
    """
    settings = get_settings()
    local_inspector = LocalDevelopmentDataInspector()

    p1_adapter = get_p1_data_adapter()
    if p1_adapter is not None:
        log.info("p1_data_inspector_active")
        return p1_adapter

    nemo_engine = get_nemo_engine()
    if nemo_engine is not None and nemo_engine.is_available():
        from app.integrations.nemo.nemo_inspector import NemoDataInspector
        log.info("nemo_data_inspector_active", profile=settings.nemo_profile)
        return NemoDataInspector(
            engine=nemo_engine,
            fail_closed=settings.nemo_fail_closed,
            fallback_inspector=local_inspector,
        )

    return local_inspector


# ---------------------------------------------------------------------------
# Document gateway
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_document_gateway() -> DocumentGateway:
    settings = get_settings()
    content_inspector = get_content_inspector()
    doc_inspector = DocumentInspector(
        content_inspector,
        fail_closed=settings.inspection_fail_closed,
    )
    scanner = ClamAVScanner(
        host=settings.clamav_host,
        port=settings.clamav_port,
        timeout=settings.clamav_timeout,
        fail_closed=settings.clamav_fail_closed,
    )
    quarantine = QuarantineManager(quarantine_dir=settings.quarantine_dir)
    return DocumentGateway(
        inspector=doc_inspector,
        scanner=scanner,
        quarantine=quarantine,
        fail_closed_on_scan_unavailable=settings.clamav_fail_closed,
    )


# ---------------------------------------------------------------------------
# Local filesystem gateway
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_filesystem_gateway() -> LocalFilesystemGateway:
    scope_registry = DirectoryScopeRegistry()
    return LocalFilesystemGateway(scope_registry=scope_registry)


# ---------------------------------------------------------------------------
# System file gateway
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_system_file_gateway() -> SystemFileGateway:
    return SystemFileGateway()


# ---------------------------------------------------------------------------
# Environment gateway
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_environment_gateway() -> EnvironmentGateway:
    policy = EnvironmentPolicy()
    guard = EnvironmentGuard(policy)
    provider = MockSecretProvider()
    broker = SecretBroker(provider=provider, permitted_secrets={})
    return EnvironmentGateway(policy=policy, guard=guard, secret_broker=broker)


# ---------------------------------------------------------------------------
# Terminal gateway
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_terminal_gateway() -> TerminalGateway:
    settings = get_settings()
    policy = CommandPolicy()
    sandbox = DockerSandboxManager()
    output_inspector = TerminalOutputInspector(
        content_inspector=get_content_inspector(),
        data_inspector=get_data_inspector(),
        fail_closed=settings.inspection_fail_closed,
    )
    worker = ExecutionWorker(
        policy=policy,
        sandbox=sandbox,
        output_inspector=output_inspector,
        workspace=settings.default_workspace,
    )
    return TerminalGateway(worker=worker)


# ---------------------------------------------------------------------------
# Offline Security Runtime
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_runtime() -> OfflineSecurityRuntime:
    return OfflineSecurityRuntime(
        document_gateway=get_document_gateway(),
        filesystem_gateway=get_filesystem_gateway(),
        system_file_gateway=get_system_file_gateway(),
        environment_gateway=get_environment_gateway(),
        terminal_gateway=get_terminal_gateway(),
        audit_port=get_audit_adapter(),
    )


# ---------------------------------------------------------------------------
# API authentication
# ---------------------------------------------------------------------------

def verify_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> str:
    """
    Development API key verification.
    Replace with Person 4's authentication middleware in production.
    """
    settings = get_settings()
    if settings.environment == "development":
        if x_api_key is None or x_api_key == settings.dev_api_key:
            return x_api_key or "dev-anonymous"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    if not x_api_key or x_api_key != settings.dev_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return x_api_key
