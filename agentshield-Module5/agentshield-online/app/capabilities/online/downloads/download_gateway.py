"""
Download Gateway — enforced entry point for all download operations.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from app.capabilities.online.downloads.download_manager import DownloadManager, DownloadPolicy
from app.capabilities.online.downloads.malware_scanner import ClamAVScanner, MockMalwareScanner
from app.capabilities.online.downloads.quarantine_manager import QuarantineManager
from app.capabilities.online.downloads.storage_manager import StorageManager
from app.core.contracts import GatewayResponse, SecurityContext
from app.core.decisions import SecurityDecision
from app.core.exceptions import (
    DownloadError,
    DownloadSizeLimitError,
    FileValidationError,
    MalwareDetectedError,
    ScannerUnavailableError,
    SSRFAttemptError,
    URLValidationError,
)
from app.integrations.ports import AuditEvent, AuditPort, PolicyContext, PolicyPort

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parents[5] / "configs" / "download_policy.yaml"


class DownloadGateway:
    """
    Enforces all download security rules.
    """

    def __init__(
        self,
        policy: PolicyPort,
        audit: AuditPort,
        download_manager: DownloadManager,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._manager = download_manager

    @classmethod
    def from_config(
        cls,
        policy: PolicyPort,
        audit: AuditPort,
        config_path: str | None = None,
        use_mock_scanner: bool = False,
        base_dir: str = "./downloads",
        quarantine_dir: str = "./quarantine",
        clamav_host: str = "localhost",
        clamav_port: int = 3310,
        fail_closed: bool = True,
    ) -> "DownloadGateway":
        path = Path(config_path or _DEFAULT_CONFIG_PATH)
        dl_config: dict[str, Any] = {}
        try:
            with open(path) as f:
                dl_config = yaml.safe_load(f).get("downloads", {})
        except Exception as e:
            logger.warning("DownloadGateway: could not load config %s: %s", path, e)

        dl_policy = DownloadPolicy(dl_config)
        storage = StorageManager(base_dir)
        quarantine = QuarantineManager(quarantine_dir)

        if use_mock_scanner:
            scanner = MockMalwareScanner()
        else:
            scanner = ClamAVScanner(
                host=clamav_host,
                port=clamav_port,
                fail_closed=fail_closed,
            )

        manager = DownloadManager(
            scanner=scanner,
            storage=storage,
            quarantine=quarantine,
            policy=dl_policy,
        )
        return cls(policy=policy, audit=audit, download_manager=manager)

    async def request_download(
        self,
        ctx: SecurityContext,
        url: str,
        filename: str | None = None,
    ) -> GatewayResponse:
        # Policy check
        policy_decision = await self._policy.authorize(
            PolicyContext(
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                capability="downloads",
                operation="request",
                resource=url,
            )
        )
        if not policy_decision.allowed:
            await self._record_audit(ctx, "DENY", "BLOCKED", policy_decision.reason, url)
            return GatewayResponse.deny(ctx, policy_decision.reason, policy_decision.policy_id)

        try:
            record = await self._manager.download(url=url, requested_filename=filename)
            await self._record_audit(ctx, "ALLOW", "EXECUTED", resource=url)
            return GatewayResponse.allow(ctx, result=record.model_dump())

        except (SSRFAttemptError, URLValidationError) as e:
            await self._record_audit(ctx, "DENY", "BLOCKED", str(e), url)
            return GatewayResponse.deny(ctx, str(e), "DOWNLOAD-URL-001")

        except MalwareDetectedError as e:
            await self._record_audit(ctx, "DENY", "QUARANTINED", str(e), url)
            return GatewayResponse.quarantined(ctx, str(e))

        except ScannerUnavailableError as e:
            await self._record_audit(ctx, "DENY", "BLOCKED", str(e), url)
            return GatewayResponse.deny(ctx, str(e), "DOWNLOAD-SCAN-001")

        except FileValidationError as e:
            await self._record_audit(ctx, "DENY", "BLOCKED", str(e), url)
            return GatewayResponse.deny(ctx, str(e), "DOWNLOAD-FILE-001")

        except DownloadSizeLimitError as e:
            await self._record_audit(ctx, "DENY", "BLOCKED", str(e), url)
            return GatewayResponse.deny(ctx, str(e), "DOWNLOAD-SIZE-001")

        except Exception as e:
            logger.error("Download gateway unexpected error: %s", e)
            await self._record_audit(ctx, "ALLOW", "FAILED", str(e)[:100], url)
            return GatewayResponse(
                request_id=ctx.request_id,
                status="FAILED",
                decision=SecurityDecision.ALLOW,
                capability="downloads",
                operation="request",
                reason=f"Download failed: {type(e).__name__}",
            )

    async def get_status(
        self,
        ctx: SecurityContext,
        download_id: str,
    ) -> GatewayResponse:
        record = self._manager.get_download(download_id)
        if not record:
            return GatewayResponse.deny(ctx, f"Download {download_id} not found", "DOWNLOAD-404")
        return GatewayResponse.allow(ctx, result=record.model_dump())

    async def _record_audit(
        self,
        ctx: SecurityContext,
        decision: str,
        status: str,
        reason: str | None = None,
        resource: str | None = None,
    ) -> None:
        await self._audit.record(
            AuditEvent(
                event_type=f"DOWNLOAD_{ctx.operation.upper()}",
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                capability="downloads",
                operation=ctx.operation,
                decision=decision,
                status=status,
                request_id=ctx.request_id,
                resource=resource,
                reason=reason,
            )
        )
