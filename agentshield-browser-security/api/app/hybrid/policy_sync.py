"""Data-plane policy synchronisation client.

The data plane initiates all communication — it polls the control plane for
policy updates over HTTPS.  The control plane never needs a direct network
path into the customer environment.

Responsibilities:
- Periodic policy polling against the control-plane sync endpoint.
- Cryptographic verification of every received policy package.
- Replay-protection: monotonically increasing sequence numbers.
- Last-known-good retention: invalid packages are discarded, not applied.
- Disconnected-mode operation: continue enforcing the last valid policy when
  the control plane is unreachable.
- Event buffering: collect telemetry events locally and flush them on
  reconnect.
- Health reporting back to the control plane.

Usage (from lifespan or a background task):

    sync_client = PolicySyncClient(
        control_plane_url="https://control.agentshield.example.com",
        deployment_id="dp-xxx",
        deployment_secret="...",
    )
    await sync_client.start()          # starts background tasks
    policy = sync_client.current_policy  # always returns a PolicySpec (never None)
    await sync_client.stop()
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

from app.hybrid.models import (
    DataPlaneHealth,
    DeploymentStatus,
    PolicyPackage,
    PolicySpec,
    PolicySyncRequest,
    PolicySyncResponse,
    TelemetryBatch,
    TelemetryEvent,
)
from app.hybrid.signing import verify_package

logger = logging.getLogger(__name__)

# Default fail-safe policy — deny everything.
_FAIL_SAFE_POLICY = PolicySpec(
    allowed_domains=[],
    blocked_domains=[],
    default_domain_policy="deny",
    allow_private_networks=False,
    dlp_enabled=True,
    threat_detection_enabled=True,
)

_DEFAULT_SYNC_INTERVAL = 300  # seconds
_MAX_RETRY_INTERVAL = 3600     # cap backoff at 1 hour
_TELEMETRY_FLUSH_INTERVAL = 60  # seconds
_MAX_BUFFERED_EVENTS = 10_000


class PolicySyncClient:
    """Background service that keeps the data plane's policy current.

    Thread-safe for reading ``current_policy`` and ``buffering events``.
    """

    def __init__(
        self,
        control_plane_url: str,
        deployment_id: str,
        deployment_secret: str,
        *,
        sync_interval_seconds: int = _DEFAULT_SYNC_INTERVAL,
        # Path to persist the last known-good policy across restarts.
        policy_cache_path: Optional[str] = None,
        http_timeout_seconds: float = 15.0,
    ) -> None:
        self._control_plane_url = control_plane_url.rstrip("/")
        self._deployment_id = deployment_id
        self._deployment_secret = deployment_secret
        self._sync_interval = sync_interval_seconds
        self._http_timeout = http_timeout_seconds
        self._cache_path = Path(policy_cache_path) if policy_cache_path else None

        # State
        self._current_package: Optional[PolicyPackage] = None
        self._last_sync_at: Optional[float] = None
        self._consecutive_failures = 0
        self._disconnected_mode = False
        self._status = DeploymentStatus.PENDING_ENROLLMENT

        # Telemetry buffer: events queued until the next successful flush.
        self._event_buffer: list[TelemetryEvent] = []
        self._telemetry_checkpoint: str = "0"
        self._buffer_lock = asyncio.Lock()

        # Background task handles
        self._sync_task: Optional[asyncio.Task] = None
        self._telemetry_task: Optional[asyncio.Task] = None
        self._health_task: Optional[asyncio.Task] = None

        self._http_client: Optional[httpx.AsyncClient] = None

        # Bootstrap from cache
        self._load_cached_policy()

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def current_policy(self) -> PolicySpec:
        """Always returns a valid PolicySpec.  Falls back to deny-all."""
        if self._current_package:
            # Verify offline validity window.
            if self._current_package.valid_until:
                now = datetime.now(timezone.utc)
                if now > self._current_package.valid_until:
                    logger.error(
                        "policy_expired",
                        extra={
                            "deployment_id": self._deployment_id,
                            "version_id": self._current_package.version_id,
                            "valid_until": self._current_package.valid_until.isoformat(),
                        },
                    )
                    return _FAIL_SAFE_POLICY
            return self._current_package.spec
        return _FAIL_SAFE_POLICY

    @property
    def current_version(self) -> Optional[str]:
        return self._current_package.version_id if self._current_package else None

    @property
    def is_disconnected(self) -> bool:
        return self._disconnected_mode

    @property
    def status(self) -> DeploymentStatus:
        return self._status

    async def buffer_event(self, event: TelemetryEvent) -> None:
        """Buffer a telemetry event for async delivery to the control plane."""
        async with self._buffer_lock:
            if len(self._event_buffer) >= _MAX_BUFFERED_EVENTS:
                # Drop the oldest event to prevent unbounded memory growth.
                self._event_buffer.pop(0)
                logger.warning(
                    "telemetry_buffer_overflow",
                    extra={"deployment_id": self._deployment_id},
                )
            self._event_buffer.append(event)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._http_client = httpx.AsyncClient(
            timeout=self._http_timeout,
            headers={
                "X-Deployment-ID": self._deployment_id,
                "User-Agent": "AgentShield-DataPlane/1.0",
            },
        )
        self._sync_task = asyncio.create_task(
            self._sync_loop(), name="policy-sync"
        )
        self._telemetry_task = asyncio.create_task(
            self._telemetry_flush_loop(), name="telemetry-flush"
        )
        self._health_task = asyncio.create_task(
            self._health_report_loop(), name="health-report"
        )
        logger.info(
            "policy_sync_started",
            extra={
                "deployment_id": self._deployment_id,
                "control_plane_url": self._control_plane_url,
                "sync_interval_seconds": self._sync_interval,
            },
        )

    async def stop(self) -> None:
        for task in (self._sync_task, self._telemetry_task, self._health_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        if self._http_client:
            await self._http_client.aclose()
        logger.info(
            "policy_sync_stopped",
            extra={"deployment_id": self._deployment_id},
        )

    # ── Sync loop ─────────────────────────────────────────────────────────────

    async def _sync_loop(self) -> None:
        while True:
            try:
                await self._do_sync()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "policy_sync_error",
                    extra={
                        "deployment_id": self._deployment_id,
                        "error": str(exc),
                    },
                )
            backoff = min(
                self._sync_interval * (2 ** min(self._consecutive_failures, 6)),
                _MAX_RETRY_INTERVAL,
            )
            await asyncio.sleep(backoff)

    async def _do_sync(self) -> None:
        assert self._http_client is not None
        req = PolicySyncRequest(
            deployment_id=self._deployment_id,
            current_version_id=self.current_version,
            current_sequence_number=(
                self._current_package.sequence_number
                if self._current_package else 0
            ),
        )
        try:
            response = await self._http_client.post(
                f"{self._control_plane_url}/v1/control/policy/sync",
                content=req.model_dump_json(),
                headers={"Content-Type": "application/json"},
                auth=_DeploymentAuth(
                    self._deployment_id, self._deployment_secret
                ),
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            self._on_sync_failure(f"HTTP {exc.response.status_code}")
            return
        except httpx.TransportError as exc:
            self._on_sync_failure(f"transport: {exc}")
            return

        self._consecutive_failures = 0
        if self._disconnected_mode:
            self._disconnected_mode = False
            logger.info(
                "policy_sync_reconnected",
                extra={"deployment_id": self._deployment_id},
            )

        result = PolicySyncResponse.model_validate(response.json())

        if result.rollback_requested and result.last_known_good_version:
            self._handle_rollback_request(result.last_known_good_version)
            return

        if result.has_update and result.package:
            self._apply_package(result.package)

        self._last_sync_at = time.monotonic()
        self._status = DeploymentStatus.ACTIVE

    def _apply_package(self, package: PolicyPackage) -> None:
        """Validate and apply a received policy package."""
        # Replay protection
        if (
            self._current_package
            and package.sequence_number <= self._current_package.sequence_number
        ):
            logger.warning(
                "policy_replay_rejected",
                extra={
                    "deployment_id": self._deployment_id,
                    "received_seq": package.sequence_number,
                    "current_seq": self._current_package.sequence_number,
                },
            )
            return

        # Cryptographic verification
        if not verify_package(package, self._deployment_secret):
            logger.error(
                "policy_signature_invalid",
                extra={
                    "deployment_id": self._deployment_id,
                    "version_id": package.version_id,
                },
            )
            # Keep current policy — never silently downgrade.
            return

        logger.info(
            "policy_updated",
            extra={
                "deployment_id": self._deployment_id,
                "version_id": package.version_id,
                "sequence_number": package.sequence_number,
            },
        )
        self._current_package = package
        self._persist_policy(package)

    def _handle_rollback_request(self, target_version: str) -> None:
        """Roll back to a specified version if we have it cached."""
        if self._current_package and self._current_package.version_id == target_version:
            logger.info(
                "policy_rollback_noop",
                extra={"deployment_id": self._deployment_id},
            )
            return

        cached = self._load_cached_policy_version(target_version)
        if cached:
            logger.info(
                "policy_rolled_back",
                extra={
                    "deployment_id": self._deployment_id,
                    "target_version": target_version,
                },
            )
            self._current_package = cached
        else:
            logger.error(
                "policy_rollback_version_not_found",
                extra={
                    "deployment_id": self._deployment_id,
                    "target_version": target_version,
                },
            )

    def _on_sync_failure(self, reason: str) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= 3 and not self._disconnected_mode:
            self._disconnected_mode = True
            self._status = DeploymentStatus.DISCONNECTED
            logger.warning(
                "policy_sync_disconnected",
                extra={
                    "deployment_id": self._deployment_id,
                    "reason": reason,
                    "current_version": self.current_version,
                    "has_policy": self._current_package is not None,
                },
            )
        else:
            logger.warning(
                "policy_sync_failure",
                extra={
                    "deployment_id": self._deployment_id,
                    "reason": reason,
                    "consecutive_failures": self._consecutive_failures,
                },
            )

    # ── Telemetry flush loop ──────────────────────────────────────────────────

    async def _telemetry_flush_loop(self) -> None:
        while True:
            await asyncio.sleep(_TELEMETRY_FLUSH_INTERVAL)
            try:
                await self._flush_telemetry()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "telemetry_flush_error",
                    extra={"deployment_id": self._deployment_id, "error": str(exc)},
                )

    async def _flush_telemetry(self) -> None:
        async with self._buffer_lock:
            if not self._event_buffer:
                return
            batch_events = list(self._event_buffer)

        if not batch_events:
            return

        batch = TelemetryBatch(
            deployment_id=self._deployment_id,
            batch_id=str(uuid.uuid4()),
            events=batch_events,
            checkpoint=self._telemetry_checkpoint,
        )

        assert self._http_client is not None
        try:
            response = await self._http_client.post(
                f"{self._control_plane_url}/v1/control/telemetry",
                content=batch.model_dump_json(),
                headers={"Content-Type": "application/json"},
                auth=_DeploymentAuth(
                    self._deployment_id, self._deployment_secret
                ),
            )
            response.raise_for_status()
            ack_data = response.json()
            # Advance checkpoint and drain the delivered events.
            async with self._buffer_lock:
                self._event_buffer = self._event_buffer[len(batch_events):]
            self._telemetry_checkpoint = ack_data.get(
                "next_checkpoint", str(int(self._telemetry_checkpoint) + len(batch_events))
            )
            logger.debug(
                "telemetry_flushed",
                extra={
                    "deployment_id": self._deployment_id,
                    "count": len(batch_events),
                },
            )
        except Exception as exc:
            logger.warning(
                "telemetry_flush_failed",
                extra={
                    "deployment_id": self._deployment_id,
                    "count": len(batch_events),
                    "error": str(exc),
                },
            )
            # Events remain in buffer — will retry next cycle.

    # ── Health reporting ──────────────────────────────────────────────────────

    async def _health_report_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                await self._send_health_report()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # Health reports are best-effort

    async def _send_health_report(self) -> None:
        seconds_since_sync = None
        if self._last_sync_at is not None:
            seconds_since_sync = time.monotonic() - self._last_sync_at

        health = DataPlaneHealth(
            deployment_id=self._deployment_id,
            status=self._status,
            seconds_since_policy_sync=seconds_since_sync,
            current_policy_version=self.current_version,
            disconnected_mode=self._disconnected_mode,
            events_buffered=len(self._event_buffer),
        )

        assert self._http_client is not None
        await self._http_client.post(
            f"{self._control_plane_url}/v1/control/deployments/{self._deployment_id}/health",
            content=health.model_dump_json(),
            headers={"Content-Type": "application/json"},
            auth=_DeploymentAuth(self._deployment_id, self._deployment_secret),
        )

    # ── Policy persistence (last-known-good) ──────────────────────────────────

    def _persist_policy(self, package: PolicyPackage) -> None:
        if not self._cache_path:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(
                package.model_dump_json(), encoding="utf-8"
            )
        except OSError as exc:
            logger.warning(
                "policy_cache_write_failed",
                extra={"error": str(exc)},
            )

    def _load_cached_policy(self) -> None:
        if not self._cache_path or not self._cache_path.exists():
            return
        try:
            data = self._cache_path.read_text(encoding="utf-8")
            pkg = PolicyPackage.model_validate_json(data)
            # Verify signature before trusting the cache.
            if verify_package(pkg, self._deployment_secret):
                self._current_package = pkg
                logger.info(
                    "policy_loaded_from_cache",
                    extra={
                        "deployment_id": self._deployment_id,
                        "version_id": pkg.version_id,
                    },
                )
            else:
                logger.warning(
                    "policy_cache_signature_invalid",
                    extra={"deployment_id": self._deployment_id},
                )
        except Exception as exc:
            logger.warning(
                "policy_cache_load_failed",
                extra={"error": str(exc)},
            )

    def _load_cached_policy_version(self, version_id: str) -> Optional[PolicyPackage]:
        """Try to load a specific version from the versioned cache directory."""
        if not self._cache_path:
            return None
        versioned = self._cache_path.parent / f"policy_{version_id}.json"
        if not versioned.exists():
            return None
        try:
            pkg = PolicyPackage.model_validate_json(
                versioned.read_text(encoding="utf-8")
            )
            if verify_package(pkg, self._deployment_secret):
                return pkg
        except Exception:
            pass
        return None


class _DeploymentAuth(httpx.Auth):
    """HMAC-SHA256 request authentication for data-plane → control-plane calls.

    Signs: {deployment_id}|{timestamp_ms}|{request_path}
    Adds headers:
        X-Deployment-ID: <deployment_id>
        X-Request-TS: <unix-ms>
        X-Signature: hmac-sha256=<hex>
    """

    def __init__(self, deployment_id: str, deployment_secret: str) -> None:
        import hashlib
        import hmac as _hmac
        self._deployment_id = deployment_id
        self._deployment_secret = deployment_secret
        self._hmac = _hmac
        self._hashlib = hashlib

    def auth_flow(self, request: httpx.Request):
        import time
        ts_ms = str(int(time.time() * 1000))
        path = request.url.path
        payload = f"{self._deployment_id}|{ts_ms}|{path}".encode("utf-8")
        sig = self._hmac.new(
            self._deployment_secret.encode("utf-8"),
            payload,
            digestmod=self._hashlib.sha256,
        ).hexdigest()
        request.headers["X-Deployment-ID"] = self._deployment_id
        request.headers["X-Request-TS"] = ts_ms
        request.headers["X-Signature"] = f"hmac-sha256={sig}"
        yield request
