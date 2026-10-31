"""
AgentShield Offline — NeMo Guardrails Engine lifecycle manager.

Responsibilities:
  - Apply telemetry opt-out BEFORE any nemoguardrails import.
  - Lazy-initialise a singleton Guardrails instance.
  - Provide async check_input() and check_output() helpers.
  - Handle timeouts, unavailability, and configuration errors.
  - Never initialise independently per request.

Telemetry note
--------------
NeMo Guardrails collects anonymous deployment usage statistics.
We always set NEMO_GUARDRAILS_NO_USAGE_STATS=1 and DO_NOT_TRACK=1
BEFORE importing nemoguardrails to opt out of telemetry.
This does NOT prevent a configured external LLM provider from receiving
content during an inference call — that is a separate concern handled
by the model provider configuration.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Optional

import structlog

from app.core.configuration import OfflineSettings, get_settings
from app.integrations.nemo.exceptions import (
    NemoConfigError,
    NemoEngineError,
    NemoNotInstalledError,
    NemoTimeoutError,
)
from app.integrations.nemo.nemo_config_loader import load_rails_config, resolve_config_path

log = structlog.get_logger(__name__)


def _apply_telemetry_opt_out(settings: OfflineSettings) -> None:
    """
    Apply telemetry opt-out environment variables before nemoguardrails is
    imported.  Must be called before the first 'import nemoguardrails'.
    """
    if settings.nemo_telemetry_disabled:
        os.environ.setdefault("NEMO_GUARDRAILS_NO_USAGE_STATS", "1")
        os.environ.setdefault("DO_NOT_TRACK", "1")
        log.debug("nemo_telemetry_opted_out")


class NemoEngine:
    """
    Singleton lifecycle wrapper around nemoguardrails.Guardrails.

    Usage (via the DI container — do not instantiate directly):
        engine = get_nemo_engine()
        result = await engine.check_input("some user text")
    """

    def __init__(self, settings: Optional[OfflineSettings] = None) -> None:
        self._settings = settings or get_settings()
        self._rails: Optional[Any] = None
        self._initialized = False
        self._init_error: Optional[str] = None
        self._active_profile: str = self._settings.nemo_profile
        self._active_config_path: Optional[Path] = None

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """
        Eagerly initialise the NeMo engine.
        Called once at startup — do not call per request.
        """
        if self._initialized:
            return

        _apply_telemetry_opt_out(self._settings)

        try:
            config_dir = resolve_config_path(
                base_path=self._settings.nemo_config_path,
                profile=self._settings.nemo_profile,
            )
            self._active_config_path = config_dir

            # Late import — telemetry opt-out must happen first
            from nemoguardrails import Guardrails  # type: ignore[import]

            rails_config = load_rails_config(config_dir)
            self._rails = Guardrails(rails_config)
            self._initialized = True
            self._init_error = None
            log.info(
                "nemo_engine_initialized",
                profile=self._active_profile,
                config=str(config_dir),
            )
        except NemoNotInstalledError as exc:
            self._init_error = str(exc)
            log.warning("nemo_not_installed", detail=str(exc))
            raise
        except NemoConfigError as exc:
            self._init_error = str(exc)
            log.error("nemo_config_error", detail=str(exc))
            raise
        except Exception as exc:
            self._init_error = f"Unexpected NeMo init error: {exc}"
            log.error("nemo_engine_init_failed", error=str(exc))
            raise NemoEngineError(self._init_error) from exc

    def is_available(self) -> bool:
        return self._initialized and self._rails is not None

    # ------------------------------------------------------------------
    # Core check helpers
    # ------------------------------------------------------------------

    async def check_input(self, content: str) -> "_NemoCheckResult":
        """
        Run configured input rails on user/document content.
        Returns a _NemoCheckResult (status, content, rail).
        """
        return await self._check(
            messages=[{"role": "user", "content": content}],
            rail_types=["input"],
        )

    async def check_output(self, content: str) -> "_NemoCheckResult":
        """
        Run configured output rails on assistant/terminal content.
        Returns a _NemoCheckResult (status, content, rail).
        """
        return await self._check(
            messages=[{"role": "assistant", "content": content}],
            rail_types=["output"],
        )

    async def _check(
        self,
        messages: list[dict],
        rail_types: list[str],
    ) -> "_NemoCheckResult":
        if not self._initialized or self._rails is None:
            raise NemoEngineError(
                f"NeMo engine not initialised. Error: {self._init_error or 'unknown'}"
            )

        timeout = self._settings.nemo_timeout

        try:
            # Build RailType list from the nemoguardrails enum
            from nemoguardrails.rails.llm.options import RailType  # type: ignore[import]

            rt_map = {"input": RailType.INPUT, "output": RailType.OUTPUT}
            rt_list = [rt_map[r] for r in rail_types if r in rt_map]

            coro = self._rails.check_async(
                messages=messages,
                rail_types=rt_list if rt_list else None,
            )
            raw_result = await asyncio.wait_for(coro, timeout=float(timeout))
            return _NemoCheckResult.from_rails_result(raw_result)

        except asyncio.TimeoutError as exc:
            raise NemoTimeoutError(timeout) from exc
        except ImportError as exc:
            raise NemoNotInstalledError() from exc
        except Exception as exc:
            # Catch RailTypeNotConfiguredError and other NeMo exceptions
            cls_name = type(exc).__name__
            log.warning("nemo_check_error", error_type=cls_name, detail=str(exc))
            raise NemoEngineError(f"NeMo check failed ({cls_name}): {exc}") from exc

    # ------------------------------------------------------------------
    # Status reporting (for health endpoint)
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Return a safe status dict — no secrets, no content."""
        try:
            import nemoguardrails  # type: ignore[import]
            pkg_version = nemoguardrails.__version__
        except ImportError:
            pkg_version = "not_installed"

        return {
            "enabled": self._settings.nemo_enabled,
            "initialized": self._initialized,
            "package_version": pkg_version,
            "profile": self._active_profile,
            "config_path": str(self._active_config_path) if self._active_config_path else None,
            "init_error": self._init_error,
            "timeout_seconds": self._settings.nemo_timeout,
            "fail_closed": self._settings.nemo_fail_closed,
            "telemetry_disabled": self._settings.nemo_telemetry_disabled,
        }


# ---------------------------------------------------------------------------
# Lightweight result container
# ---------------------------------------------------------------------------


class _NemoCheckResult:
    """
    Normalised result from a NeMo rails check.
    Decoupled from the nemoguardrails internal types so callers
    don't need to import nemoguardrails to read results.
    """

    PASSED = "PASSED"
    MODIFIED = "MODIFIED"
    BLOCKED = "BLOCKED"

    def __init__(
        self,
        status: str,
        content: str,
        rail: Optional[str] = None,
    ) -> None:
        self.status = status          # "PASSED" | "MODIFIED" | "BLOCKED"
        self.content = content        # final content after rails processing
        self.rail = rail              # name of blocking rail (BLOCKED only)

    @classmethod
    def from_rails_result(cls, result: Any) -> "_NemoCheckResult":
        """Convert a nemoguardrails RailsResult to our normalised type."""
        try:
            from nemoguardrails.rails.llm.options import RailStatus  # type: ignore[import]
            status_map = {
                RailStatus.PASSED: cls.PASSED,
                RailStatus.MODIFIED: cls.MODIFIED,
                RailStatus.BLOCKED: cls.BLOCKED,
            }
            status = status_map.get(result.status, cls.BLOCKED)
        except (ImportError, AttributeError):
            # Fallback: inspect the status value directly
            raw = str(getattr(result, "status", "BLOCKED")).upper()
            if "PASSED" in raw:
                status = cls.PASSED
            elif "MODIFIED" in raw:
                status = cls.MODIFIED
            else:
                status = cls.BLOCKED

        content = str(getattr(result, "content", "") or "")
        rail = getattr(result, "rail", None)

        return cls(status=status, content=content, rail=rail)

    def __repr__(self) -> str:
        return f"_NemoCheckResult(status={self.status!r}, rail={self.rail!r})"
