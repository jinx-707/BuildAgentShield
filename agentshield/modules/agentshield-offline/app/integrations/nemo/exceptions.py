"""
AgentShield Offline — NeMo integration exceptions.

These extend the existing AgentShield exception hierarchy.
"""

from __future__ import annotations

from app.core.exceptions import AgentShieldError, InspectorUnavailableError


class NemoNotInstalledError(InspectorUnavailableError):
    """
    Raised when nemoguardrails is not installed but the NeMo inspector is
    requested.  Install with: pip install -e ".[nemo]"
    """

    def __init__(self) -> None:
        super().__init__(
            "nemoguardrails is not installed. "
            "Run: pip install -e '[nemo]' to enable NeMo Guardrails integration."
        )


class NemoConfigError(AgentShieldError):
    """Raised when the NeMo configuration is invalid or cannot be loaded."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="NEMO_CONFIG_ERROR")


class NemoEngineError(AgentShieldError):
    """Raised when the NeMo engine fails to initialise or execute."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="NEMO_ENGINE_ERROR")


class NemoTimeoutError(AgentShieldError):
    """Raised when a NeMo inspection call times out."""

    def __init__(self, timeout: int) -> None:
        super().__init__(
            f"NeMo inspection timed out after {timeout}s",
            code="NEMO_TIMEOUT",
        )
        self.timeout = timeout


class NemoRailTypeError(AgentShieldError):
    """Raised when a requested rail type is not configured."""

    def __init__(self, rail_type: str) -> None:
        super().__init__(
            f"Rail type '{rail_type}' is not configured in the active NeMo profile",
            code="NEMO_RAIL_TYPE_NOT_CONFIGURED",
        )
