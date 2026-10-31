"""P1 integration exceptions."""

from __future__ import annotations
from app.core.exceptions import AgentShieldError, InspectorUnavailableError


class P1NotAvailableError(InspectorUnavailableError):
    """Raised when the penetration-prevention package cannot be imported."""
    def __init__(self) -> None:
        super().__init__(
            "Person 1's penetration-prevention module is not available. "
            "Add it to PYTHONPATH or install it, then set AGENTSHIELD_P1_ENABLED=true."
        )


class P1ConfigError(AgentShieldError):
    """Raised when P1 configuration or initialisation fails."""
    def __init__(self, message: str) -> None:
        super().__init__(message, code="P1_CONFIG_ERROR")


class P1InspectionError(AgentShieldError):
    """Raised when a P1 engine call fails unexpectedly."""
    def __init__(self, message: str) -> None:
        super().__init__(message, code="P1_INSPECTION_ERROR")
