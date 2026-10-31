"""
Test fixtures — Mock NeMo engine and helpers.

All NeMo tests use these mocks so the test suite never requires the
nemoguardrails package to be installed.  Tests that need real NeMo
inference are marked @pytest.mark.nemo_model and skipped by default.
"""

from __future__ import annotations

from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock


# ---------------------------------------------------------------------------
# Mock _NemoCheckResult
# ---------------------------------------------------------------------------

class MockNemoCheckResult:
    PASSED = "PASSED"
    MODIFIED = "MODIFIED"
    BLOCKED = "BLOCKED"

    def __init__(self, status: str, content: str = "", rail: Optional[str] = None):
        self.status = status
        self.content = content
        self.rail = rail


def make_passed_result(content: str = "safe content") -> MockNemoCheckResult:
    return MockNemoCheckResult(status="PASSED", content=content)


def make_modified_result(content: str = "modified content") -> MockNemoCheckResult:
    return MockNemoCheckResult(status="MODIFIED", content=content)


def make_blocked_result(rail: str = "check jailbreak") -> MockNemoCheckResult:
    return MockNemoCheckResult(status="BLOCKED", content="", rail=rail)


# ---------------------------------------------------------------------------
# Mock NemoEngine
# ---------------------------------------------------------------------------

class MockNemoEngine:
    """
    A mock NemoEngine that never calls actual nemoguardrails.
    Behaviour is controlled per test via set_input_result / set_output_result.
    """

    def __init__(
        self,
        input_result: Optional[MockNemoCheckResult] = None,
        output_result: Optional[MockNemoCheckResult] = None,
    ):
        self._input_result = input_result or make_passed_result()
        self._output_result = output_result or make_passed_result()
        self._initialized = True
        self._init_error = None
        self._active_profile = "mock"
        self._active_config_path = None
        self._settings = _MockSettings()

    def set_input_result(self, result: MockNemoCheckResult) -> None:
        self._input_result = result

    def set_output_result(self, result: MockNemoCheckResult) -> None:
        self._output_result = result

    def is_available(self) -> bool:
        return self._initialized

    async def check_input(self, content: str) -> MockNemoCheckResult:
        return self._input_result

    async def check_output(self, content: str) -> MockNemoCheckResult:
        return self._output_result

    def status(self) -> dict:
        return {
            "enabled": True,
            "initialized": True,
            "package_version": "mock",
            "profile": "mock",
            "config_path": None,
            "init_error": None,
            "timeout_seconds": 30,
            "fail_closed": True,
            "telemetry_disabled": True,
        }


class UnavailableMockNemoEngine(MockNemoEngine):
    """Simulates a NeMo engine that failed to initialise."""

    def __init__(self):
        super().__init__()
        self._initialized = False
        self._init_error = "NeMo not available (simulated)"

    def is_available(self) -> bool:
        return False

    async def check_input(self, content: str) -> MockNemoCheckResult:
        from app.integrations.nemo.exceptions import NemoEngineError
        raise NemoEngineError("Engine not initialized (simulated)")

    async def check_output(self, content: str) -> MockNemoCheckResult:
        from app.integrations.nemo.exceptions import NemoEngineError
        raise NemoEngineError("Engine not initialized (simulated)")


class TimeoutMockNemoEngine(MockNemoEngine):
    """Simulates a NeMo engine that always times out."""

    async def check_input(self, content: str) -> MockNemoCheckResult:
        from app.integrations.nemo.exceptions import NemoTimeoutError
        raise NemoTimeoutError(30)

    async def check_output(self, content: str) -> MockNemoCheckResult:
        from app.integrations.nemo.exceptions import NemoTimeoutError
        raise NemoTimeoutError(30)


# ---------------------------------------------------------------------------
# Minimal mock settings object used inside MockNemoEngine
# ---------------------------------------------------------------------------

class _MockSettings:
    nemo_enabled = True
    nemo_max_content_chars = 50_000
    nemo_timeout = 30
    nemo_fail_closed = True
    nemo_telemetry_disabled = True
    nemo_profile = "mock"
    nemo_config_path = "configs/nemo"
    nemo_inspect_documents = True
    nemo_inspect_terminal_output = True
