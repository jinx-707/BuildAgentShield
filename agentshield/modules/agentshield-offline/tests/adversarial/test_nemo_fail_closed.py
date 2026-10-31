"""
Adversarial tests — NeMo fail-closed behaviour.

Verifies that NeMo failures never silently pass content through.
Every failure mode must be handled explicitly.
"""

from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import pytest

from tests.fixtures.nemo.mock_engine import (
    MockNemoEngine,
    TimeoutMockNemoEngine,
    UnavailableMockNemoEngine,
    make_passed_result,
)
from app.integrations.nemo.nemo_inspector import NemoContentInspector, NemoDataInspector
from app.integrations.nemo.exceptions import (
    NemoEngineError,
    NemoNotInstalledError,
    NemoTimeoutError,
)
from app.core.exceptions import InspectorUnavailableError


@pytest.mark.adversarial
class TestNemoFailClosed:
    # ----- NemoContentInspector fail-closed -----

    @pytest.mark.asyncio
    async def test_content_timeout_fail_closed_raises(self):
        inspector = NemoContentInspector(TimeoutMockNemoEngine(), fail_closed=True)
        with pytest.raises(InspectorUnavailableError):
            await inspector.inspect("content")

    @pytest.mark.asyncio
    async def test_content_engine_unavailable_fail_closed_raises(self):
        inspector = NemoContentInspector(UnavailableMockNemoEngine(), fail_closed=True)
        with pytest.raises(InspectorUnavailableError):
            await inspector.inspect("content")

    @pytest.mark.asyncio
    async def test_content_timeout_fail_open_not_passed(self):
        """fail_closed=False on timeout returns not-inspected, never silently passes."""
        inspector = NemoContentInspector(TimeoutMockNemoEngine(), fail_closed=False)
        result = await inspector.inspect("content")
        assert result.passed is False
        assert result.inspector == "nemo_guardrails_unavailable"

    @pytest.mark.asyncio
    async def test_content_unavailable_fail_open_not_passed(self):
        inspector = NemoContentInspector(UnavailableMockNemoEngine(), fail_closed=False)
        result = await inspector.inspect("content")
        assert result.passed is False
        assert "unavailable" in result.note.lower() or "NOT inspected" in result.note

    # ----- NemoDataInspector fail-closed -----

    @pytest.mark.asyncio
    async def test_data_timeout_fail_closed_raises(self):
        inspector = NemoDataInspector(TimeoutMockNemoEngine(), fail_closed=True)
        with pytest.raises(InspectorUnavailableError):
            await inspector.inspect("content")

    @pytest.mark.asyncio
    async def test_data_engine_unavailable_fail_closed_raises(self):
        inspector = NemoDataInspector(UnavailableMockNemoEngine(), fail_closed=True)
        with pytest.raises(InspectorUnavailableError):
            await inspector.inspect("content")

    @pytest.mark.asyncio
    async def test_data_timeout_fail_open_not_passed(self):
        inspector = NemoDataInspector(TimeoutMockNemoEngine(), fail_closed=False)
        result = await inspector.inspect("content")
        assert result.passed is False

    # ----- Exception types -----

    @pytest.mark.asyncio
    async def test_nemo_engine_error_fail_closed(self):
        class ErrorEngine(MockNemoEngine):
            async def check_input(self, content):
                raise NemoEngineError("Unexpected NeMo failure")

        inspector = NemoContentInspector(ErrorEngine(), fail_closed=True)
        with pytest.raises(InspectorUnavailableError):
            await inspector.inspect("content")

    @pytest.mark.asyncio
    async def test_nemo_engine_error_fail_open_returns_not_inspected(self):
        class ErrorEngine(MockNemoEngine):
            async def check_input(self, content):
                raise NemoEngineError("Unexpected NeMo failure")

        inspector = NemoContentInspector(ErrorEngine(), fail_closed=False)
        result = await inspector.inspect("content")
        assert result.passed is False
        assert result.inspector == "nemo_guardrails_unavailable"

    @pytest.mark.asyncio
    async def test_not_installed_fail_closed(self):
        class NotInstalledEngine(MockNemoEngine):
            async def check_input(self, content):
                raise NemoNotInstalledError()

        inspector = NemoContentInspector(NotInstalledEngine(), fail_closed=True)
        with pytest.raises(InspectorUnavailableError):
            await inspector.inspect("content")

    # ----- Secret protection in failure mode -----

    @pytest.mark.asyncio
    async def test_secrets_not_leaked_in_fail_open_result(self):
        """Even in fail-open mode, secret values must never appear in findings."""
        inspector = NemoContentInspector(TimeoutMockNemoEngine(), fail_closed=False)
        secret_content = "OPENAI_API_KEY=sk-realkey12345 in this content"
        result = await inspector.inspect(secret_content)
        # The raw secret should not appear in any finding
        for finding in result.findings:
            assert "sk-realkey12345" not in str(finding)
        assert "sk-realkey12345" not in result.note

    @pytest.mark.asyncio
    async def test_existing_agentshield_permissions_unchanged_on_nemo_failure(
        self, tmp_path
    ):
        """
        When NeMo fails, AgentShield's own enforcement (filesystem, terminal, etc.)
        must remain fully operational and unchanged.
        """
        from app.capabilities.offline.system_files.gateway import SystemFileGateway
        from app.core.contracts import FileOperation, SecurityDecision, SystemFileInspectRequest
        import sys

        gw = SystemFileGateway()
        if sys.platform.startswith("win"):
            pytest.skip("Linux-only protected path test")

        req = SystemFileInspectRequest(
            agent_id="test-agent",
            tool_name="system_file_inspect",
            operation="inspect",
            path="/etc/passwd",
            access_type=FileOperation.READ,
        )
        resp = await gw.inspect(req)
        assert resp.decision == SecurityDecision.DENY, (
            "System file protection must work regardless of NeMo status"
        )
