"""
Integration tests — Audit event generation.
"""

from __future__ import annotations

import pytest

from app.core.contracts import (
    DocumentAnalysisRequest,
    FileReadRequest,
    SecurityDecision,
    SystemFileInspectRequest,
    FileOperation,
)


class TestAuditEventGeneration:
    @pytest.mark.asyncio
    async def test_audit_recorded_on_allow(self, runtime, audit_adapter, sample_txt_file):
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(sample_txt_file),
            run_malware_scan=False,
        )
        await runtime.analyze_document(req)
        assert len(audit_adapter.events) >= 1
        event = audit_adapter.last_event()
        assert event is not None
        assert event.agent_id == "test-agent"
        assert event.decision == SecurityDecision.ALLOW

    @pytest.mark.asyncio
    async def test_audit_recorded_on_deny(self, runtime, audit_adapter):
        import sys
        if sys.platform == "win32":
            pytest.skip("Linux path test")
        req = SystemFileInspectRequest(
            agent_id="test-agent",
            tool_name="system_file_inspect",
            operation="inspect",
            path="/etc/passwd",
            access_type=FileOperation.READ,
        )
        await runtime.inspect_system_path(req)
        event = audit_adapter.last_event()
        assert event is not None
        assert event.decision == SecurityDecision.DENY

    @pytest.mark.asyncio
    async def test_audit_never_contains_file_contents(self, runtime, audit_adapter, sample_txt_file):
        req = FileReadRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="read",
            file_path=str(sample_txt_file),
        )
        await runtime.read_file(req)
        for event in audit_adapter.events:
            # Audit metadata must not contain file contents
            assert "Hello, this is" not in str(event.metadata)

    @pytest.mark.asyncio
    async def test_audit_never_contains_secrets(self, runtime, audit_adapter):
        from app.core.contracts import SecretAccessRequest
        req = SecretAccessRequest(
            agent_id="test-agent",
            tool_name="secret_access",
            operation="retrieve",
            secret_id="test-secret",
        )
        await runtime.access_secret(req)
        for event in audit_adapter.events:
            # The actual secret value must never appear in audit logs
            assert "test-value-123" not in str(event.metadata)
            assert "test-value-123" not in str(event.reason or "")
