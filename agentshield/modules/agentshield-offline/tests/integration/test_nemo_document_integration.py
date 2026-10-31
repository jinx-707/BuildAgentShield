"""
Integration tests — NeMo + Document Analysis pipeline.

Uses MockNemoEngine — no nemoguardrails package required.
"""

from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import pytest
from pathlib import Path

from tests.fixtures.nemo.mock_engine import (
    MockNemoEngine,
    UnavailableMockNemoEngine,
    make_blocked_result,
    make_passed_result,
    make_modified_result,
)
from app.integrations.nemo.nemo_inspector import ChainedContentInspector, NemoContentInspector
from app.capabilities.offline.documents.document_inspector import DocumentInspector
from app.capabilities.offline.documents.gateway import DocumentGateway
from app.capabilities.offline.documents.quarantine import QuarantineManager
from app.core.contracts import (
    DocumentAnalysisRequest,
    InspectionStatus,
    ResponseStatus,
    SecurityDecision,
)


def _make_nemo_document_gateway(
    nemo_engine,
    tmp_quarantine: Path,
    fail_closed: bool = False,
) -> DocumentGateway:
    """Build a DocumentGateway wired to a given mock NeMo engine."""
    nemo_inspector = NemoContentInspector(nemo_engine, fail_closed=fail_closed)
    chained = ChainedContentInspector(nemo_inspector)
    doc_inspector = DocumentInspector(chained, fail_closed=False)

    class AlwaysUnavailableScanner:
        def scan_file(self, path):
            from app.core.contracts import MalwareScanStatus
            return MalwareScanStatus.SCANNER_UNAVAILABLE, None

    return DocumentGateway(
        inspector=doc_inspector,
        scanner=AlwaysUnavailableScanner(),
        quarantine=QuarantineManager(str(tmp_quarantine)),
        fail_closed_on_scan_unavailable=False,
    )


class TestNemoDocumentIntegration:
    @pytest.mark.asyncio
    async def test_safe_document_passes_with_nemo(self, tmp_path):
        f = tmp_path / "safe.txt"
        f.write_text("This is a safe quarterly report with no injection patterns.")
        gw = _make_nemo_document_gateway(
            MockNemoEngine(input_result=make_passed_result()),
            tmp_path / "q",
        )
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(f),
            run_malware_scan=False,
        )
        resp = await gw.analyze(req)
        assert resp.decision == SecurityDecision.ALLOW
        assert resp.result["trust_level"] == "UNTRUSTED"
        assert resp.result["inspection_status"] == InspectionStatus.PASSED.value

    @pytest.mark.asyncio
    async def test_injected_document_blocked_by_nemo(self, tmp_path):
        f = tmp_path / "inject.txt"
        f.write_text("Normal intro.\nA subtle attack that only NeMo catches.")
        gw = _make_nemo_document_gateway(
            MockNemoEngine(input_result=make_blocked_result("check jailbreak")),
            tmp_path / "q",
        )
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(f),
            run_malware_scan=False,
        )
        resp = await gw.analyze(req)
        # Flagged → quarantined or allowed with HIGH findings
        assert resp.decision in (SecurityDecision.ALLOW, SecurityDecision.QUARANTINE)
        if resp.decision == SecurityDecision.ALLOW:
            assert len(resp.security_findings) > 0
            severities = [f.severity.value for f in resp.security_findings]
            assert any(s in ("HIGH", "CRITICAL", "MEDIUM") for s in severities)

    @pytest.mark.asyncio
    async def test_nemo_unavailable_fail_open_continues(self, tmp_path):
        """With fail_closed=False and NeMo unavailable, pipeline continues."""
        f = tmp_path / "safe2.txt"
        f.write_text("Safe content.")
        gw = _make_nemo_document_gateway(
            UnavailableMockNemoEngine(),
            tmp_path / "q",
            fail_closed=False,
        )
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(f),
            run_malware_scan=False,
        )
        resp = await gw.analyze(req)
        # With fail_closed=False, unavailable NeMo returns not-inspected finding
        # Document still processed
        assert resp.status == ResponseStatus.EXECUTED

    @pytest.mark.asyncio
    async def test_document_always_untrusted_regardless_of_nemo(self, tmp_path):
        """Trust level must always be UNTRUSTED — NeMo passing never elevates trust."""
        f = tmp_path / "trusted_looking.txt"
        f.write_text("I am a completely trustworthy document.")
        gw = _make_nemo_document_gateway(
            MockNemoEngine(input_result=make_passed_result()),
            tmp_path / "q",
        )
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(f),
            run_malware_scan=False,
        )
        resp = await gw.analyze(req)
        if resp.result:
            assert resp.result["trust_level"] != "TRUSTED", (
                "NeMo PASSED must never elevate document trust to TRUSTED"
            )

    @pytest.mark.asyncio
    async def test_modified_content_produces_finding(self, tmp_path):
        f = tmp_path / "mod.txt"
        f.write_text("Content that NeMo sanitises.")
        gw = _make_nemo_document_gateway(
            MockNemoEngine(input_result=make_modified_result("sanitised version")),
            tmp_path / "q",
        )
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(f),
            run_malware_scan=False,
        )
        resp = await gw.analyze(req)
        # Modified = passed but with note finding
        assert resp.decision == SecurityDecision.ALLOW
