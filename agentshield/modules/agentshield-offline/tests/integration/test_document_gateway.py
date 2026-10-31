"""
Integration tests — Document Analysis Gateway.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.contracts import (
    DocumentAnalysisRequest,
    MalwareScanStatus,
    OfflineModule,
    ResponseStatus,
    SecurityDecision,
)


class TestDocumentGatewayIntegration:
    @pytest.mark.asyncio
    async def test_analyzes_safe_txt(self, document_gateway, sample_txt_file):
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(sample_txt_file),
            run_malware_scan=True,
        )
        resp = await document_gateway.analyze(req)
        # Scanner is unavailable in tests but fail_closed=False
        assert resp.decision == SecurityDecision.ALLOW
        assert resp.status == ResponseStatus.EXECUTED
        assert resp.module == OfflineModule.DOCUMENT_ANALYSIS
        result = resp.result
        assert result is not None
        assert result["file_format"] == "txt"
        assert result["trust_level"] == "UNTRUSTED"
        assert result["extracted_text_length"] > 0

    @pytest.mark.asyncio
    async def test_rejects_spoofed_pdf(self, document_gateway, spoofed_extension_file):
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(spoofed_extension_file),
            run_malware_scan=False,
        )
        resp = await document_gateway.analyze(req)
        assert resp.decision == SecurityDecision.DENY
        assert "signature" in (resp.reason or "").lower()

    @pytest.mark.asyncio
    async def test_analyzes_json_document(self, document_gateway, sample_json_file):
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(sample_json_file),
            run_malware_scan=False,
        )
        resp = await document_gateway.analyze(req)
        assert resp.decision == SecurityDecision.ALLOW
        result = resp.result
        assert result["file_format"] == "json"

    @pytest.mark.asyncio
    async def test_analyzes_csv_document(self, document_gateway, sample_csv_file):
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(sample_csv_file),
            run_malware_scan=False,
        )
        resp = await document_gateway.analyze(req)
        assert resp.decision == SecurityDecision.ALLOW

    @pytest.mark.asyncio
    async def test_content_hash_present(self, document_gateway, sample_txt_file):
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(sample_txt_file),
            run_malware_scan=False,
        )
        resp = await document_gateway.analyze(req)
        assert resp.result is not None
        assert len(resp.result["content_hash"]) == 64  # SHA-256 hex

    @pytest.mark.asyncio
    async def test_nonexistent_file_denied(self, document_gateway, tmp_path):
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(tmp_path / "nonexistent.txt"),
            run_malware_scan=False,
        )
        resp = await document_gateway.analyze(req)
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.asyncio
    async def test_injection_content_flagged(self, document_gateway, injection_txt_file):
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(injection_txt_file),
            run_malware_scan=False,
        )
        resp = await document_gateway.analyze(req)
        # Should either be flagged or quarantined
        assert resp.decision in (
            SecurityDecision.ALLOW,       # allowed with findings
            SecurityDecision.QUARANTINE,  # quarantined due to findings
        )
        if resp.decision == SecurityDecision.ALLOW:
            # Must have security findings
            assert len(resp.security_findings) > 0

    @pytest.mark.asyncio
    async def test_scanner_unavailable_fail_closed(
        self, content_inspector, tmp_path, tmp_quarantine
    ):
        """With fail_closed=True, scanner unavailable → deny."""
        from app.capabilities.offline.documents.document_inspector import DocumentInspector
        from app.capabilities.offline.documents.gateway import DocumentGateway
        from app.capabilities.offline.documents.quarantine import QuarantineManager

        class UnavailableScanner:
            def scan_file(self, path):
                return MalwareScanStatus.SCANNER_UNAVAILABLE, None

        doc_inspector = DocumentInspector(content_inspector, fail_closed=False)
        gw = DocumentGateway(
            inspector=doc_inspector,
            scanner=UnavailableScanner(),
            quarantine=QuarantineManager(str(tmp_quarantine)),
            fail_closed_on_scan_unavailable=True,  # fail closed
        )
        f = tmp_path / "test.txt"
        f.write_text("Safe content")
        req = DocumentAnalysisRequest(
            agent_id="test-agent",
            tool_name="analyze_document",
            operation="analyze",
            file_path=str(f),
            run_malware_scan=True,
        )
        resp = await gw.analyze(req)
        assert resp.decision == SecurityDecision.DENY
        assert "unavailable" in (resp.reason or "").lower()
