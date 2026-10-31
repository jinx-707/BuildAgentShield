"""
AgentShield Offline — Document Analysis Gateway.

Orchestrates the full document security pipeline:
  1. File validation (existence, size, signature, MIME)
  2. Malware scanning via ClamAV
  3. Document parsing (text + metadata extraction)
  4. Content inspection (injection, PII) via ContentInspectionPort
  5. Quarantine if needed
  6. Return structured result

Extracted document content is ALWAYS tagged as UNTRUSTED.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

import structlog

from app.capabilities.offline.documents.document_inspector import DocumentInspector
from app.capabilities.offline.documents.file_validator import FileValidator
from app.capabilities.offline.documents.malware_scanner import ClamAVScanner
from app.capabilities.offline.documents.parser import DocumentParser
from app.capabilities.offline.documents.quarantine import QuarantineManager
from app.core.contracts import (
    BaseOfflineResponse,
    DocumentAnalysisRequest,
    DocumentAnalysisResult,
    ExtractionStatus,
    InspectionStatus,
    MalwareScanStatus,
    OfflineModule,
    RiskLevel,
    SecurityDecision,
    SecurityFinding,
)
from app.core.decisions import allow_response, deny_response, quarantine_response
from app.core.exceptions import DocumentParseError, DocumentSizeLimitError, UnsupportedFormatError
from app.utils.file_hashing import sha256_file

log = structlog.get_logger(__name__)
_MODULE = OfflineModule.DOCUMENT_ANALYSIS
_TOOL = "analyze_document"


class DocumentGateway:
    """
    Single enforcement point for all document analysis operations.
    """

    def __init__(
        self,
        inspector: DocumentInspector,
        scanner: ClamAVScanner,
        quarantine: QuarantineManager,
        fail_closed_on_scan_unavailable: bool = True,
    ) -> None:
        self._validator = FileValidator()
        self._parser = DocumentParser()
        self._inspector = inspector
        self._scanner = scanner
        self._quarantine = quarantine
        self._fail_closed = fail_closed_on_scan_unavailable

    async def analyze(
        self, request: DocumentAnalysisRequest
    ) -> BaseOfflineResponse:
        document_id = str(uuid.uuid4())
        path = Path(request.file_path)
        findings: list[SecurityFinding] = []

        # ----------------------------------------------------------------
        # Step 1: File validation
        # ----------------------------------------------------------------
        try:
            fmt = self._validator.validate(path)
        except UnsupportedFormatError as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason=exc.message,
                risk_level=RiskLevel.MEDIUM,
            )
        except DocumentSizeLimitError as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason=exc.message,
                risk_level=RiskLevel.MEDIUM,
            )
        except Exception as exc:  # noqa: BLE001
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason=f"File validation error: {exc}",
                risk_level=RiskLevel.MEDIUM,
            )

        # ----------------------------------------------------------------
        # Step 2: Content hash
        # ----------------------------------------------------------------
        try:
            content_hash = sha256_file(path)
        except Exception:
            content_hash = "hash_unavailable"

        file_size = path.stat().st_size

        # ----------------------------------------------------------------
        # Step 3: Malware scan
        # ----------------------------------------------------------------
        malware_status = MalwareScanStatus.NOT_SCANNED
        threat_name: Optional[str] = None

        if request.run_malware_scan:
            malware_status, threat_name = self._scanner.scan_file(path)

            if malware_status == MalwareScanStatus.INFECTED:
                q_id = self._quarantine.quarantine(
                    path,
                    reason=f"Malware detected: {threat_name}",
                    original_hash=content_hash,
                    document_id=document_id,
                )
                findings.append(
                    SecurityFinding(
                        severity=RiskLevel.CRITICAL,
                        category="malware",
                        description=f"Malware detected: {threat_name}",
                        recommendation="File quarantined — do not use",
                    )
                )
                return quarantine_response(
                    request_id=request.request_id,
                    module=_MODULE,
                    tool=_TOOL,
                    reason=f"Malware detected: {threat_name}",
                    quarantine_id=q_id,
                    risk_level=RiskLevel.CRITICAL,
                    findings=findings,
                )

            if malware_status in (
                MalwareScanStatus.SCANNER_UNAVAILABLE,
                MalwareScanStatus.SCAN_FAILED,
            ):
                if self._fail_closed:
                    return deny_response(
                        request_id=request.request_id,
                        module=_MODULE,
                        tool=_TOOL,
                        reason=(
                            f"Malware scanner unavailable — cannot confirm file safety "
                            f"(status: {malware_status.value})"
                        ),
                        risk_level=RiskLevel.HIGH,
                    )
                # fail-open: continue with SCANNER_UNAVAILABLE status recorded

        # ----------------------------------------------------------------
        # Step 4: Document parsing
        # ----------------------------------------------------------------
        extraction_status = ExtractionStatus.SKIPPED
        parsed_text = ""
        page_count: Optional[int] = None
        metadata: dict = {}

        if request.extract_text or request.extract_metadata:
            try:
                parsed = await self._parser.parse(path, fmt)
                parsed_text = parsed.text
                page_count = parsed.page_count
                metadata = parsed.metadata
                extraction_status = ExtractionStatus.SUCCESS
            except DocumentParseError as exc:
                log.warning("document_parse_failed", error=exc.message, format=fmt)
                extraction_status = ExtractionStatus.FAILED
                findings.append(
                    SecurityFinding(
                        severity=RiskLevel.MEDIUM,
                        category="parse_error",
                        description=exc.message,
                        recommendation="Document may be malformed or intentionally crafted to crash parsers",
                    )
                )

        # ----------------------------------------------------------------
        # Step 5: Content inspection
        # ----------------------------------------------------------------
        inspection_status: InspectionStatus = InspectionStatus.SKIPPED
        inspection_findings: list[SecurityFinding] = []

        if parsed_text:
            inspection_status, inspection_findings = await self._inspector.inspect(
                parsed_text,
                document_id=document_id,
                file_format=fmt,
            )
            findings.extend(inspection_findings)

        # ----------------------------------------------------------------
        # Step 6: Decide trust level and response
        # ----------------------------------------------------------------
        # Determine overall risk
        has_critical = any(f.severity == RiskLevel.CRITICAL for f in findings)
        has_high = any(f.severity == RiskLevel.HIGH for f in findings)
        risk_level = (
            RiskLevel.CRITICAL if has_critical
            else RiskLevel.HIGH if has_high
            else RiskLevel.MEDIUM if findings
            else RiskLevel.LOW
        )

        # Documents from local disk are always UNTRUSTED
        trust_level = "UNTRUSTED"
        if inspection_status == InspectionStatus.FLAGGED:
            trust_level = "SUSPICIOUS"

        analysis_result = DocumentAnalysisResult(
            document_id=document_id,
            file_format=fmt,
            file_size=file_size,
            content_hash=content_hash,
            extraction_status=extraction_status,
            malware_scan_status=malware_status,
            inspection_status=inspection_status,
            trust_level=trust_level,
            page_count=page_count,
            extracted_text_length=len(parsed_text) if parsed_text else 0,
            metadata=metadata,
            security_findings=findings,
            quarantined=False,
        )

        # If content was flagged, quarantine the document
        if inspection_status == InspectionStatus.FLAGGED and has_high:
            q_id = self._quarantine.quarantine(
                path,
                reason="Content inspection flagged suspicious content",
                original_hash=content_hash,
                document_id=document_id,
                metadata={"inspection_status": inspection_status.value},
            )
            analysis_result.quarantined = True
            analysis_result.quarantine_id = q_id
            return quarantine_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=_TOOL,
                reason="Document content flagged by inspection",
                quarantine_id=q_id,
                risk_level=risk_level,
                findings=findings,
            )

        return allow_response(
            request_id=request.request_id,
            module=_MODULE,
            tool=_TOOL,
            result=analysis_result.model_dump(),
            risk_level=risk_level,
            findings=findings,
        )
