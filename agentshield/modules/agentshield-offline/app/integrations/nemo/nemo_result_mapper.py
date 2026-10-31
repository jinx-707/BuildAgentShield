"""
AgentShield Offline — NeMo result → AgentShield contract mapper.

Translates _NemoCheckResult into the existing InspectionStatus /
ContentInspectionResult / DataInspectionResult contracts so the rest of
the module never needs to know whether NeMo or the local dev inspector ran.
"""

from __future__ import annotations

from typing import Any, Optional

from app.core.contracts import InspectionStatus, RiskLevel, SecurityFinding
from app.integrations.nemo.nemo_engine import _NemoCheckResult
from app.integrations.ports import ContentInspectionResult, DataInspectionResult


def map_to_content_result(
    nemo_result: _NemoCheckResult,
    *,
    original_content: str,
    source_metadata: Optional[dict[str, Any]] = None,
) -> ContentInspectionResult:
    """
    Convert a _NemoCheckResult to a ContentInspectionResult.

    Mapping:
      PASSED  → passed=True,  findings=[]
      MODIFIED → passed=True, findings=[note about modification]
      BLOCKED → passed=False, findings=[blocking rail finding]
    """
    if nemo_result.status == _NemoCheckResult.PASSED:
        return ContentInspectionResult(
            passed=True,
            findings=[],
            risk_score=0.0,
            inspector="nemo_guardrails",
            note="NeMo input rails: PASSED",
        )

    if nemo_result.status == _NemoCheckResult.MODIFIED:
        return ContentInspectionResult(
            passed=True,   # Modified but not blocked — content was sanitised
            findings=[
                {
                    "category": "nemo_content_modified",
                    "pattern": "nemo_input_rail_modification",
                    "match": "",
                    "note": (
                        "NeMo input rails modified the content but did not block it. "
                        "Modified content is used."
                    ),
                }
            ],
            risk_score=0.2,
            inspector="nemo_guardrails",
            note="NeMo input rails: MODIFIED",
        )

    # BLOCKED
    rail_name = nemo_result.rail or "unknown_rail"
    return ContentInspectionResult(
        passed=False,
        findings=[
            {
                "category": "nemo_input_blocked",
                "pattern": f"nemo_rail:{rail_name}",
                "match": nemo_result.content[:200] if nemo_result.content else "",
                "note": f"NeMo Guardrails blocked input via rail: {rail_name}",
            }
        ],
        risk_score=1.0,
        inspector="nemo_guardrails",
        note=f"NeMo input rails: BLOCKED by {rail_name}",
    )


def map_to_data_result(
    nemo_result: _NemoCheckResult,
    *,
    original_content: str,
) -> DataInspectionResult:
    """
    Convert a _NemoCheckResult to a DataInspectionResult.

    For output rails:
      PASSED   → passed=True,  no redaction
      MODIFIED → passed=False, redacted_content = nemo_result.content
      BLOCKED  → passed=False, redacted_content = "" (content withheld)
    """
    if nemo_result.status == _NemoCheckResult.PASSED:
        return DataInspectionResult(
            passed=True,
            redacted_content=None,
            findings=[],
            inspector="nemo_guardrails",
            note="NeMo output rails: PASSED",
        )

    if nemo_result.status == _NemoCheckResult.MODIFIED:
        return DataInspectionResult(
            passed=False,
            redacted_content=nemo_result.content,
            findings=[
                {
                    "category": "nemo_output_modified",
                    "type": "nemo_rail_modification",
                    "note": "NeMo output rails modified the content",
                }
            ],
            inspector="nemo_guardrails",
            note="NeMo output rails: MODIFIED",
        )

    # BLOCKED — withhold the content entirely
    rail_name = nemo_result.rail or "unknown_rail"
    return DataInspectionResult(
        passed=False,
        redacted_content="[OUTPUT BLOCKED BY NEMO GUARDRAILS]",
        findings=[
            {
                "category": "nemo_output_blocked",
                "type": f"nemo_rail:{rail_name}",
                "note": f"NeMo Guardrails blocked output via rail: {rail_name}",
            }
        ],
        inspector="nemo_guardrails",
        note=f"NeMo output rails: BLOCKED by {rail_name}",
    )


def map_to_inspection_status(
    ci_result: ContentInspectionResult,
) -> tuple[InspectionStatus, list[SecurityFinding]]:
    """
    Convert a ContentInspectionResult to the (InspectionStatus, findings)
    tuple expected by DocumentInspector.
    """
    findings: list[SecurityFinding] = []
    for raw in ci_result.findings:
        findings.append(
            SecurityFinding(
                severity=RiskLevel.HIGH if ci_result.risk_score > 0.5 else RiskLevel.MEDIUM,
                category=raw.get("category", "nemo_finding"),
                description=raw.get("pattern", raw.get("note", "")),
                evidence=raw.get("match", "")[:200],
                recommendation="Content flagged by NeMo Guardrails — review before use",
            )
        )

    if not ci_result.passed:
        return InspectionStatus.FLAGGED, findings
    return InspectionStatus.PASSED, findings
