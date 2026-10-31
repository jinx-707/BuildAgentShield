"""
AgentShield Offline — Local Development Content Inspector.

⚠️  DEVELOPMENT COMPONENT — VERY LIMITED — NOT FOR PRODUCTION USE ⚠️

This inspector uses simple pattern matching to flag obvious prompt injection
patterns and is provided ONLY for functional demonstration and basic test
cases.

IT CANNOT RELIABLY DETECT SOPHISTICATED PROMPT INJECTION ATTACKS.

When Person 1's security engine is available (which includes proper ML-based
prompt injection detection, PII detection, and DLP policies), replace this
adapter through the dependency injection container.

See docs/integration_guide.md for replacement instructions.
"""

from __future__ import annotations

import re
from typing import Any, Optional

import structlog

from app.integrations.ports import ContentInspectionResult, DataInspectionResult

log = structlog.get_logger(__name__)

_ADAPTER_NOTE = (
    "LOCAL_DEVELOPMENT_INSPECTOR — rule-based only, NOT a production security control. "
    "Replace with Person 1's ML-based inspector."
)

# Very limited set of obvious injection indicators for demo/test purposes.
# This list is NOT comprehensive and MUST NOT be treated as complete coverage.
_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(previous|all|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted)", re.IGNORECASE),
    re.compile(r"disregard\s+(your\s+)?(safety|ethical|content)\s+(guidelines?|policy|policies)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s*mode", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"IGNORE ALL PREVIOUS", re.IGNORECASE),
    re.compile(r"new\s+instructions?:", re.IGNORECASE),
    re.compile(r"override\s+(previous\s+)?instructions?", re.IGNORECASE),
]

# Limited secret pattern detection for output redaction demo
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE)),
    ("aws_secret", re.compile(r"(?:aws.{0,20}secret|secret.{0,20}key)\s*[=:]\s*\S{20,}", re.IGNORECASE)),
    ("openai_key", re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE)),
    ("anthropic_key", re.compile(r"sk-ant-[a-zA-Z0-9\-]{10,}", re.IGNORECASE)),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}", re.IGNORECASE)),
    ("generic_password", re.compile(r"password\s*[=:]\s*\S{6,}", re.IGNORECASE)),
]


class LocalDevelopmentContentInspector:
    """
    Development-only content inspector.
    Uses basic regex matching to flag obvious patterns.
    MUST be replaced by Person 1's engine in production.
    """

    def __init__(self) -> None:
        log.warning(
            "local_content_inspector_active",
            note=_ADAPTER_NOTE,
        )

    async def inspect(
        self,
        content: str,
        *,
        source_metadata: Optional[dict[str, Any]] = None,
    ) -> ContentInspectionResult:
        findings = []
        for pattern in _INJECTION_PATTERNS:
            m = pattern.search(content)
            if m:
                findings.append(
                    {
                        "category": "prompt_injection_candidate",
                        "pattern": pattern.pattern,
                        "match": m.group(0)[:100],
                        "note": "Rule-based detection — may have false positives and false negatives",
                    }
                )

        passed = len(findings) == 0
        if not passed:
            log.warning(
                "content_inspection_flagged",
                finding_count=len(findings),
                source=source_metadata,
                note=_ADAPTER_NOTE,
            )
        return ContentInspectionResult(
            passed=passed,
            findings=findings,
            risk_score=min(1.0, len(findings) * 0.3),
            inspector="local_development_inspector",
            note=_ADAPTER_NOTE,
        )


class LocalDevelopmentDataInspector:
    """
    Development-only data / output inspector for secret detection.
    MUST be replaced by Person 1's DLP engine in production.
    """

    def __init__(self) -> None:
        log.warning(
            "local_data_inspector_active",
            note=_ADAPTER_NOTE,
        )

    async def inspect(
        self,
        content: str,
        *,
        context: Optional[dict[str, Any]] = None,
    ) -> DataInspectionResult:
        findings = []
        redacted = content

        for label, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(content):
                findings.append(
                    {
                        "category": "potential_secret",
                        "type": label,
                        "note": "Rule-based detection only",
                    }
                )
                # Replace with redaction marker — do NOT include the secret value
                redacted = redacted.replace(m.group(0), f"[REDACTED:{label.upper()}]")

        passed = len(findings) == 0
        return DataInspectionResult(
            passed=passed,
            redacted_content=redacted if not passed else None,
            findings=findings,
            inspector="local_development_data_inspector",
            note=_ADAPTER_NOTE,
        )
