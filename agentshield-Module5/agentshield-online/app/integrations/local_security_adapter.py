"""
LOCAL DEVELOPMENT ONLY — Content and Data Inspection Adapters.

These are NOT production-grade detectors.
They perform basic heuristic checks to support standalone testing.
Replace with Person 1's shared security engine in production.

Clearly identified as development-only in all responses.
"""
from __future__ import annotations

import re
from typing import Any

from app.integrations.ports import (
    ContentInspectionPort,
    DataInspectionPort,
    InspectionFinding,
    InspectionResult,
)

INSPECTOR_ID = "LOCAL_DEV_INSPECTOR_NOT_FOR_PRODUCTION"

# Patterns for basic prompt-injection heuristics
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(previous|all|above|prior)\s+instruction", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+)?(?:a\s+)?different", re.IGNORECASE),
    re.compile(r"system\s+prompt\s*(override|bypass|ignore)", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"IGNORE\s+ALL\s+PREVIOUS", re.IGNORECASE),
    re.compile(r"disregard\s+your\s+(previous\s+)?instructions", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"override\s+safety", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
    re.compile(r"prompt\s+injection", re.IGNORECASE),
]

# Basic PII / sensitive data heuristics
_PII_PATTERNS = [
    (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "CREDIT_CARD_NUMBER", "HIGH"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN_PATTERN", "HIGH"),
    (re.compile(r"\bpassword\s*[:=]\s*\S+", re.IGNORECASE), "PASSWORD_FIELD", "HIGH"),
    (re.compile(r"\bapi[_-]?key\s*[:=]\s*\S+", re.IGNORECASE), "API_KEY_FIELD", "HIGH"),
    (re.compile(r"\bsecret\s*[:=]\s*\S+", re.IGNORECASE), "SECRET_FIELD", "HIGH"),
    (re.compile(r"\btoken\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}", re.IGNORECASE), "TOKEN_FIELD", "MEDIUM"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "EMAIL_ADDRESS", "LOW"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "PHONE_NUMBER", "LOW"),
    (re.compile(r"\b\d{10,16}\b"), "POTENTIAL_ACCOUNT_NUMBER", "LOW"),
]


class LocalContentInspectionAdapter(ContentInspectionPort):
    """
    Development-only content inspector.
    Checks for common prompt injection patterns.
    NOT equivalent to Person 1's production classifier.
    """

    async def inspect(
        self,
        content: str,
        source: str,
        metadata: dict[str, Any] | None = None,
    ) -> InspectionResult:
        findings: list[InspectionFinding] = []

        for pattern in _INJECTION_PATTERNS:
            if pattern.search(content):
                findings.append(
                    InspectionFinding(
                        finding_type="PROMPT_INJECTION_HEURISTIC",
                        severity="HIGH",
                        description=(
                            f"Potential prompt injection pattern detected in {source}. "
                            f"Pattern: {pattern.pattern[:60]}"
                        ),
                        location=source,
                    )
                )

        safe = len(findings) == 0
        return InspectionResult(
            safe_to_use=safe,
            findings=findings,
            summary=(
                f"[{INSPECTOR_ID}] {'No issues' if safe else str(len(findings)) + ' issue(s)'} "
                f"found in {source}"
            ),
            inspected_by=INSPECTOR_ID,
        )


class LocalDataInspectionAdapter(DataInspectionPort):
    """
    Development-only DLP adapter.
    Detects obvious PII/secret patterns via regex heuristics.
    NOT equivalent to Person 1's production DLP engine.
    """

    async def inspect(
        self,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> InspectionResult:
        findings: list[InspectionFinding] = []

        for pattern, finding_type, severity in _PII_PATTERNS:
            if pattern.search(content):
                findings.append(
                    InspectionFinding(
                        finding_type=finding_type,
                        severity=severity,
                        description=(
                            f"Potential {finding_type.replace('_', ' ').lower()} detected."
                        ),
                    )
                )

        high_severity = any(f.severity == "HIGH" for f in findings)
        return InspectionResult(
            safe_to_use=not high_severity,
            findings=findings,
            summary=(
                f"[{INSPECTOR_ID}] DLP check: "
                f"{'BLOCKED' if high_severity else 'PASS'} "
                f"({len(findings)} finding(s))"
            ),
            inspected_by=INSPECTOR_ID,
        )
