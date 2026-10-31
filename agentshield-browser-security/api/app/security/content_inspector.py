"""Prompt injection content inspector.

Detects common prompt injection patterns in untrusted webpage content
and produces structured findings with severity levels and trust labels.

This is a heuristic detector, not a complete security control. It
identifies suspicious patterns that warrant attention but cannot
guarantee detection of all injection attempts. Content returned from
the browser must always be treated as untrusted regardless of
inspection results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from app.interfaces.inspection import ContentInspectionRequest, ContentInspector
from app.schemas.browser import Finding, InspectionResult


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Prompt injection detection patterns.
# Each pattern is (rule_id, severity, regex, description).
INJECTION_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "PI-001",
        "critical",
        re.compile(
            r"(?i)ignore\s+(?:previous|prior|above|all)\s+(?:instructions?|prompts?|rules?|directives?)",
        ),
        "instruction to ignore previous instructions",
    ),
    (
        "PI-002",
        "critical",
        re.compile(
            r"(?i)(?:disregard|forget|ignore)\s+(?:the\s+)?(?:above|previous|prior|all)\s+",
        ),
        "instruction to disregard prior content",
    ),
    (
        "PI-003",
        "critical",
        re.compile(
            r"(?i)you\s+are\s+now\s+(?:a|an|the)\s+\w+",
        ),
        "role manipulation attempt",
    ),
    (
        "PI-004",
        "critical",
        re.compile(
            r"(?i)(?:reveal|show|print|display|output)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|directives?)",
        ),
        "request to reveal system prompt",
    ),
    (
        "PI-005",
        "high",
        re.compile(
            r"(?i)(?:execute|run|call|invoke)\s+(?:the\s+)?(?:command|function|tool|api|script)",
        ),
        "tool invocation manipulation",
    ),
    (
        "PI-006",
        "high",
        re.compile(
            r"(?i)(?:navigate|go|fetch|open|visit)\s+(?:to\s+)?(?:https?://|file://|ftp://)",
        ),
        "instruction to navigate to a specific URL",
    ),
    (
        "PI-007",
        "high",
        re.compile(
            r"(?i)(?:secret|password|token|api[_\s-]?key|credential|private[_\s-]?key)",
        ),
        "request to expose credentials",
    ),
    (
        "PI-008",
        "medium",
        re.compile(
            r"(?i)act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a|an|the)\s+\w+",
        ),
        "persona injection attempt",
    ),
    (
        "PI-009",
        "medium",
        re.compile(
            r"(?i)do\s+not\s+(?:follow|adhere|comply)\s+(?:your|the)\s+(?:instructions?|rules?)",
        ),
        "instruction to not follow rules",
    ),
    (
        "PI-010",
        "medium",
        re.compile(
            r"<\s*!--\s*(?:.*?)(?:ignore|disregard|system|prompt|instruction)",
            re.DOTALL,
        ),
        "hidden instructions in HTML comments",
    ),
    (
        "PI-011",
        "low",
        re.compile(
            r"(?i)important\s*:\s*(?:you\s+must|you\s+should|please|now)",
        ),
        "urgency injection pattern",
    ),
    (
        "PI-012",
        "low",
        re.compile(
            r"(?i)\[INST\]|\[/INST\]|\[SYSTEM\]|\[/SYSTEM\]",
        ),
        "LLM tag injection attempt",
    ),
]

# Obfuscation detection patterns.
OBFUSCATION_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "PI-OBF-001",
        "medium",
        re.compile(r"(?i)atob\s*\("),
        "base64 decode instruction",
    ),
    (
        "PI-OBF-002",
        "medium",
        re.compile(
            r"(?i)(?:\\x[0-9a-f]{2}){3,}",
        ),
        "hex-encoded string",
    ),
    (
        "PI-OBF-003",
        "low",
        re.compile(
            r"(?i)&#x?[0-9a-f]+;",
        ),
        "HTML entity encoding",
    ),
]


class PromptInjectionInspector(ContentInspector):
    """Heuristic prompt injection detector for untrusted webpage content.

    Scans content for known prompt injection patterns and produces
    structured findings. This is defense-in-depth, not a guarantee.
    All browser-returned content must be treated as untrusted regardless
    of inspection results.
    """

    def __init__(self, *, max_scan_bytes: int = 1_048_576) -> None:
        self._max_scan_bytes = max_scan_bytes

    async def inspect(self, request: ContentInspectionRequest) -> InspectionResult:
        findings: list[Finding] = []

        content = request.content or ""
        if len(content) > self._max_scan_bytes:
            content = content[: self._max_scan_bytes]

        for rule_id, severity, pattern, description in INJECTION_PATTERNS:
            for match in pattern.finditer(content):
                start = match.start()
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=description,
                        location={
                            "offset": start,
                            "matched": match.group()[:200],
                        },
                    )
                )

        for rule_id, severity, pattern, description in OBFUSCATION_PATTERNS:
            for match in pattern.finditer(content):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=description,
                        location={
                            "offset": match.start(),
                            "matched": match.group()[:200],
                        },
                    )
                )

        has_findings = len(findings) > 0
        highest_severity = (
            max(f.severity for f in findings) if findings else "none"
        )

        return InspectionResult(
            inspector_name="prompt-injection-heuristic",
            findings=findings,
            trust_label="untrusted",
            content_classification=(
                "suspicious" if has_findings else "untrusted-clean"
            ),
            highest_severity=highest_severity,
            summary=(
                f"{len(findings)} potential prompt injection pattern(s) detected"
                if has_findings
                else "no known prompt injection patterns detected"
            ),
        )
