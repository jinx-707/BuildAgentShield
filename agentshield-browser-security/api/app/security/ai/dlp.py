"""Data Loss Prevention engine for AgentShield Prompt 3.

Detects configurable sensitive patterns and supports redaction, blocking, and
audit logging. Raw sensitive values are never stored or logged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.security.ai.detection import Detection, DetectionResult


@dataclass
class DlpRule:
    """A single DLP detection rule."""

    rule_id: str
    name: str
    pattern: re.Pattern
    severity: str = "medium"
    confidence: int = 70
    action: str = "redact"  # redact, block, allow


class DlpEngine:
    """Configurable DLP engine.

    Detection is pattern-based (regex). We explicitly do not claim
    comprehensive DLP; this is a configurable regular-expression module.
    """

    name = "dlp-engine"

    DEFAULT_RULES: list[tuple[str, str, str, str, int, str]] = [
        (
            "DLP-001",
            "API Key",
            r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9_-]{16,}",
            "high",
            85,
            "block",
        ),
        (
            "DLP-002",
            "Auth Token",
            r"(?i)(?:authorization|bearer|token)\s*[:=]\s*[A-Za-z0-9._-]{16,}",
            "high",
            80,
            "block",
        ),
        (
            "DLP-003",
            "Password",
            r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[^\s&]{6,}",
            "high",
            80,
            "block",
        ),
        (
            "DLP-004",
            "Personal Information (SSN-like)",
            r"\b\d{3}-\d{2}-\d{4}\b",
            "medium",
            70,
            "redact",
        ),
        (
            "DLP-005",
            "Credit Card-like",
            r"\b(?:\d[ -]*?){13,16}\b",
            "medium",
            65,
            "redact",
        ),
        (
            "DLP-006",
            "Confidential Marker",
            r"(?i)\b(?:confidential|proprietary|internal only)\b",
            "low",
            60,
            "allow",
        ),
    ]

    def __init__(self, rules: list[DlpRule] | None = None) -> None:
        if rules is None:
            self._rules = [
                DlpRule(rule_id=rid, name=name, pattern=re.compile(pat), severity=sev, confidence=conf, action=act)
                for rid, name, pat, sev, conf, act in self.DEFAULT_RULES
            ]
        else:
            self._rules = list(rules)

    def inspect(self, *, content: str, request_id: str) -> DetectionResult:
        """Scan content for DLP violations. Returns detections and a redacted
        version is not returned here; callers use `redact()` separately."""
        result = DetectionResult()
        text = content or ""

        for rule in self._rules:
            for m in rule.pattern.finditer(text):
                result.detections.append(
                    Detection(
                        rule_id=rule.rule_id,
                        module="dlp",
                        category="sensitive_information_exposure",
                        severity=rule.severity,
                        reason=f"DLP match: {rule.name}",
                        target="content",
                        evidence={"matched": "[REDACTED]", "offset": m.start()},
                        confidence=rule.confidence,
                    )
                )
                if rule.action == "block":
                    result.blocked = True
                    result.action = "block"
                elif rule.action == "redact" and result.action not in ("block",):
                    result.action = "redact"

        result.risk_score = self._score(result.detections)
        return result

    def redact(self, content: str) -> str:
        """Return content with detected sensitive matches replaced by a safe
        placeholder. Raw values are never returned."""
        text = content or ""
        for rule in self._rules:
            text = rule.pattern.sub("[REDACTED]", text)
        return text

    @staticmethod
    def _score(detections: list[Detection]) -> int:
        if not detections:
            return 0
        weights = {"low": 10, "medium": 25, "high": 50, "critical": 90}
        score = sum(weights.get(d.severity, 25) * (d.confidence / 100) for d in detections)
        return min(100, int(round(score)))
