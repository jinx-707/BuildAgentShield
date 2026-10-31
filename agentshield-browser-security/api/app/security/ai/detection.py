"""AI Agent Security detection, DLP, risk, and orchestration modules for Prompt 3.

These modules sit on top of the existing enforcement architecture
(DatabasePolicyEngine -> BrowserSecurityOrchestrator -> Browser Worker ->
Egress Proxy) and add AI-agent-specific threat detection, data loss
prevention, permission governance, and explainable risk scoring.

Security design principles (non-negotiable):
- An LLM classifier is never the only security boundary. Critical actions are
  controlled by deterministic policy enforcement.
- No raw secrets or sensitive values are ever logged or persisted.
- Every record is organization-scoped; cross-tenant access is impossible by
  construction.
- Detections are best-effort heuristics; we never claim perfect
  prompt-injection prevention.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared data structures
# ---------------------------------------------------------------------------


@dataclass
class Detection:
    """A single detection from a detection module."""

    rule_id: str
    module: str
    category: str
    severity: str  # low, medium, high, critical
    reason: str
    target: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: int = 50  # 0-100


@dataclass
class DetectionResult:
    """Aggregated result from all detection modules."""

    detections: list[Detection] = field(default_factory=list)
    blocked: bool = False
    action: str = "allow"  # allow, deny, redact, require_approval
    risk_score: int = 0  # 0-100

    @property
    def highest_severity(self) -> str:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        best = "none"
        for d in self.detections:
            if order.get(d.severity, 0) > order.get(best, 0):
                best = d.severity
        return best

    def to_dict(self) -> dict[str, Any]:
        return {
            "detections": [
                {
                    "rule_id": d.rule_id,
                    "module": d.module,
                    "category": d.category,
                    "severity": d.severity,
                    "reason": d.reason,
                    "target": d.target,
                    "confidence": d.confidence,
                }
                for d in self.detections
            ],
            "blocked": self.blocked,
            "action": self.action,
            "risk_score": self.risk_score,
            "highest_severity": self.highest_severity,
        }


# ---------------------------------------------------------------------------
# Threat detection engine
# ---------------------------------------------------------------------------


class ThreatDetectionEngine:
    """Modular threat detection for AI agent actions and content.

    Each module is deterministic and pattern-based. No LLM is relied upon as a
    security boundary.
    """

    name = "threat-detection-engine"

    # Indirect prompt injection patterns found in untrusted content.
    INJECTION_PATTERNS = [
        (
            "PI-001",
            "critical",
            r"(?i)ignore\s+(?:previous|prior|above|all)\s+(?:instructions?|prompts?|rules?|directives?)",
            "instruction to ignore previous instructions",
        ),
        (
            "PI-002",
            "critical",
            r"(?i)(?:disregard|forget|ignore)\s+(?:the\s+)?(?:above|previous|prior|all)\s+",
            "instruction to disregard prior content",
        ),
        (
            "PI-003",
            "critical",
            r"(?i)you\s+are\s+now\s+(?:a|an|the)\s+\w+",
            "role manipulation attempt",
        ),
        (
            "PI-004",
            "critical",
            r"(?i)(?:reveal|show|print|display|output)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|directives?)",
            "request to reveal system prompt",
        ),
        (
            "PI-005",
            "high",
            r"(?i)(?:send|transmit|email|post)\s+(?:the\s+)?(?:user'?s\s+)?(?:credentials|password|token|api key|secret)",
            "request to exfiltrate credentials",
        ),
    ]

    # Malicious webpage instruction patterns.
    MALICIOUS_PAGE_PATTERNS = [
        (
            "MW-001",
            "high",
            r"(?i)(?:javascript:|data:text/html|vbscript:)",
            "suspicious URI scheme in content",
        ),
        (
            "MW-002",
            "medium",
            r"(?i)(?:eval|setTimeout|setInterval|Function\()\s*\(",
            "dynamic code execution pattern",
        ),
    ]

    # Suspicious navigation patterns.
    NAVIGATION_PATTERNS = [
        (
            "SN-001",
            "high",
            r"169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200",
            "cloud metadata endpoint access attempt",
        ),
        (
            "SN-002",
            "high",
            r"(?i)(?:localhost|127\.0\.0\.1|::1|0\.0\.0\.0)",
            "localhost/loopback access attempt",
        ),
        (
            "SN-003",
            "medium",
            r"(?i)(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)",
            "private network access attempt",
        ),
    ]

    # Data exfiltration patterns.
    EXFILTRATION_PATTERNS = [
        (
            "DX-001",
            "high",
            r"(?i)(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*[^\s&]+",
            "possible secret in outbound data",
        ),
        (
            "DX-002",
            "medium",
            r"(?i)(?:credit.?card|ssn|social.?security|passport)",
            "possible sensitive identifier in outbound data",
        ),
    ]

    def __init__(self) -> None:
        self._compiled_injection = [
            (rid, sev, re.compile(pat), desc)
            for rid, sev, pat, desc in self.INJECTION_PATTERNS
        ]
        self._compiled_malicious = [
            (rid, sev, re.compile(pat), desc)
            for rid, sev, pat, desc in self.MALICIOUS_PAGE_PATTERNS
        ]
        self._compiled_nav = [
            (rid, sev, re.compile(pat), desc)
            for rid, sev, pat, desc in self.NAVIGATION_PATTERNS
        ]
        self._compiled_exfil = [
            (rid, sev, re.compile(pat), desc)
            for rid, sev, pat, desc in self.EXFILTRATION_PATTERNS
        ]

    def detect_content(self, *, content: str, request_id: str) -> DetectionResult:
        """Scan untrusted content for injection and malicious instructions."""
        result = DetectionResult()
        text = content or ""

        for rid, sev, pattern, desc in self._compiled_injection:
            for m in pattern.finditer(text):
                result.detections.append(
                    Detection(
                        rule_id=rid,
                        module="prompt-injection",
                        category="indirect_prompt_injection",
                        severity=sev,
                        reason=desc,
                        target="content",
                        evidence={"matched": m.group()[:200], "offset": m.start()},
                        confidence=80,
                    )
                )
                result.blocked = True
                result.action = "deny"

        for rid, sev, pattern, desc in self._compiled_malicious:
            for m in pattern.finditer(text):
                result.detections.append(
                    Detection(
                        rule_id=rid,
                        module="malicious-content",
                        category="malicious_webpage_instructions",
                        severity=sev,
                        reason=desc,
                        target="content",
                        evidence={"matched": m.group()[:200], "offset": m.start()},
                        confidence=70,
                    )
                )
                result.blocked = True
                result.action = "deny"

        result.risk_score = self._score(result.detections)
        return result

    def detect_navigation(self, *, url: str, request_id: str) -> DetectionResult:
        """Scan a navigation target for suspicious destinations."""
        result = DetectionResult()
        text = url or ""

        for rid, sev, pattern, desc in self._compiled_nav:
            if pattern.search(text):
                result.detections.append(
                    Detection(
                        rule_id=rid,
                        module="navigation",
                        category="suspicious_navigation",
                        severity=sev,
                        reason=desc,
                        target=url,
                        confidence=85,
                    )
                )
                result.blocked = True
                result.action = "deny"

        result.risk_score = self._score(result.detections)
        return result

    def detect_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any],
        request_id: str,
    ) -> DetectionResult:
        """Scan a tool invocation for misuse patterns."""
        result = DetectionResult()
        payload = str(tool_args or {})

        for rid, sev, pattern, desc in self._compiled_exfil:
            if pattern.search(payload):
                result.detections.append(
                    Detection(
                        rule_id=rid,
                        module="data-exfiltration",
                        category="data_exfiltration_attempt",
                        severity=sev,
                        reason=desc,
                        target=tool_name,
                        confidence=75,
                    )
                )
                result.blocked = True
                result.action = "deny"

        result.risk_score = self._score(result.detections)
        return result

    @staticmethod
    def _score(detections: list[Detection]) -> int:
        if not detections:
            return 0
        weights = {"low": 10, "medium": 25, "high": 50, "critical": 90}
        score = sum(weights.get(d.severity, 25) * (d.confidence / 100) for d in detections)
        return min(100, int(round(score)))
