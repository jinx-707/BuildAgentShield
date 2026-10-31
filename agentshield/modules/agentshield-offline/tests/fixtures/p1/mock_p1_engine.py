"""
Mock P1 engine objects for unit/integration tests.

These reproduce the exact interface that P1's SecurityEngine / InputGuard /
OutputGuard expose, without requiring presidio, spacy, or any P1 imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from unittest.mock import AsyncMock


# ─── Minimal schema stubs matching P1's schemas.py ───────────────────────────

class _Action:
    ALLOW = "allow"
    WARN = "warn"
    MASK = "mask"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class _RiskLevel:
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MockRiskScore:
    overall_score: float = 0.0
    level: Any = None
    recommended_action: Any = None
    component_scores: dict = field(default_factory=dict)
    factors: list = field(default_factory=list)

    def __post_init__(self):
        if self.level is None:
            self.level = type("RiskLevel", (), {"value": "safe"})()
        if self.recommended_action is None:
            self.recommended_action = type("Action", (), {"value": "allow"})()


@dataclass
class MockDetectionFinding:
    detector: Any
    rule_id: str
    description: str
    risk_score: float = 0.5
    start_index: Optional[int] = None
    end_index: Optional[int] = None
    redacted_value: Optional[str] = None
    match_preview: Optional[str] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class MockProvenanceRecord:
    record_id: str = "mock-record-id"
    sequence_number: int = 0
    current_hash: str = "abc123"
    input_hash: str = "def456"
    action_taken: Any = None
    risk_level: Any = None
    signature: str = "mocksig"
    timestamp: Any = None
    parent_hash: Optional[str] = None
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    output_hash: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    source_type: Any = None
    trust_level: Any = None
    source_uri: Optional[str] = None
    parent_id: Optional[str] = None
    parent_ids: list = field(default_factory=list)

    def __post_init__(self):
        if self.action_taken is None:
            self.action_taken = type("Action", (), {"value": "allow"})()
        if self.risk_level is None:
            self.risk_level = type("RiskLevel", (), {"value": "safe"})()
        import datetime
        if self.timestamp is None:
            self.timestamp = datetime.datetime.now(datetime.timezone.utc)


def _make_risk_score(action_value: str, risk_value: str = "safe") -> MockRiskScore:
    return MockRiskScore(
        overall_score={"safe": 0.0, "low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}.get(risk_value, 0.0),
        level=type("RiskLevel", (), {"value": risk_value})(),
        recommended_action=type("Action", (), {"value": action_value})(),
        factors=[],
    )


# ─── Mock InputGuard responses ────────────────────────────────────────────────

@dataclass
class MockInputResponse:
    allowed: bool
    action: Any
    sanitized_prompt: str
    risk_assessment: MockRiskScore
    findings: list
    provenance_record: MockProvenanceRecord
    latency_ms: float = 1.0


def make_input_allow(content: str = "") -> MockInputResponse:
    return MockInputResponse(
        allowed=True,
        action=type("Action", (), {"value": "allow"})(),
        sanitized_prompt=content,
        risk_assessment=_make_risk_score("allow", "safe"),
        findings=[],
        provenance_record=MockProvenanceRecord(),
    )


def make_input_block(content: str = "", findings=None) -> MockInputResponse:
    f = findings or [MockDetectionFinding(
        detector=type("DT", (), {"value": "injection"})(),
        rule_id="INJ_DIR_001",
        description="Injection attempt detected",
        risk_score=0.95,
        match_preview="ignore previous...",
        metadata={"category": "DIRECT_OVERRIDE"},
    )]
    return MockInputResponse(
        allowed=False,
        action=type("Action", (), {"value": "block"})(),
        sanitized_prompt="[INPUT_BLOCKED_BY_GUARDRAIL]",
        risk_assessment=_make_risk_score("block", "critical"),
        findings=f,
        provenance_record=MockProvenanceRecord(),
    )


def make_input_mask(original: str, masked: str) -> MockInputResponse:
    return MockInputResponse(
        allowed=True,
        action=type("Action", (), {"value": "mask"})(),
        sanitized_prompt=masked,
        risk_assessment=_make_risk_score("mask", "medium"),
        findings=[MockDetectionFinding(
            detector=type("DT", (), {"value": "pii"})(),
            rule_id="PII_001",
            description="PII masked",
            risk_score=0.4,
            match_preview="[MASKED]",
            metadata={"category": "PII"},
        )],
        provenance_record=MockProvenanceRecord(),
    )


# ─── Mock OutputGuard responses ───────────────────────────────────────────────

@dataclass
class MockOutputResponse:
    allowed: bool
    action: Any
    sanitized_output: str
    risk_assessment: MockRiskScore
    findings: list
    provenance_record: MockProvenanceRecord
    latency_ms: float = 1.0


def make_output_allow(content: str = "") -> MockOutputResponse:
    return MockOutputResponse(
        allowed=True,
        action=type("Action", (), {"value": "allow"})(),
        sanitized_output=content,
        risk_assessment=_make_risk_score("allow", "safe"),
        findings=[],
        provenance_record=MockProvenanceRecord(),
    )


def make_output_block(content: str = "") -> MockOutputResponse:
    return MockOutputResponse(
        allowed=False,
        action=type("Action", (), {"value": "block"})(),
        sanitized_output="[OUTPUT_BLOCKED_BY_GUARDRAIL]",
        risk_assessment=_make_risk_score("block", "critical"),
        findings=[MockDetectionFinding(
            detector=type("DT", (), {"value": "secret"})(),
            rule_id="SEC_AWS_001",
            description="AWS key detected",
            risk_score=0.95,
            match_preview="AKIA...",
            metadata={"category": "SECRET"},
        )],
        provenance_record=MockProvenanceRecord(),
    )


def make_output_mask(original: str, masked: str) -> MockOutputResponse:
    return MockOutputResponse(
        allowed=True,
        action=type("Action", (), {"value": "mask"})(),
        sanitized_output=masked,
        risk_assessment=_make_risk_score("mask", "medium"),
        findings=[],
        provenance_record=MockProvenanceRecord(),
    )


# ─── Mock InputGuard class ────────────────────────────────────────────────────

class MockP1InputGuard:
    """Drop-in mock for P1's InputGuard. Returns configured responses."""

    def __init__(self, response: MockInputResponse = None):
        self._response = response or make_input_allow()

    def set_response(self, response: MockInputResponse) -> None:
        self._response = response

    async def validate_async(self, request, **kwargs) -> MockInputResponse:
        return self._response

    def validate(self, request, **kwargs) -> MockInputResponse:
        import asyncio
        return asyncio.get_event_loop().run_until_complete(self.validate_async(request, **kwargs))

    async def validate_external_content_async(self, content, **kwargs) -> MockInputResponse:
        return self._response


class MockP1OutputGuard:
    """Drop-in mock for P1's OutputGuard."""

    def __init__(self, response: MockOutputResponse = None):
        self._response = response or make_output_allow()

    def set_response(self, response: MockOutputResponse) -> None:
        self._response = response

    async def validate_async(self, request, **kwargs) -> MockOutputResponse:
        return self._response

    async def validate_tool_call_async(self, **kwargs) -> MockOutputResponse:
        return self._response

    async def validate_tool_output_async(self, **kwargs) -> MockOutputResponse:
        return self._response
