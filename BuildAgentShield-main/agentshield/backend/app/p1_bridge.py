from __future__ import annotations

import json
import re
from typing import Any

from .config import Settings
from .contracts import Finding, RiskLevel, ToolRequest
from .p1 import MockSecurityEngine
from .teammate_loader import load_p1


_CODE_SANITIZER = re.compile(r"[^a-z0-9_]+")


def _severity(detector: str, score: float) -> RiskLevel:
    if detector == "secret":
        return RiskLevel.CRITICAL
    if score >= 0.85:
        return RiskLevel.CRITICAL
    if score >= 0.65:
        return RiskLevel.HIGH
    if score >= 0.35:
        return RiskLevel.MEDIUM
    if score > 0:
        return RiskLevel.LOW
    return RiskLevel.NONE


def _safe_code(detector: str, rule_id: str) -> str:
    raw = f"p1_{detector}_{rule_id}".lower()
    return _CODE_SANITIZER.sub("_", raw).strip("_")[:100] or "p1_finding"


def _map_finding(item: Any, location: str) -> Finding:
    detector = str(getattr(item.detector, "value", item.detector))
    rule_id = str(getattr(item, "rule_id", "finding"))
    score = float(getattr(item, "risk_score", 0.0) or 0.0)
    description = str(getattr(item, "description", "") or "")
    evidence = (
        getattr(item, "match_preview", None)
        or getattr(item, "redacted_value", None)
        or ""
    )
    return Finding(
        code=_safe_code(detector, rule_id),
        severity=_severity(detector, score),
        reason=description[:500] or f"P1 {detector} detector reported a finding.",
        evidence=str(evidence)[:500],
        location=location[:200],
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.code, finding.location, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
        if len(result) >= 100:
            break
    return result


class P1SecurityEngine:
    name = "p1_security_engine"

    def __init__(
        self,
        engine: Any,
        schemas: Any,
        fallback: MockSecurityEngine | None = None,
    ) -> None:
        self._engine = engine
        self._schemas = schemas
        self._fallback = fallback or MockSecurityEngine()

    @staticmethod
    def _payload(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)

    def _p1_findings(self, response: Any, location: str) -> list[Finding]:
        return [_map_finding(item, location) for item in response.findings]

    async def inspect_input(
        self, request: ToolRequest, tool_name: str, arguments: dict[str, Any]
    ) -> list[Finding]:
        local = await self._fallback.inspect_input(request, tool_name, arguments)
        response = await self._engine.inspect_input(
            self._payload({"tool_name": tool_name, "arguments": arguments}),
            source_uri=request.provenance.source,
        )
        return _dedupe(local + self._p1_findings(response, "arguments"))

    async def inspect_output(
        self, request: ToolRequest, tool_name: str, output: dict[str, Any]
    ) -> list[Finding]:
        local = await self._fallback.inspect_output(request, tool_name, output)
        response = await self._engine.inspect_output(
            {"tool_name": tool_name, "tool_output": self._payload(output)},
            mode="tool_output",
            source_uri=request.provenance.source,
        )
        return _dedupe(local + self._p1_findings(response, "result"))

    async def inspect_tool_call(
        self, request: ToolRequest, tool_name: str, arguments: dict[str, Any]
    ) -> list[Finding]:
        local = await self._fallback.inspect_tool_call(request, tool_name, arguments)
        response = await self._engine.inspect_output(
            {"tool_name": tool_name, "tool_args": arguments},
            mode="tool_call",
            source_uri=request.provenance.source,
        )
        return _dedupe(local + self._p1_findings(response, "arguments"))

    async def inspect_data(
        self, data: dict[str, Any], source: str = "unknown"
    ) -> list[Finding]:
        local = await self._fallback.inspect_data(data, source)
        response = await self._engine.inspect_data(
            self._payload(data),
            source_uri=source,
        )
        return _dedupe(local + self._p1_findings(response, "data"))

    def calculate_risk(self, findings: list[Finding], base_score: int = 0) -> int:
        return self._fallback.calculate_risk(findings, base_score)


def create_p1_engine(settings: Settings | None = None) -> P1SecurityEngine:
    modules = load_p1(settings)
    config = modules["config"].AgentShieldConfig()
    engine = modules["security_engine"].SecurityEngine(config=config)
    return P1SecurityEngine(engine, modules["schemas"])
