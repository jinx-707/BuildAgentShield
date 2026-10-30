from __future__ import annotations

import re
from typing import Any, Protocol

from .contracts import Finding, RiskLevel, ToolRequest
from .security import EMAIL_PATTERN, sanitize_dict


class SecurityEngine(Protocol):
    async def inspect_input(
        self, request: ToolRequest, tool_name: str, arguments: dict[str, Any]
    ) -> list[Finding]: ...

    async def inspect_output(
        self, request: ToolRequest, tool_name: str, output: dict[str, Any]
    ) -> list[Finding]: ...

    async def inspect_tool_call(
        self, request: ToolRequest, tool_name: str, arguments: dict[str, Any]
    ) -> list[Finding]: ...

    async def inspect_data(
        self, data: dict[str, Any], source: str = "unknown"
    ) -> list[Finding]: ...

    def calculate_risk(self, findings: list[Finding], base_score: int = 0) -> int: ...


INJECTION_PATTERNS = [
    (re.compile(r"ignore (all )?(previous|prior) instructions", re.I), "prompt_injection"),
    (re.compile(r"(reveal|print|return) (the )?(system prompt|hidden instructions)", re.I), "prompt_leak"),
    (re.compile(r"you are now|new instructions|developer mode", re.I), "instruction_override"),
    (re.compile(r"exfiltrat|send .*secret|read .*\.env|cat .*id_rsa", re.I), "exfiltration_instruction"),
]
DANGEROUS_COMMAND = re.compile(
    r"(rm\s+-[a-z]*r[a-z]*f?\s+/(\s|$)|mkfs|dd\s+if=|shutdown|reboot|:\(\)\s*\{|"
    r"curl[^\n|]*\|\s*(sh|bash)|wget[^\n|]*\|\s*(sh|bash)|chmod\s+-R\s+777\s+/)",
    re.I,
)
SECRET_VALUE = re.compile(
    r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"sk_(live|test)_[A-Za-z0-9]{12,})"
)
PII_VALUE = re.compile(
    r"(\b\d{3}-\d{2}-\d{4}\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)"
)


def _flatten(value: Any, path: str = "arguments") -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            items.extend(_flatten(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            items.extend(_flatten(item, f"{path}[{index}]"))
    else:
        items.append((path, str(value)))
    return items


class MockSecurityEngine:
    async def inspect_input(
        self, request: ToolRequest, tool_name: str, arguments: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []
        flattened = _flatten(arguments)
        text = " ".join(value for _, value in flattened)
        for pattern, code in INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        code=code,
                        severity=RiskLevel.HIGH,
                        reason="Untrusted content contains instructions that attempt to override agent policy.",
                        evidence=match.group(0)[:120],
                        location="arguments",
                    )
                )
        if request.provenance.trust.value == "untrusted" and findings:
            findings.append(
                Finding(
                    code="tainted_external_content",
                    severity=RiskLevel.HIGH,
                    reason="Content is tainted and must not gain execution authority.",
                    evidence=request.provenance.source[:120],
                    location="provenance.source",
                )
            )
        for path, value in flattened:
            if SECRET_VALUE.search(value) or re.search(r"(?i)(password|secret|api[_-]?key)", path):
                findings.append(
                    Finding(
                        code="secret_material",
                        severity=RiskLevel.CRITICAL,
                        reason="Secret material was detected in tool arguments.",
                        evidence="[REDACTED]",
                        location=path,
                    )
                )
            if re.search(r"(^|[\\/])\.\.([\\/]|$)", value):
                findings.append(
                    Finding(
                        code="path_traversal",
                        severity=RiskLevel.CRITICAL,
                        reason="Path traversal outside the authorized workspace was detected.",
                        evidence=value[:160],
                        location=path,
                    )
                )
            if tool_name == "run_command" and DANGEROUS_COMMAND.search(value):
                findings.append(
                    Finding(
                        code="destructive_command",
                        severity=RiskLevel.CRITICAL,
                        reason="A destructive or remote-code command pattern was detected.",
                        evidence=value[:160],
                        location=path,
                    )
                )
        if tool_name == "send_email":
            body = f"{arguments.get('body', '')} {arguments.get('pii', '')}"
            if PII_VALUE.search(body):
                findings.append(
                    Finding(
                        code="pii_in_egress",
                        severity=RiskLevel.HIGH,
                        reason="Personally identifiable information is present in outbound email content.",
                        evidence="[REDACTED]",
                        location="arguments.body",
                    )
                )
        if request.provenance.data_classification.value in {"sensitive", "secret"}:
            findings.append(
                Finding(
                    code="sensitive_provenance",
                    severity=RiskLevel.MEDIUM,
                    reason="Request provenance is classified as sensitive or secret.",
                    evidence=request.provenance.source[:120],
                    location="provenance.data_classification",
                )
            )
        return findings

    async def inspect_output(
        self, request: ToolRequest, tool_name: str, output: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []
        text = " ".join(value for _, value in _flatten(output, "result"))
        if SECRET_VALUE.search(text):
            findings.append(
                Finding(
                    code="secret_in_output",
                    severity=RiskLevel.CRITICAL,
                    reason="Adapter output contained secret material and was sanitized.",
                    evidence="[REDACTED]",
                    location="result",
                )
            )
        if PII_VALUE.search(text) or EMAIL_PATTERN.search(text):
            findings.append(
                Finding(
                    code="pii_in_output",
                    severity=RiskLevel.MEDIUM,
                    reason="Adapter output contained personal data and was sanitized.",
                    evidence="[REDACTED]",
                    location="result",
                )
            )
        return findings

    async def inspect_tool_call(
        self, request: ToolRequest, tool_name: str, arguments: dict[str, Any]
    ) -> list[Finding]:
        return await self.inspect_input(request, tool_name, arguments)

    async def inspect_data(
        self, data: dict[str, Any], source: str = "unknown"
    ) -> list[Finding]:
        request = ToolRequest(
            request_id=f"inspect_{source[:40]}",
            tool_name="inspect_data",
            arguments=data,
            provenance={
                "source": source or "unknown",
                "trust": "untrusted",
                "tainted": True,
            },
        )
        return await self.inspect_input(request, "inspect_data", data)

    def calculate_risk(self, findings: list[Finding], base_score: int = 0) -> int:
        weights = {
            RiskLevel.NONE: 0,
            RiskLevel.LOW: 5,
            RiskLevel.MEDIUM: 15,
            RiskLevel.HIGH: 30,
            RiskLevel.CRITICAL: 50,
        }
        score = base_score
        for finding in findings:
            score = max(score, min(100, score + weights[finding.severity]))
        return score


class UnavailableSecurityEngine:
    async def inspect_input(
        self, request: ToolRequest, tool_name: str, arguments: dict[str, Any]
    ) -> list[Finding]:
        raise RuntimeError("security engine unavailable")

    async def inspect_output(
        self, request: ToolRequest, tool_name: str, output: dict[str, Any]
    ) -> list[Finding]:
        raise RuntimeError("security engine unavailable")

    async def inspect_tool_call(
        self, request: ToolRequest, tool_name: str, arguments: dict[str, Any]
    ) -> list[Finding]:
        raise RuntimeError("security engine unavailable")

    async def inspect_data(
        self, data: dict[str, Any], source: str = "unknown"
    ) -> list[Finding]:
        raise RuntimeError("security engine unavailable")

    def calculate_risk(self, findings: list[Finding], base_score: int = 0) -> int:
        raise RuntimeError("security engine unavailable")


def sanitize_output(output: dict[str, Any]) -> dict[str, Any]:
    return sanitize_dict(output)
