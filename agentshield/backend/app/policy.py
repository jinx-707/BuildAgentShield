from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import Settings
from .contracts import (
    AuthContext,
    DataClassification,
    Decision,
    Finding,
    Provenance,
    RiskLevel,
    SecurityVerdict,
    ToolSpec,
    TrustLevel,
)
from .security import sanitize_dict


SEVERITY_WEIGHT = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 5,
    RiskLevel.MEDIUM: 15,
    RiskLevel.HIGH: 30,
    RiskLevel.CRITICAL: 50,
}

POLICY_FINDING_CODES = {
    "registry.default_deny": "unknown_tool",
    "integration.p1_unavailable": "inspection_failed",
    "integration.inspection_failed": "inspection_failed",
    "integration.adapter_unavailable": "adapter_unavailable",
    "rbac.default_deny": "permission_denied",
    "abac.path_scope": "scope_denied",
    "abac.domain_scope": "scope_denied",
    "abac.email_scope": "scope_denied",
    "abac.mcp_scope": "scope_denied",
    "semantic.system_files": "system_file_access",
    "semantic.secrets": "secret_access",
    "semantic.terminal": "dangerous_command",
    "semantic.pii_egress": "pii_exfiltration",
    "semantic.sensitive_email": "sensitive_egress",
    "semantic.untrusted_browser": "untrusted_content",
    "provenance.untrusted_content": "untrusted_content",
    "financial.budget": "payment_over_budget",
    "financial.merchant": "merchant_not_allowed",
}


class OPANotAvailable(RuntimeError):
    pass


class OPAEvaluator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self.settings.opa_url)

    async def probe(self) -> None:
        result = await self.evaluate(
            {
                "principal": {"permissions": [], "scopes": {}},
                "tool": {
                    "name": "health_probe",
                    "permission": "health.probe",
                    "requires_approval": False,
                    "supports_egress": False,
                },
                "arguments": {},
                "provenance": {"trust": "trusted", "data_classification": "internal"},
                "findings": [],
                "local_decision": Decision.ALLOW.value,
                "local_risk_score": 0,
            }
        )
        decision = str(result.get("decision", "")).upper()
        if decision == "BLOCK":
            decision = "DENY"
        if decision not in {item.value for item in Decision}:
            raise OPANotAvailable("OPA returned an unknown decision")

    async def evaluate(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.settings.opa_url:
            raise OPANotAvailable("OPA is not configured")
        url = f"{self.settings.opa_url.rstrip('/')}/v1/data/agentshield/execution/decision"
        try:
            async with httpx.AsyncClient(timeout=self.settings.opa_timeout_seconds) as client:
                response = await client.post(url, json={"input": payload})
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OPANotAvailable("OPA evaluation failed") from exc
        result = data.get("result")
        if not isinstance(result, dict) or "decision" not in result:
            raise OPANotAvailable("OPA returned an invalid decision")
        return result


class PolicyEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.opa = OPAEvaluator(settings)

    async def evaluate(
        self,
        auth: AuthContext,
        spec: ToolSpec,
        arguments: dict[str, Any],
        provenance: Provenance,
        findings: list[Finding],
    ) -> SecurityVerdict:
        local = self._local(auth, spec, arguments, provenance, findings)
        if local.decision in {Decision.DENY, Decision.QUARANTINE}:
            return local
        if not self.opa.enabled:
            return local
        try:
            result = await self.opa.evaluate(
                {
                    "principal": auth.model_dump(mode="json"),
                    "tool": spec.model_dump(mode="json"),
                    "arguments": arguments,
                    "provenance": provenance.model_dump(mode="json"),
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                    "local_decision": local.decision.value,
                    "local_risk_score": local.risk_score,
                }
            )
        except OPANotAvailable as exc:
            return SecurityVerdict(
                decision=Decision.DENY,
                risk_level=RiskLevel.CRITICAL,
                risk_score=100,
                reason=f"Policy engine failed closed: {exc}",
                findings=findings,
                policy_id="fail_closed",
            )
        remote_decision = str(result.get("decision", "")).upper()
        if remote_decision == "BLOCK":
            remote_decision = "DENY"
        if remote_decision not in {decision.value for decision in Decision}:
            return SecurityVerdict(
                decision=Decision.DENY,
                risk_level=RiskLevel.CRITICAL,
                risk_score=100,
                reason="Policy engine returned an unknown decision",
                findings=findings,
                policy_id="fail_closed",
            )
        remote = Decision(remote_decision)
        final = self._most_restrictive(local.decision, remote)
        return local.model_copy(
            update={
                "decision": final,
                "reason": str(result.get("reason", local.reason))[:1000],
                "policy_id": str(result.get("policy_id", local.policy_id or "opa"))[:100],
                "requires_approval": final == Decision.REQUIRE_APPROVAL,
            }
        )

    def _local(
        self,
        auth: AuthContext,
        spec: ToolSpec,
        arguments: dict[str, Any],
        provenance: Provenance,
        findings: list[Finding],
    ) -> SecurityVerdict:
        score = spec.risk_score
        for finding in findings:
            score = max(score, min(100, score + SEVERITY_WEIGHT[finding.severity]))
        critical = [finding for finding in findings if finding.severity == RiskLevel.CRITICAL]
        high = [finding for finding in findings if finding.severity == RiskLevel.HIGH]

        if spec.name not in {"read_document", "read_file", "read_system_file", "read_env_var", "run_command", "delete_file", "browse_url", "send_email", "export_data", "download_file", "initiate_payment", "call_external_api", "mcp_call"}:
            return self._verdict(Decision.DENY, score, "Tool is not registered.", findings, "registry.default_deny")

        if spec.permission not in auth.permissions:
            return self._verdict(
                Decision.DENY,
                max(score, 60),
                f"Agent lacks the required permission '{spec.permission}'.",
                findings,
                "rbac.default_deny",
            )

        if critical:
            return self._verdict(
                Decision.DENY,
                100 if any(item.code in {"secret_material", "destructive_command", "path_traversal"} for item in critical) else max(score, 90),
                critical[0].reason,
                findings,
                "inspection.critical",
            )

        if spec.name == "send_email" and any(
            finding.code == "pii_in_egress" for finding in findings
        ):
            return self._verdict(
                Decision.DENY,
                max(score, 92),
                "Outbound email contains personal data and was blocked by data-loss policy.",
                findings,
                "semantic.pii_egress",
            )

        if provenance.trust == TrustLevel.UNTRUSTED and high:
            return self._verdict(
                Decision.QUARANTINE,
                max(score, 85),
                "Untrusted content attempted to influence a privileged action and was quarantined.",
                findings,
                "provenance.untrusted_content",
            )

        if provenance.trust == TrustLevel.UNTRUSTED and spec.name in {
            "read_document",
            "read_file",
            "download_file",
        }:
            return self._verdict(
                Decision.REQUIRE_APPROVAL,
                max(score, 70),
                "Content from an untrusted source requires exact-action human approval.",
                findings,
                "provenance.untrusted_content",
                approval=True,
            )

        scopes = auth.scopes or {}
        if spec.name == "read_document":
            document = str(arguments.get("document", "")).replace("\\", "/")
            if ".." in document.split("/") or document.startswith("/"):
                return self._verdict(
                    Decision.DENY,
                    max(score, 95),
                    "Document path traversal is denied by default.",
                    findings,
                    "abac.path_scope",
                )
        if spec.name == "read_file":
            path = str(arguments.get("path", ""))
            if not self._path_allowed(path, scopes):
                return self._verdict(
                    Decision.DENY,
                    max(score, 80),
                    "File path is outside the agent's authorized workspace scope.",
                    findings,
                    "abac.path_scope",
                )
        if spec.name == "delete_file":
            path = str(arguments.get("path", ""))
            if not self._path_allowed(path, scopes):
                return self._verdict(
                    Decision.DENY,
                    max(score, 85),
                    "Delete path is outside the agent's authorized workspace scope.",
                    findings,
                    "abac.path_scope",
                )
            return self._verdict(
                Decision.REQUIRE_APPROVAL,
                max(score, 70),
                "Deleting workspace files requires exact-action human approval.",
                findings,
                "approval.destructive_action",
                approval=True,
            )
        if spec.name == "read_system_file":
            allowed = scopes.get("allowed_system_paths", [])
            path = str(arguments.get("path", ""))
            if path not in allowed:
                return self._verdict(
                    Decision.DENY,
                    max(score, 95),
                    "Protected system files are denied by default.",
                    findings,
                    "semantic.system_files",
                )
        if spec.name == "read_env_var":
            allowed = scopes.get("allowed_env", [])
            name = str(arguments.get("name", ""))
            if name not in allowed:
                return self._verdict(
                    Decision.DENY,
                    max(score, 95),
                    "Environment secrets are denied unless explicitly scoped.",
                    findings,
                    "semantic.secrets",
                )
        if spec.name == "run_command":
            if findings:
                return self._verdict(
                    Decision.DENY,
                    99,
                    "Terminal command failed security inspection.",
                    findings,
                    "semantic.terminal",
                )
            return self._verdict(
                Decision.REQUIRE_APPROVAL,
                max(score, 75),
                "Terminal execution requires human approval and runs in an isolated mock worker.",
                findings,
                "approval.terminal",
                approval=True,
            )
        if spec.name == "browse_url":
            url = str(arguments.get("url", ""))
            host = (urlparse(url).hostname or "").lower()
            if arguments.get("trust") == "untrusted" or provenance.trust == TrustLevel.UNTRUSTED:
                return self._verdict(
                    Decision.QUARANTINE,
                    max(score, 88),
                    "Untrusted web content was isolated before it could influence the agent.",
                    findings,
                    "semantic.untrusted_browser",
                )
            if not self._host_allowed(host, scopes):
                return self._verdict(
                    Decision.DENY,
                    max(score, 70),
                    "Destination host is not on the agent's allowlist.",
                    findings,
                    "abac.domain_scope",
                )
        if spec.name in {"download_file", "call_external_api"}:
            url = str(arguments.get("url") or arguments.get("endpoint") or "")
            host = (urlparse(url).hostname or "").lower()
            if not self._host_allowed(host, scopes):
                return self._verdict(
                    Decision.DENY,
                    max(score, 70),
                    "Destination host is not on the agent's allowlist.",
                    findings,
                    "abac.domain_scope",
                )
        if spec.name == "mcp_call":
            server = str(arguments.get("server", ""))
            if server not in scopes.get("allowed_servers", []):
                return self._verdict(
                    Decision.DENY,
                    max(score, 70),
                    "MCP server is not on the agent's allowlist.",
                    findings,
                    "abac.mcp_scope",
                )
        if spec.name == "send_email":
            if any(finding.code == "pii_in_egress" for finding in findings):
                return self._verdict(
                    Decision.DENY,
                    max(score, 92),
                    "Outbound email contains personal data and was blocked by data-loss policy.",
                    findings,
                    "semantic.pii_egress",
                )
            if provenance.data_classification in {DataClassification.SENSITIVE, DataClassification.SECRET}:
                return self._verdict(
                    Decision.DENY,
                    max(score, 90),
                    "Sensitive data cannot be sent through the email adapter.",
                    findings,
                    "semantic.sensitive_email",
                )
            recipient_domain = str(arguments.get("to", "")).rsplit("@", 1)[-1].lower()
            if not self._host_allowed(recipient_domain, scopes):
                return self._verdict(
                    Decision.DENY,
                    max(score, 75),
                    "Email recipient domain is not on the agent's allowlist.",
                    findings,
                    "abac.email_scope",
                )
            return self._verdict(
                Decision.REQUIRE_APPROVAL,
                max(score, 60),
                "Sending email requires exact-action human approval.",
                findings,
                "approval.email",
                approval=True,
            )
        if spec.name == "export_data":
            if provenance.data_classification in {DataClassification.SENSITIVE, DataClassification.SECRET} or arguments.get("data_classification") == "sensitive":
                return self._verdict(
                    Decision.REDACT,
                    max(score, 65),
                    "Export is allowed only after sensitive fields are redacted.",
                    findings,
                    "dlp.redact_export",
                )
            return self._verdict(
                Decision.REQUIRE_APPROVAL,
                max(score, 55),
                "Exporting workspace data requires exact-action approval.",
                findings,
                "approval.export",
                approval=True,
            )
        if spec.name == "initiate_payment":
            budget = float(scopes.get("payment_budget", 0) or 0)
            amount = float(arguments.get("amount", 0) or 0)
            merchant = str(arguments.get("merchant", ""))
            merchants = scopes.get("allowed_merchants", [])
            if amount > budget:
                return self._verdict(
                    Decision.DENY,
                    max(score, 85),
                    f"Payment amount exceeds the ${budget:.2f} agent budget.",
                    findings,
                    "financial.budget",
                )
            if not merchant or merchant not in merchants:
                return self._verdict(
                    Decision.DENY,
                    max(score, 85),
                    "Merchant is not on the agent's allowlist.",
                    findings,
                    "financial.merchant",
                )
            return self._verdict(
                Decision.REQUIRE_APPROVAL,
                max(score, 60),
                "Sandbox payments require exact-action human approval.",
                findings,
                "approval.payment",
                approval=True,
            )
        if spec.name in {"call_external_api", "mcp_call", "download_file"}:
            return self._verdict(
                Decision.REQUIRE_APPROVAL,
                max(score, 60),
                "External integrations require human approval.",
                findings,
                "approval.external_integration",
                approval=True,
            )

        return self._verdict(
            Decision.ALLOW,
            score,
            "Request satisfies registry, RBAC, ABAC, and inspection policy.",
            findings,
            "gateway.allow",
        )

    def _verdict(
        self,
        decision: Decision,
        score: int,
        reason: str,
        findings: list[Finding],
        policy_id: str,
        *,
        approval: bool = False,
        arguments: dict[str, Any] | None = None,
    ) -> SecurityVerdict:
        score = max(0, min(100, int(score)))
        risk_level = self._risk_level(score)
        resolved = list(findings)
        if decision in {Decision.DENY, Decision.QUARANTINE} and not resolved:
            resolved.append(
                Finding(
                    code=POLICY_FINDING_CODES.get(policy_id, "policy_denied"),
                    severity=risk_level,
                    reason=reason[:1000],
                    location="policy",
                    evidence=policy_id[:160],
                )
            )
        return SecurityVerdict(
            decision=decision,
            risk_level=risk_level,
            risk_score=score,
            reason=reason[:1000],
            findings=resolved,
            policy_id=policy_id,
            requires_approval=approval or decision == Decision.REQUIRE_APPROVAL,
            sanitized_arguments=sanitize_dict(arguments) if decision == Decision.REDACT and arguments else None,
        )

    @staticmethod
    def _risk_level(score: int) -> RiskLevel:
        if score >= 85:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 30:
            return RiskLevel.MEDIUM
        if score > 0:
            return RiskLevel.LOW
        return RiskLevel.NONE

    @staticmethod
    def _path_allowed(path: str, scopes: dict[str, Any]) -> bool:
        if ".." in path.replace("\\", "/").split("/"):
            return False
        normalized = path.replace("\\", "/").lstrip("./")
        if not normalized:
            return False
        allowed_paths = [str(item).replace("\\", "/").strip("/") for item in scopes.get("allowed_paths", [])]
        if not allowed_paths:
            return False
        if normalized.startswith("/"):
            return any(normalized == item or normalized.startswith(f"{item}/") for item in allowed_paths if item.startswith("/"))
        return any(normalized == item or normalized.startswith(f"{item}/") for item in allowed_paths)

    @staticmethod
    def _host_allowed(host: str, scopes: dict[str, Any]) -> bool:
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except ValueError:
            pass
        allowed = [str(item).lower().strip(".") for item in scopes.get("allowed_domains", [])]
        return any(host == item or host.endswith(f".{item}") for item in allowed)

    @staticmethod
    def _most_restrictive(first: Decision, second: Decision) -> Decision:
        rank = {
            Decision.ALLOW: 0,
            Decision.REDACT: 1,
            Decision.REQUIRE_APPROVAL: 2,
            Decision.QUARANTINE: 3,
            Decision.DENY: 4,
        }
        return first if rank[first] >= rank[second] else second
