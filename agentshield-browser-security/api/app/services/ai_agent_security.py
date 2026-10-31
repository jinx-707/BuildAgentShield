"""AI Agent Security service for AgentShield Prompt 3.

Orchestrates AI agent actions through the existing enforcement architecture
(DatabasePolicyEngine -> BrowserSecurityOrchestrator -> Browser Worker ->
Egress Proxy) and layers AI-agent-specific threat detection, DLP, permission
governance, and explainable risk scoring on top.

Every action is organization-scoped and persisted to PostgreSQL. Security
events are published to the SSE event pipeline for the enterprise console.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from app.db.ai_models import (
    AgentExecution,
    DlpFinding,
    RiskAssessment,
    ThreatDetection,
    ToolDecision,
)
from app.db.base import get_db_session
from app.db.models import AgentCapability, Capability
from app.enterprise.auth import verify_agent_credentials
from app.security.ai.detection import ThreatDetectionEngine, DetectionResult
from app.security.ai.dlp import DlpEngine
from app.security.ai.risk import RiskEngine
from app.services.capability_service import CapabilityService
from app.services.event_broadcaster import broadcaster

logger = logging.getLogger(__name__)


class AgentSecurityService:
    """Mediates AI agent actions through AgentShield enforcement."""

    def __init__(self, *, orchestrator=None, policy_engine=None) -> None:
        self._orchestrator = orchestrator
        self._policy_engine = policy_engine
        self._threat_engine = ThreatDetectionEngine()
        self._dlp_engine = DlpEngine()
        self._risk_engine = RiskEngine()

    # ------------------------------------------------------------------
    # Agent authentication
    # ------------------------------------------------------------------

    def authenticate_agent(
        self, *, agent_id: str, secret: str, db
    ) -> Any | None:
        """Authenticate an agent by id + secret (server-side hash only).

        Returns the Agent model or None. The plaintext secret is never
        returned or logged.
        """
        return verify_agent_credentials(db, agent_id, secret)

    # ------------------------------------------------------------------
    # Action execution
    # ------------------------------------------------------------------

    async def execute_action(
        self,
        *,
        agent,
        organization_id: str,
        action: str,
        target: str | None = None,
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        ip_address: str | None = None,
        db=None,
    ) -> dict[str, Any]:
        """Execute an agent action through the full enforcement path."""
        _own_db = False
        if db is None:
            try:
                db = get_db_session()
                _own_db = True
            except RuntimeError:
                db = None
        try:
            return await self._execute_action_tx(
                db=db,
                agent=agent,
                organization_id=organization_id,
                action=action,
                target=target,
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=session_id,
                request_id=request_id,
                ip_address=ip_address,
            )
        finally:
            if _own_db and db is not None:
                db.close()

    async def _execute_action_tx(
        self,
        *,
        db,
        agent,
        organization_id: str,
        action: str,
        target: str | None = None,
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        agent_id = agent.agent_id
        agent_permissions = list(agent.permissions or [])
        tool_args = tool_args or {}

        # 1. Permission governance (Part 5): check agent capabilities.
        perm_decision, perm_reason = self._check_permissions(
            agent=agent,
            organization_id=organization_id,
            action=action,
            tool_name=tool_name,
            tool_args=tool_args,
            target=target,
        )

        # 2. Threat detection (Part 2).
        threat_result = self._threat_engine.detect_navigation(
            url=target or "", request_id=request_id or ""
        )
        if tool_name:
            tool_threat = self._threat_engine.detect_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                request_id=request_id or "",
            )
            threat_result.detections.extend(tool_threat.detections)
            if tool_threat.blocked:
                threat_result.blocked = True
                threat_result.action = "deny"

        # 3. DLP (Part 4).
        dlp_result = self._dlp_engine.inspect(
            content=str(tool_args or target or ""),
            request_id=request_id or "",
        )

        # Combine threat + DLP detections for risk scoring.
        combined = self._merge_detections(threat_result, dlp_result)

        # 4. Risk assessment (Part 7).
        destination_sensitive = self._is_sensitive_target(target)
        prior_violations = self._count_prior_violations(db, organization_id, agent_id)
        risk = self._risk_engine.assess(
            detection_result=combined,
            agent_permissions=agent_permissions,
            destination_sensitive=destination_sensitive,
            prior_violations=prior_violations,
        )

        # 5. Deterministic enforcement decision.
        # Permission denial and any blocked detection => deny.
        if perm_decision == "deny" or combined.blocked or risk.enforcement_decision == "deny":
            final_decision = "deny"
        elif risk.enforcement_decision == "require_approval" or perm_decision == "require_approval":
            final_decision = "require_approval"
        else:
            final_decision = "allow"

        # 6. Enforce via the real enforcement path for navigation actions.
        enforcement_detail = None
        if action == "navigate" and target and final_decision in ("allow", "require_approval"):
            # Navigate through the existing orchestrator (policy -> worker -> proxy).
            if self._orchestrator is not None:
                try:
                    from app.schemas.browser import BrowserNavigateRequest
                    from pydantic import AnyHttpUrl

                    nav_request = BrowserNavigateRequest(
                        url=target,
                        wait_until="networkidle2",
                        timeout_ms=15000,
                        session_id=session_id,
                    )
                    worker_result = await self._orchestrator.navigate(
                        nav_request,
                        request_id=request_id or "",
                        agent_id=agent_id,
                        organization_id=organization_id,
                    )
                    enforcement_detail = {
                        "final_url": worker_result.final_url,
                        "status_code": worker_result.status_code,
                        "policy": worker_result.policy.model_dump() if worker_result.policy else None,
                        "inspection": worker_result.inspection.model_dump() if worker_result.inspection else None,
                    }
                except Exception as exc:
                    logger.exception("enforcement_navigation_failed")
                    final_decision = "deny"
                    enforcement_detail = {"error": str(exc)}
            else:
                enforcement_detail = {"skipped": "no orchestrator configured"}

        # 7. Persist records (Part 9) — only when a DB session is available.
        execution_id = str(uuid.uuid4())
        created_at = None
        if db is not None:
            execution = self._persist_execution(
                db=db,
                organization_id=organization_id,
                agent_id=agent_id,
                session_id=session_id,
                request_id=request_id,
                action=action,
                target=target,
                decision=final_decision,
                reason=perm_reason or risk.enforcement_decision,
                severity=risk.severity,
                risk_score=risk.risk_score,
                trust_label="untrusted",
                evidence={
                    "threat": combined.to_dict(),
                    "dlp": dlp_result.to_dict(),
                    "risk": {
                        "score": risk.risk_score,
                        "severity": risk.severity,
                        "reasons": risk.detection_reasons,
                    },
                    "enforcement": enforcement_detail,
                },
                ip_address=ip_address,
            )
            execution_id = str(execution.id)
            created_at = execution.created_at

            self._persist_threat_detections(
                db=db,
                organization_id=organization_id,
                agent_id=agent_id,
                session_id=session_id,
                execution_id=execution_id,
                detections=combined.detections,
            )
            self._persist_dlp_findings(
                db=db,
                organization_id=organization_id,
                agent_id=agent_id,
                session_id=session_id,
                detections=dlp_result.detections,
            )
            self._persist_risk_assessment(
                db=db,
                organization_id=organization_id,
                agent_id=agent_id,
                execution_id=execution_id,
                risk=risk,
            )
            if tool_name:
                self._persist_tool_decision(
                    db=db,
                    organization_id=organization_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    decision=final_decision,
                    reason=perm_reason or risk.enforcement_decision,
                    risk_score=risk.risk_score,
                )
            db.commit()

        # 8. Publish SSE event (non-blocking, best-effort).
        event = {
            "id": execution_id,
            "organization_id": organization_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "action": action,
            "target": target,
            "decision": final_decision,
            "risk_score": risk.risk_score,
            "severity": risk.severity,
            "created_at": created_at.isoformat() if created_at else None,
        }
        try:
            asyncio.ensure_future(broadcaster.publish(event))
        except RuntimeError:
            # No running event loop; SSE delivery is best-effort.
            pass

        return {
            "execution_id": execution_id,
            "agent_id": agent_id,
            "organization_id": organization_id,
            "action": action,
            "decision": final_decision,
            "reason": perm_reason or risk.enforcement_decision,
            "severity": risk.severity,
            "risk_score": risk.risk_score,
            "threat": combined.to_dict(),
            "dlp": dlp_result.to_dict(),
            "risk": {
                "score": risk.risk_score,
                "severity": risk.severity,
                "recommended_action": risk.recommended_action,
                "enforcement_decision": risk.enforcement_decision,
                "reasons": risk.detection_reasons,
            },
            "enforcement": enforcement_detail,
            "created_at": created_at.isoformat() if created_at else None,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_permissions(
        self,
        *,
        agent: Agent,
        organization_id: str,
        action: str,
        tool_name: str | None,
        tool_args: dict[str, Any],
        target: str | None = None,
    ) -> tuple[str, str | None]:
        """Map actions to required agent permissions with capability enforcement.

        Checks agent capabilities (enabled state, allowed tools, resource scope,
        domain restrictions, approval requirements) server-side via CapabilityService.
        Falls back to the legacy agent.permissions JSON list when no capability
        record exists or no database is available.
        """
        # 1. Capability-based enforcement (server-side, persisted)
        # Only check capabilities when a DB session is available.
        try:
            cap_svc = CapabilityService(db=getattr(self, "_db_context", None))
            cap_decision = cap_svc.check_capability(
                agent=agent,
                organization_id=organization_id,
                capability_key=None,
                tool_name=tool_name,
                target=target,
                tool_args=tool_args,
            )
            if not cap_decision.allowed:
                if cap_decision.require_approval:
                    return "require_approval", cap_decision.reason or "capability requires human approval"
                return "deny", cap_decision.reason or "capability check failed"
        except RuntimeError:
            # No database configured; fall through to legacy permission check.
            pass

        # 2. Legacy permission list check (backward compatibility)
        agent_permissions = list(agent.permissions or [])
        required = {
            "navigate": "browser_navigation",
            "click": "page_interaction",
            "type": "page_interaction",
            "scroll": "page_interaction",
            "extract": "data_extraction",
            "screenshot": "page_interaction",
            "tool_call": "external_communication",
            "file_download": "file_downloads",
            "form_submit": "form_submission",
            "sensitive_access": "sensitive_data_access",
        }.get(action)

        if not required:
            return "deny", f"unknown action {action} not permitted"

        if tool_name and tool_name not in agent_permissions:
            return "deny", f"tool {tool_name} not in agent permissions"

        if required not in agent_permissions:
            return "require_approval", f"agent lacks permission {required}"

        return "allow", None

    def _merge_detections(
        self, threat: DetectionResult, dlp: DetectionResult
    ) -> DetectionResult:
        merged = DetectionResult()
        merged.detections = list(threat.detections) + list(dlp.detections)
        merged.blocked = threat.blocked or dlp.blocked
        merged.action = "deny" if merged.blocked else (
            dlp.action if dlp.action in ("redact",) else threat.action
        )
        merged.risk_score = min(100, threat.risk_score + dlp.risk_score)
        return merged

    def _is_sensitive_target(self, target: str | None) -> bool:
        if not target:
            return False
        sensitive = ("metadata", "internal", "admin", "secret", "credential")
        return any(s in target.lower() for s in sensitive)

    def _count_prior_violations(self, db, organization_id: str, agent_id: str) -> int:
        if db is None:
            return 0
        try:
            return (
                db.query(ThreatDetection)
                .filter(
                    ThreatDetection.organization_id == organization_id,
                    ThreatDetection.agent_id == agent_id,
                )
                .count()
            )
        except Exception:
            logger.exception("prior_violation_count_failed")
            return 0

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _persist_execution(self, db, *, organization_id, agent_id, session_id,
                           request_id, action, target, decision, reason,
                           severity, risk_score, trust_label, evidence,
                           ip_address):
        row = AgentExecution(
            organization_id=organization_id,
            agent_id=agent_id,
            session_id=session_id,
            request_id=request_id,
            action=action,
            target=target,
            decision=decision,
            reason=reason,
            severity=severity,
            risk_score=risk_score,
            trust_label=trust_label,
            evidence=evidence,
        )
        db.add(row)
        db.flush()
        return row

    def _persist_threat_detections(self, db, *, organization_id, agent_id,
                                   session_id, execution_id, detections):
        for d in detections:
            db.add(
                ThreatDetection(
                    organization_id=organization_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    execution_id=execution_id,
                    threat_category=d.category,
                    detection_module=d.module,
                    detection_reason=d.reason,
                    severity=d.severity,
                    risk_score=d.confidence,
                    action_taken="deny" if d.module in ("prompt-injection", "malicious-content", "navigation", "data-exfiltration") else "flagged",
                    target=d.target,
                    evidence=d.evidence,
                )
            )

    def _persist_dlp_findings(self, db, *, organization_id, agent_id,
                              session_id, detections):
        for d in detections:
            db.add(
                DlpFinding(
                    organization_id=organization_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    detection_rule=d.rule_id,
                    detection_reason=d.reason,
                    severity=d.severity,
                    confidence=d.confidence,
                    action_taken="redacted",
                    target=d.target,
                    evidence=d.evidence,
                )
            )

    def _persist_risk_assessment(self, db, *, organization_id, agent_id,
                                 execution_id, risk):
        db.add(
            RiskAssessment(
                organization_id=organization_id,
                agent_id=agent_id,
                execution_id=execution_id,
                risk_score=risk.risk_score,
                severity=risk.severity,
                recommended_action=risk.recommended_action,
                enforcement_decision=risk.enforcement_decision,
                detection_reasons=risk.detection_reasons,
                risk_factors=risk.risk_factors,
            )
        )

    def _persist_tool_decision(self, db, *, organization_id, agent_id,
                               session_id, tool_name, tool_args, decision,
                               reason, risk_score):
        db.add(
            ToolDecision(
                organization_id=organization_id,
                agent_id=agent_id,
                session_id=session_id,
                tool_name=tool_name,
                tool_args=tool_args,
                decision=decision,
                reason=reason,
                policy_references=["agent-permissions", "risk-engine"],
                risk_score=risk_score,
            )
        )
