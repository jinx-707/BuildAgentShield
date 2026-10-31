"""Transparent, explainable risk scoring for AgentShield Prompt 3.

Risk scoring is explainable and configurable. A numerical score never overrides
deterministic security policy enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.security.ai.detection import DetectionResult


@dataclass
class RiskAssessment:
    """The result of a risk assessment."""

    risk_score: int  # 0-100
    severity: str  # low, medium, high, critical
    recommended_action: str  # allow, deny, require_approval
    enforcement_decision: str  # allow, deny, require_approval
    detection_reasons: list[str]
    risk_factors: dict[str, Any]


class RiskEngine:
    """Computes explainable risk scores from detection results and context."""

    name = "risk-engine"

    # Base risk contributed by each detection severity.
    SEVERITY_SCORE = {"low": 10, "medium": 30, "high": 60, "critical": 90}

    # Agent permission risk factors.
    PERMISSION_RISK = {
        "file_downloads": 20,
        "form_submission": 15,
        "external_communication": 20,
        "sensitive_data_access": 25,
        "page_interaction": 5,
        "browser_navigation": 5,
        "data_extraction": 10,
    }

    def assess(
        self,
        *,
        detection_result: DetectionResult,
        agent_permissions: list[str] | None = None,
        destination_sensitive: bool = False,
        prior_violations: int = 0,
    ) -> RiskAssessment:
        """Assess risk and produce a recommended enforcement decision.

        The enforcement decision is governed by deterministic rules: any
        critical detection or a blocked detection forces deny. High risk scores
        require approval. Scores never override a deny decision.
        """
        detections = detection_result.detections

        # Start from the detection engine's own risk score.
        score = detection_result.risk_score
        reasons: list[str] = []
        factors: dict[str, Any] = {
            "detection_score": detection_result.risk_score,
            "detection_count": len(detections),
        }

        # Add reasons from detections.
        for d in detections:
            reasons.append(f"{d.module}:{d.rule_id} ({d.severity}): {d.reason}")

        # Agent permission risk factors.
        perm_risk = 0
        if agent_permissions:
            for p in agent_permissions:
                if p in self.PERMISSION_RISK:
                    perm_risk += self.PERMISSION_RISK[p]
        factors["permission_risk"] = perm_risk
        score = min(100, score + perm_risk)
        if perm_risk:
            reasons.append(f"agent permissions contribute {perm_risk} risk points")

        # Destination sensitivity.
        if destination_sensitive:
            factors["destination_sensitive"] = True
            score = min(100, score + 15)
            reasons.append("destination is sensitive")

        # Prior violations.
        if prior_violations:
            factors["prior_violations"] = prior_violations
            score = min(100, score + min(20, prior_violations * 5))
            reasons.append(f"{prior_violations} prior violation(s)")

        # Deterministic enforcement: any critical detection or blocked action
        # forces deny regardless of score.
        has_critical = any(d.severity == "critical" for d in detections)
        if has_critical or detection_result.blocked:
            decision = "deny"
            recommended = "deny"
        elif score >= 75:
            decision = "require_approval"
            recommended = "require_approval"
        elif score >= 40:
            decision = "require_approval"
            recommended = "require_approval"
        else:
            decision = "allow"
            recommended = "allow"

        severity = self._severity_from_score(score)

        return RiskAssessment(
            risk_score=score,
            severity=severity,
            recommended_action=recommended,
            enforcement_decision=decision,
            detection_reasons=reasons,
            risk_factors=factors,
        )

    @staticmethod
    def _severity_from_score(score: int) -> str:
        if score >= 75:
            return "high"
        if score >= 40:
            return "medium"
        if score > 0:
            return "low"
        return "none"
