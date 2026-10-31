"""
AgentShield Context-Aware Risk Scoring Engine.
Aggregates findings from injection, secret, PII, DLP, and provenance sub-engines,
incorporates source trust, agent capability context, permissions, and requested actions,
and determines decisive policy actions with normalized compound scores (0-100).
"""

from __future__ import annotations

from typing import Any

from core.config import AgentShieldConfig, setup_logger
from core.schemas import (
    Action,
    DetectionFinding,
    DetectorType,
    DLPAnalysisResult,
    GuardrailContext,
    InjectionAnalysisResult,
    PIIAnalysisResult,
    ProvenanceRecord,
    RiskLevel,
    RiskScore,
    SecretAnalysisResult,
    SensitivityLevel,
    SourceType,
    TrustLevel,
)

logger = setup_logger("agentshield.risk")


# Default trust tiers per content origin source
DEFAULT_SOURCE_TRUST_LEVELS: dict[SourceType, TrustLevel] = {
    SourceType.SYSTEM: TrustLevel.TRUSTED,
    SourceType.USER: TrustLevel.MEDIUM,
    SourceType.FILE: TrustLevel.MEDIUM,
    SourceType.TOOL_OUTPUT: TrustLevel.LOW,
    SourceType.WEBSITE: TrustLevel.UNTRUSTED,
    SourceType.AGENT: TrustLevel.MEDIUM,
}

# Multipliers applied based on source trust level
TRUST_MULTIPLIERS: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 1.30,
    TrustLevel.LOW: 1.15,
    TrustLevel.MEDIUM: 1.00,
    TrustLevel.HIGH: 0.90,
    TrustLevel.TRUSTED: 0.80,
}

# Component risk scores attributed to origin trust tier
TRUST_COMPONENT_SCORES: dict[TrustLevel, float] = {
    TrustLevel.UNTRUSTED: 1.00,
    TrustLevel.LOW: 0.65,
    TrustLevel.MEDIUM: 0.35,
    TrustLevel.HIGH: 0.15,
    TrustLevel.TRUSTED: 0.00,
}


class RiskEngine:
    """
    Evaluates multi-vector threats and computes a normalized compound risk score
    (both 0.0-1.0 and 0-100 scales) with source provenance trust, agent capability
    context, tool permissions, and requested actions.
    """

    HIGH_RISK_TOOLS: set[str] = {
        "bash",
        "shell",
        "terminal",
        "python_repl",
        "execute_code",
        "code_execution",
        "database_write",
        "database_delete",
        "file_write",
        "file_delete",
        "cloud_deploy",
        "system_cmd",
        "eval",
        "exec",
    }

    MEDIUM_RISK_TOOLS: set[str] = {
        "web_search",
        "read_file",
        "http_request",
        "api_call",
        "database_read",
    }

    HIGH_RISK_ACTIONS: set[str] = {
        "delete",
        "drop",
        "truncate",
        "execute",
        "exec",
        "shell",
        "eval",
        "bash",
        "deploy",
        "wipe",
        "exfiltrate",
        "modify_system",
        "kill",
        "terminate",
        "format",
        "escalate",
    }

    MEDIUM_RISK_ACTIONS: set[str] = {
        "write",
        "update",
        "create",
        "send",
        "upload",
        "patch",
        "modify",
        "insert",
        "post",
        "put",
    }

    LOW_RISK_ACTIONS: set[str] = {
        "read",
        "query",
        "select",
        "get",
        "fetch",
        "search",
        "list",
        "view",
        "describe",
        "inspect",
        "allow",
    }

    def __init__(
        self,
        config: AgentShieldConfig | None = None,
        weights: dict[str, float] | None = None,
        thresholds: dict[str, float] | None = None,
    ) -> None:
        self.config = config or AgentShieldConfig()

        # Configurable component weights
        self.weights: dict[str, float] = {
            "injection": self.config.weight_injection,
            "secret": self.config.weight_secret,
            "dlp": self.config.weight_dlp,
            "pii": self.config.weight_pii,
            "source_trust": 0.15,
            "requested_action": 0.10,
        }
        if weights:
            self.weights.update(weights)

        # Configurable decision thresholds (normalized 0.0 - 1.0)
        self.thresholds: dict[str, float] = {
            "safe": 0.20,
            "low": 0.45,
            "medium": 0.70,
            "high": 0.85,
            "warn": self.config.risk_warn_threshold,
            "block": self.config.risk_block_threshold,
            "quarantine": 0.85,
        }
        if thresholds:
            self.set_thresholds(thresholds)

    def set_weights(self, weights: dict[str, float]) -> None:
        """Configures or updates component weights."""
        self.weights.update(weights)

    def update_weights(self, **kwargs: float) -> dict[str, float]:
        """Updates specific component weights via keyword arguments."""
        for k, v in kwargs.items():
            if k in self.weights:
                self.weights[k] = float(v)
        return self.weights.copy()

    def set_thresholds(self, thresholds: dict[str, float]) -> None:
        """Configures or updates risk and action thresholds."""
        for k, v in thresholds.items():
            val = float(v)
            if val > 1.0:
                val /= 100.0
            self.thresholds[k] = val

    def update_thresholds(self, **kwargs: float) -> dict[str, float]:
        """Updates specific risk or action thresholds via keyword arguments."""
        for k, v in kwargs.items():
            val = float(v)
            if val > 1.0:
                val /= 100.0
            self.thresholds[k] = val
        return self.thresholds.copy()

    def reset_configuration(self) -> None:
        """Restores weights and thresholds to configuration defaults."""
        self.weights = {
            "injection": self.config.weight_injection,
            "secret": self.config.weight_secret,
            "dlp": self.config.weight_dlp,
            "pii": self.config.weight_pii,
            "source_trust": 0.15,
            "requested_action": 0.10,
        }
        self.thresholds = {
            "safe": 0.20,
            "low": 0.45,
            "medium": 0.70,
            "high": 0.85,
            "warn": self.config.risk_warn_threshold,
            "block": self.config.risk_block_threshold,
            "quarantine": 0.85,
        }

    def _normalize_trust_level(
        self,
        source_trust: TrustLevel | str | None,
        provenance_record: ProvenanceRecord | None,
        context: GuardrailContext | None,
    ) -> TrustLevel:
        """Resolves the effective trust level from arguments, provenance, or context."""
        # 1. Direct argument
        if isinstance(source_trust, TrustLevel):
            return source_trust
        if isinstance(source_trust, str):
            normalized = source_trust.strip().lower()
            for tl in TrustLevel:
                if tl.value == normalized:
                    return tl

        # 2. Provenance record
        if provenance_record:
            if isinstance(provenance_record.trust_level, TrustLevel):
                return provenance_record.trust_level
            if hasattr(provenance_record, "source_type") and provenance_record.source_type:
                return DEFAULT_SOURCE_TRUST_LEVELS.get(provenance_record.source_type, TrustLevel.MEDIUM)

        # 3. Context metadata
        if context and context.metadata:
            meta_trust = context.metadata.get("source_trust") or context.metadata.get("trust_level")
            if isinstance(meta_trust, TrustLevel):
                return meta_trust
            if isinstance(meta_trust, str):
                normalized = meta_trust.strip().lower()
                for tl in TrustLevel:
                    if tl.value == normalized:
                        return tl
            meta_source = context.metadata.get("source_type")
            if isinstance(meta_source, SourceType):
                return DEFAULT_SOURCE_TRUST_LEVELS.get(meta_source, TrustLevel.MEDIUM)
            if isinstance(meta_source, str):
                norm_source = meta_source.strip().lower()
                for st in SourceType:
                    if st.value == norm_source:
                        return DEFAULT_SOURCE_TRUST_LEVELS.get(st, TrustLevel.MEDIUM)

        return TrustLevel.MEDIUM

    def _assess_requested_action(
        self,
        requested_action: Action | str | None,
        context: GuardrailContext | None,
    ) -> tuple[float, str | None]:
        """Assesses risk attributed to the requested action or operation."""
        action_val: Action | str | None = requested_action
        if action_val is None and context and context.metadata:
            action_val = context.metadata.get("requested_action") or context.metadata.get("action")

        if action_val is None:
            return 0.0, None

        if isinstance(action_val, Action):
            if action_val == Action.QUARANTINE:
                return 1.0, "QUARANTINE"
            if action_val == Action.BLOCK:
                return 0.95, "BLOCK"
            if action_val == Action.WARN:
                return 0.40, "WARN"
            if action_val == Action.MASK:
                return 0.25, "MASK"
            if action_val == Action.ALLOW:
                return 0.0, "ALLOW"

        action_str = str(action_val).strip().lower()
        # Check against high-risk actions
        for act in self.HIGH_RISK_ACTIONS:
            if act in action_str:
                return 0.90, action_str

        # Check against medium-risk actions
        for act in self.MEDIUM_RISK_ACTIONS:
            if act in action_str:
                return 0.50, action_str

        # Check against low-risk actions
        for act in self.LOW_RISK_ACTIONS:
            if act in action_str:
                return 0.10, action_str

        return 0.30, action_str

    def evaluate(
        self,
        injection_res: InjectionAnalysisResult | None = None,
        pii_res: PIIAnalysisResult | None = None,
        secret_res: SecretAnalysisResult | None = None,
        dlp_res: DLPAnalysisResult | None = None,
        findings: list[DetectionFinding] | None = None,
        context: GuardrailContext | None = None,
        source_trust: TrustLevel | str | None = None,
        provenance_record: ProvenanceRecord | None = None,
        requested_action: Action | str | None = None,
    ) -> RiskScore:
        """
        Computes compound risk score, normalized 0-100 score, risk level,
        and action policy recommendation based on findings, source trust,
        agent permissions, and requested actions.
        """
        factors: list[str] = []
        component_scores: dict[str, float] = {
            "injection": 0.0,
            "secret": 0.0,
            "pii": 0.0,
            "dlp": 0.0,
            "source_trust": 0.0,
            "requested_action": 0.0,
        }

        # Collect raw findings passed directly
        direct_findings: list[DetectionFinding] = list(findings) if findings else []
        has_maskable_findings = False

        # --------------------------------------------------------------------
        # 1. Injection Vector
        # --------------------------------------------------------------------
        inj_findings = [f for f in direct_findings if f.detector == DetectorType.INJECTION]
        if injection_res and injection_res.findings:
            inj_findings.extend(injection_res.findings)

        if injection_res and (injection_res.findings or injection_res.confidence > 0):
            component_scores["injection"] = injection_res.confidence
            cats = ", ".join(injection_res.attack_categories) if injection_res.attack_categories else "general"
            factors.append(f"Prompt injection risk ({cats}) with confidence {injection_res.confidence:.2f}")
            if injection_res.obfuscation_detected:
                factors.append("Obfuscation technique detected in injection payload")
        elif inj_findings:
            max_inj = max(f.risk_score for f in inj_findings)
            component_scores["injection"] = max_inj
            factors.append(f"Prompt injection risk detected from {len(inj_findings)} finding(s) with max score {max_inj:.2f}")

        # --------------------------------------------------------------------
        # 2. Secret Vector
        # --------------------------------------------------------------------
        sec_findings = [f for f in direct_findings if f.detector == DetectorType.SECRET]
        if secret_res and secret_res.findings:
            sec_findings.extend(secret_res.findings)

        if secret_res and secret_res.findings:
            max_secret = max(f.risk_score for f in secret_res.findings)
            component_scores["secret"] = max_secret
            factors.append(f"Secret/credential leakage detected ({secret_res.secret_count} occurrences)")
            has_maskable_findings = True
        elif sec_findings:
            max_secret = max(f.risk_score for f in sec_findings)
            component_scores["secret"] = max_secret
            factors.append(f"Secret/credential leakage detected ({len(sec_findings)} occurrences)")
            has_maskable_findings = True

        # --------------------------------------------------------------------
        # 3. PII Vector
        # --------------------------------------------------------------------
        pii_finding_list = [f for f in direct_findings if f.detector == DetectorType.PII]
        if pii_res and pii_res.findings:
            pii_finding_list.extend(pii_res.findings)

        if pii_res and pii_res.findings:
            max_pii = max(f.risk_score for f in pii_res.findings)
            scaled_pii = min(1.0, max_pii + (0.05 * (len(pii_res.findings) - 1)))
            component_scores["pii"] = scaled_pii
            factors.append(f"Personally Identifiable Information present ({pii_res.pii_count} items)")
            has_maskable_findings = True
        elif pii_finding_list:
            max_pii = max(f.risk_score for f in pii_finding_list)
            scaled_pii = min(1.0, max_pii + (0.05 * (len(pii_finding_list) - 1)))
            component_scores["pii"] = scaled_pii
            factors.append(f"Personally Identifiable Information present ({len(pii_finding_list)} items)")
            has_maskable_findings = True

        # --------------------------------------------------------------------
        # 4. DLP Vector
        # --------------------------------------------------------------------
        dlp_finding_list = [f for f in direct_findings if f.detector == DetectorType.DLP]
        if dlp_res and dlp_res.findings:
            dlp_finding_list.extend(dlp_res.findings)

        if dlp_res and dlp_res.findings:
            max_dlp = max(f.risk_score for f in dlp_res.findings)
            component_scores["dlp"] = max_dlp
            factors.append(f"DLP classification alert at level {dlp_res.highest_sensitivity.value.upper()}")
        elif dlp_finding_list:
            max_dlp = max(f.risk_score for f in dlp_finding_list)
            component_scores["dlp"] = max_dlp
            factors.append(f"DLP classification finding detected ({len(dlp_finding_list)} items)")

        # --------------------------------------------------------------------
        # 5. Source Trust Evaluation
        # --------------------------------------------------------------------
        resolved_trust = self._normalize_trust_level(source_trust, provenance_record, context)
        trust_multiplier = TRUST_MULTIPLIERS.get(resolved_trust, 1.00)
        component_scores["source_trust"] = TRUST_COMPONENT_SCORES.get(resolved_trust, 0.35)

        if resolved_trust != TrustLevel.MEDIUM:
            factors.append(f"Source trust evaluated as {resolved_trust.value.upper()} (multiplier x{trust_multiplier:.2f})")

        # --------------------------------------------------------------------
        # 6. Requested Action Risk Evaluation
        # --------------------------------------------------------------------
        action_risk, action_name = self._assess_requested_action(requested_action, context)
        component_scores["requested_action"] = action_risk
        if action_name and action_risk > 0.0:
            factors.append(f"Requested action assessed: '{action_name}' (action risk factor: {action_risk:.2f})")

        # --------------------------------------------------------------------
        # 7. Agent Permissions & Capability Multipliers
        # --------------------------------------------------------------------
        context_multiplier = 1.0
        active_high_risk: set[str] = set()

        if context:
            if context.is_privileged_agent:
                context_multiplier = self.config.privileged_agent_multiplier
                factors.append(f"Privileged agent risk multiplier applied (x{context_multiplier:.2f})")

            # Check high-impact tool capabilities
            active_high_risk = set(context.tools_enabled).intersection(self.HIGH_RISK_TOOLS)
            if active_high_risk:
                tool_mult = 1.15
                context_multiplier *= tool_mult
                factors.append(f"High-impact tools active ({', '.join(sorted(active_high_risk))})")

            # Check metadata permissions
            if context.metadata:
                permissions = str(context.metadata.get("permissions", "")).lower()
                role = str(context.metadata.get("role", "")).lower()
                if any(kw in permissions or kw in role for kw in ("admin", "root", "superuser", "elevated")):
                    if not context.is_privileged_agent:
                        context_multiplier *= 1.15
                        factors.append("Elevated administrative permissions active")
                elif "read_only" in permissions or "read_only" in role:
                    context_multiplier *= 0.90
                    factors.append("Read-only permissions applied (risk dampener)")

        # Factor in source trust multiplier if threats or operations exist
        has_security_findings = any(
            component_scores[k] > 0.0 for k in ("injection", "secret", "pii", "dlp")
        )
        if has_security_findings or action_risk > 0.0:
            context_multiplier *= trust_multiplier

        # Clamp context multiplier to schema constraints [0.5, 3.0]
        context_multiplier = min(3.0, max(0.5, context_multiplier))

        # --------------------------------------------------------------------
        # 8. Weighted Compound Aggregation
        # --------------------------------------------------------------------
        raw_weighted = (
            component_scores["injection"] * self.weights.get("injection", self.config.weight_injection)
            + component_scores["secret"] * self.weights.get("secret", self.config.weight_secret)
            + component_scores["dlp"] * self.weights.get("dlp", self.config.weight_dlp)
            + component_scores["pii"] * self.weights.get("pii", self.config.weight_pii)
        )

        # Include requested action risk contribution when an explicit action is assessed
        if action_risk > 0.0:
            raw_weighted += action_risk * self.weights.get("requested_action", 0.10)

        overall_score = min(1.0, raw_weighted * context_multiplier)

        # --------------------------------------------------------------------
        # 9. Fast-Path Hard Policy Triggers
        # --------------------------------------------------------------------
        # Hard blocking condition for secrets
        if self.config.block_on_secret_leak and component_scores["secret"] >= 0.90:
            overall_score = max(overall_score, 0.95)
            factors.append("CRITICAL: Unmasked credential leak triggered mandatory block policy")

        # Hard blocking condition for injections
        if self.config.block_on_critical_injection and injection_res and injection_res.is_injection:
            overall_score = max(overall_score, 0.90)
            factors.append("CRITICAL: Prompt injection confidence crossed block threshold")

        # DLP policy violation
        if dlp_res and dlp_res.violates_policy:
            overall_score = max(overall_score, 0.85)
            factors.append(
                f"CRITICAL: Sensitivity exceeds permitted threshold ({self.config.dlp_max_allowed_sensitivity.value})"
            )

        # --------------------------------------------------------------------
        # 10. Risk Level Categorization (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
        # --------------------------------------------------------------------
        if overall_score < self.thresholds["safe"]:
            level = RiskLevel.SAFE
        elif overall_score < self.thresholds["low"]:
            level = RiskLevel.LOW
        elif overall_score < self.thresholds["medium"]:
            level = RiskLevel.MEDIUM
        elif overall_score < self.thresholds["high"]:
            level = RiskLevel.HIGH
        else:
            level = RiskLevel.CRITICAL

        # --------------------------------------------------------------------
        # 11. Decisive Action Policy (ALLOW, WARN, MASK, BLOCK, QUARANTINE)
        # --------------------------------------------------------------------
        # Check quarantine triggers
        explicit_quarantine = (
            requested_action == Action.QUARANTINE
            or (isinstance(requested_action, str) and requested_action.lower() == "quarantine")
            or bool(
                context
                and (
                    context.metadata.get("quarantine") is True
                    or (context.metadata.get("quarantine_on_critical") is True and level == RiskLevel.CRITICAL)
                )
            )
        )

        # Severe multi-vector threat containment from untrusted source
        untrusted_critical_containment = (
            level == RiskLevel.CRITICAL
            and resolved_trust in (TrustLevel.UNTRUSTED, TrustLevel.LOW)
            and (bool(active_high_risk) or (context and context.is_privileged_agent))
        )

        if explicit_quarantine or untrusted_critical_containment:
            action = Action.QUARANTINE
            if untrusted_critical_containment and not explicit_quarantine:
                factors.append("QUARANTINE: Critical multi-vector threat from untrusted origin isolated for containment")
        elif overall_score >= self.thresholds["block"]:
            action = Action.BLOCK
        elif overall_score >= self.thresholds["warn"]:
            if (pii_res and pii_res.has_pii) or (secret_res and secret_res.has_secrets) or has_maskable_findings:
                action = Action.MASK
            else:
                action = Action.WARN
        else:
            # Low or Safe risk: if PII or maskable secrets are present, sanitize via MASK
            if (pii_res and pii_res.has_pii) or (secret_res and secret_res.has_secrets) or has_maskable_findings:
                action = Action.MASK
            else:
                action = Action.ALLOW

        # --------------------------------------------------------------------
        # 12. 0-100 Normalized Score Calculation
        # --------------------------------------------------------------------
        overall_score_clamped = min(1.0, max(0.0, overall_score))
        score_100 = round(overall_score_clamped * 100.0, 2)

        component_scores["normalized_score_100"] = score_100
        component_scores["score_100"] = score_100

        logger.debug(
            "Risk evaluation computed. Score=%.3f (100-scale=%.2f), Level=%s, Action=%s",
            overall_score_clamped,
            score_100,
            level.value,
            action.value,
        )

        score = RiskScore(
            overall_score=round(overall_score_clamped, 3),
            level=level,
            component_scores={k: round(v, 3) if isinstance(v, float) else v for k, v in component_scores.items()},
            factors=factors,
            recommended_action=action,
            context_multiplier=round(context_multiplier, 2),
        )

        # Dynamically attach score_100 attribute for direct accessibility
        object.__setattr__(score, "score_100", score_100)
        object.__setattr__(score, "normalized_score_100", score_100)

        return score

    def get_score_100(self, score: RiskScore) -> float:
        """Returns normalized risk score from 0.0 to 100.0."""
        return getattr(score, "score_100", round(score.overall_score * 100.0, 2))

    def to_score_100(self, score: RiskScore) -> float:
        """Convenience alias for get_score_100."""
        return self.get_score_100(score)

    def evaluate_100(self, *args: Any, **kwargs: Any) -> tuple[float, RiskLevel, Action]:
        """Convenience evaluator returning a tuple of (score_100, RiskLevel, Action)."""
        score = self.evaluate(*args, **kwargs)
        return self.get_score_100(score), score.level, score.recommended_action
