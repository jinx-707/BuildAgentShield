"""
Unit tests for AgentShield Context-Aware Risk Engine.
Comprehensive coverage for multi-vector threat scoring, 0-100 normalization,
SAFE/LOW/MEDIUM/HIGH/CRITICAL risk tiers, ALLOW/WARN/MASK/BLOCK/QUARANTINE actions,
source trust, agent permissions, requested actions, and dynamic configuration.
"""

import pytest
from core.config import AgentShieldConfig
from core.risk_engine import RiskEngine
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
    SecretAnalysisResult,
    SensitivityLevel,
    SourceType,
    TrustLevel,
)


@pytest.fixture
def risk_engine() -> RiskEngine:
    config = AgentShieldConfig(
        risk_warn_threshold=0.45,
        risk_block_threshold=0.75,
        weight_injection=0.35,
        weight_secret=0.30,
        weight_dlp=0.20,
        weight_pii=0.15,
    )
    return RiskEngine(config)


# ============================================================================
# Existing Core Baseline Tests (Preserved 100%)
# ============================================================================

def test_benign_evaluation_returns_safe(risk_engine: RiskEngine) -> None:
    score = risk_engine.evaluate()
    assert score.overall_score == 0.0
    assert score.level == RiskLevel.SAFE
    assert score.recommended_action == Action.ALLOW


def test_pii_triggers_mask_action(risk_engine: RiskEngine) -> None:
    pii_finding = DetectionFinding(
        detector=DetectorType.PII,
        rule_id="PII_EMAIL_001",
        description="Email found",
        risk_score=0.40,
    )
    pii_res = PIIAnalysisResult(
        has_pii=True,
        pii_count=1,
        findings=[pii_finding],
        sanitized_text="Redacted text",
    )
    score = risk_engine.evaluate(pii_res=pii_res)
    assert score.recommended_action == Action.MASK
    assert "email" in score.factors[0].lower() or "personally identifiable" in score.factors[0].lower()


def test_compound_risk_aggregation(risk_engine: RiskEngine) -> None:
    inj_res = InjectionAnalysisResult(
        is_injection=False,
        confidence=0.50,
        attack_categories=["HYPOTHETICAL"],
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_JBK_004",
                description="Hypothetical framing",
                risk_score=0.50,
            )
        ],
    )
    dlp_res = DLPAnalysisResult(
        violates_policy=False,
        highest_sensitivity=SensitivityLevel.INTERNAL,
        findings=[
            DetectionFinding(
                detector=DetectorType.DLP,
                rule_id="DLP_INFRA_001",
                description="Internal domain",
                risk_score=0.40,
            )
        ],
        sanitized_text="sanitized",
    )

    score = risk_engine.evaluate(injection_res=inj_res, dlp_res=dlp_res)
    # Expected weighted: 0.50 * 0.35 + 0.40 * 0.20 = 0.175 + 0.08 = 0.255
    assert score.overall_score > 0.20
    assert score.component_scores["injection"] == 0.50
    assert score.component_scores["dlp"] == 0.40


def test_privileged_agent_multiplier(risk_engine: RiskEngine) -> None:
    inj_res = InjectionAnalysisResult(
        is_injection=False,
        confidence=0.40,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_001",
                description="Moderate test",
                risk_score=0.40,
            )
        ],
    )
    standard_ctx = GuardrailContext(is_privileged_agent=False)
    score_standard = risk_engine.evaluate(injection_res=inj_res, context=standard_ctx)

    privileged_ctx = GuardrailContext(is_privileged_agent=True)
    score_privileged = risk_engine.evaluate(injection_res=inj_res, context=privileged_ctx)

    assert score_privileged.overall_score > score_standard.overall_score
    assert score_privileged.context_multiplier > 1.0


def test_high_impact_tool_context(risk_engine: RiskEngine) -> None:
    inj_res = InjectionAnalysisResult(
        is_injection=False,
        confidence=0.40,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_001",
                description="Moderate test",
                risk_score=0.40,
            )
        ],
    )
    tool_ctx = GuardrailContext(tools_enabled=["bash", "python_repl"])
    score = risk_engine.evaluate(injection_res=inj_res, context=tool_ctx)
    assert any("High-impact tools active" in f for f in score.factors)


def test_critical_secret_leak_triggers_mandatory_block(risk_engine: RiskEngine) -> None:
    secret_res = SecretAnalysisResult(
        has_secrets=True,
        secret_count=1,
        findings=[
            DetectionFinding(
                detector=DetectorType.SECRET,
                rule_id="SEC_KEY_001",
                description="Private key",
                risk_score=1.0,
            )
        ],
        sanitized_text="sanitized",
    )
    score = risk_engine.evaluate(secret_res=secret_res)
    assert score.overall_score >= 0.90
    assert score.level == RiskLevel.CRITICAL
    assert score.recommended_action == Action.BLOCK


# ============================================================================
# Prompt 7 Requirement 2: 0-100 Normalized Risk Score Tests
# ============================================================================

def test_normalized_score_0_to_100_benign(risk_engine: RiskEngine) -> None:
    score = risk_engine.evaluate()
    assert score.overall_score == 0.0
    assert score.score_100 == 0.0
    assert score.normalized_score_100 == 0.0
    assert score.component_scores["normalized_score_100"] == 0.0
    assert score.component_scores["score_100"] == 0.0
    assert risk_engine.get_score_100(score) == 0.0
    assert risk_engine.to_score_100(score) == 0.0


def test_normalized_score_0_to_100_scaling(risk_engine: RiskEngine) -> None:
    # Injection confidence 0.80 -> 0.80 * 0.35 = 0.28 overall score -> 28.0 on 100-scale
    inj_res = InjectionAnalysisResult(
        confidence=0.80,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_002",
                description="Suspicious prompt",
                risk_score=0.80,
            )
        ],
    )
    score = risk_engine.evaluate(injection_res=inj_res)
    assert score.overall_score == pytest.approx(0.28, abs=0.01)
    assert score.score_100 == pytest.approx(28.0, abs=1.0)
    assert score.component_scores["normalized_score_100"] == pytest.approx(28.0, abs=1.0)
    assert risk_engine.get_score_100(score) == pytest.approx(28.0, abs=1.0)

    score_100, level, action = risk_engine.evaluate_100(injection_res=inj_res)
    assert score_100 == pytest.approx(28.0, abs=1.0)
    assert level == RiskLevel.LOW
    assert action == Action.ALLOW


# ============================================================================
# Prompt 7 Requirement 3: All 5 Risk Levels (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
# ============================================================================

def test_risk_level_safe(risk_engine: RiskEngine) -> None:
    # Score < 0.20 -> SAFE
    score = risk_engine.evaluate()
    assert score.overall_score < 0.20
    assert score.level == RiskLevel.SAFE


def test_risk_level_low(risk_engine: RiskEngine) -> None:
    # 0.20 <= Score < 0.45 -> LOW
    inj_res = InjectionAnalysisResult(
        confidence=0.70,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_LOW",
                description="Low injection",
                risk_score=0.70,
            )
        ],
    )
    score = risk_engine.evaluate(injection_res=inj_res)
    # 0.70 * 0.35 = 0.245
    assert 0.20 <= score.overall_score < 0.45
    assert score.level == RiskLevel.LOW


def test_risk_level_medium(risk_engine: RiskEngine) -> None:
    # 0.45 <= Score < 0.70 -> MEDIUM
    inj_res = InjectionAnalysisResult(
        confidence=0.80,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_MED",
                description="Med injection",
                risk_score=0.80,
            )
        ],
    )
    sec_res = SecretAnalysisResult(
        has_secrets=True,
        secret_count=1,
        findings=[
            DetectionFinding(
                detector=DetectorType.SECRET,
                rule_id="SEC_MED",
                description="Internal token",
                risk_score=0.75,
            )
        ],
        sanitized_text="token",
    )
    score = risk_engine.evaluate(injection_res=inj_res, secret_res=sec_res)
    # 0.80 * 0.35 + 0.75 * 0.30 = 0.28 + 0.225 = 0.505
    assert 0.45 <= score.overall_score < 0.70
    assert score.level == RiskLevel.MEDIUM


def test_risk_level_high(risk_engine: RiskEngine) -> None:
    # 0.70 <= Score < 0.85 -> HIGH
    inj_res = InjectionAnalysisResult(
        confidence=0.85,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_HIGH",
                description="High injection",
                risk_score=0.85,
            )
        ],
    )
    sec_res = SecretAnalysisResult(
        has_secrets=True,
        secret_count=1,
        findings=[
            DetectionFinding(
                detector=DetectorType.SECRET,
                rule_id="SEC_HIGH",
                description="Access token",
                risk_score=0.85,
            )
        ],
        sanitized_text="token",
    )
    dlp_res = DLPAnalysisResult(
        violates_policy=False,
        highest_sensitivity=SensitivityLevel.CONFIDENTIAL,
        findings=[
            DetectionFinding(
                detector=DetectorType.DLP,
                rule_id="DLP_HIGH",
                description="Confidential design doc",
                risk_score=0.85,
            )
        ],
        sanitized_text="confidential",
    )
    # 0.85 * 0.35 + 0.85 * 0.30 + 0.85 * 0.20 = 0.2975 + 0.255 + 0.170 = 0.7225
    score = risk_engine.evaluate(injection_res=inj_res, secret_res=sec_res, dlp_res=dlp_res)
    assert 0.70 <= score.overall_score < 0.85
    assert score.level == RiskLevel.HIGH


def test_risk_level_critical(risk_engine: RiskEngine) -> None:
    # Score >= 0.85 -> CRITICAL
    inj_res = InjectionAnalysisResult(
        is_injection=True,
        confidence=0.98,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_CRIT",
                description="Critical jailbreak",
                risk_score=0.98,
            )
        ],
    )
    score = risk_engine.evaluate(injection_res=inj_res)
    assert score.overall_score >= 0.85
    assert score.level == RiskLevel.CRITICAL


# ============================================================================
# Prompt 7 Requirement 4: All 5 Actions (ALLOW, WARN, MASK, BLOCK, QUARANTINE)
# ============================================================================

def test_action_allow(risk_engine: RiskEngine) -> None:
    score = risk_engine.evaluate()
    assert score.recommended_action == Action.ALLOW


def test_action_warn(risk_engine: RiskEngine) -> None:
    # Moderate risk (>= warn_threshold = 0.45) with no PII/secrets to mask
    inj_res = InjectionAnalysisResult(
        confidence=0.90,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_WARN",
                description="Moderate injection suspicion",
                risk_score=0.90,
            )
        ],
    )
    dlp_res = DLPAnalysisResult(
        violates_policy=False,
        highest_sensitivity=SensitivityLevel.INTERNAL,
        findings=[
            DetectionFinding(
                detector=DetectorType.DLP,
                rule_id="DLP_WARN",
                description="Internal reference",
                risk_score=0.80,
            )
        ],
        sanitized_text="internal",
    )
    # 0.90 * 0.35 + 0.80 * 0.20 = 0.315 + 0.160 = 0.475 (between 0.45 and 0.75)
    score = risk_engine.evaluate(injection_res=inj_res, dlp_res=dlp_res)
    assert 0.45 <= score.overall_score < 0.75
    assert score.recommended_action == Action.WARN


def test_action_mask(risk_engine: RiskEngine) -> None:
    pii_finding = DetectionFinding(
        detector=DetectorType.PII,
        rule_id="PII_001",
        description="Phone number found",
        risk_score=0.45,
    )
    pii_res = PIIAnalysisResult(
        has_pii=True,
        pii_count=1,
        findings=[pii_finding],
        sanitized_text="masked",
    )
    score = risk_engine.evaluate(pii_res=pii_res)
    assert score.recommended_action == Action.MASK


def test_action_block(risk_engine: RiskEngine) -> None:
    dlp_res = DLPAnalysisResult(
        violates_policy=True,
        highest_sensitivity=SensitivityLevel.RESTRICTED,
        findings=[
            DetectionFinding(
                detector=DetectorType.DLP,
                rule_id="DLP_RESTRICTED",
                description="Restricted corporate secret",
                risk_score=1.0,
            )
        ],
        sanitized_text="sanitized",
    )
    score = risk_engine.evaluate(dlp_res=dlp_res)
    assert score.recommended_action == Action.BLOCK


def test_action_quarantine_explicit_request(risk_engine: RiskEngine) -> None:
    # Explicit Action.QUARANTINE or string "quarantine"
    score = risk_engine.evaluate(requested_action=Action.QUARANTINE)
    assert score.recommended_action == Action.QUARANTINE

    score_str = risk_engine.evaluate(requested_action="quarantine")
    assert score_str.recommended_action == Action.QUARANTINE


def test_action_quarantine_context_flag(risk_engine: RiskEngine) -> None:
    # Quarantine flag in context metadata
    ctx = GuardrailContext(metadata={"quarantine": True})
    score = risk_engine.evaluate(context=ctx)
    assert score.recommended_action == Action.QUARANTINE


def test_action_quarantine_untrusted_source_critical_threat(risk_engine: RiskEngine) -> None:
    # Critical threat from UNTRUSTED origin with active execution tools triggers quarantine
    inj_res = InjectionAnalysisResult(
        is_injection=True,
        confidence=0.98,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_CRIT_001",
                description="Remote code exploit payload",
                risk_score=0.98,
            )
        ],
    )
    ctx = GuardrailContext(tools_enabled=["bash", "python_repl"])
    score = risk_engine.evaluate(
        injection_res=inj_res,
        context=ctx,
        source_trust=TrustLevel.UNTRUSTED,
    )
    assert score.level == RiskLevel.CRITICAL
    assert score.recommended_action == Action.QUARANTINE
    assert any("QUARANTINE" in factor for factor in score.factors)


# ============================================================================
# Prompt 7 Requirement 1: Source Trust & Provenance Integration
# ============================================================================

def test_source_trust_untrusted_vs_trusted(risk_engine: RiskEngine) -> None:
    inj_res = InjectionAnalysisResult(
        confidence=0.60,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_001",
                description="Suspicious phrasing",
                risk_score=0.60,
            )
        ],
    )
    # Untrusted source multiplier = 1.30
    score_untrusted = risk_engine.evaluate(
        injection_res=inj_res,
        source_trust=TrustLevel.UNTRUSTED,
    )
    # Trusted source multiplier = 0.80
    score_trusted = risk_engine.evaluate(
        injection_res=inj_res,
        source_trust=TrustLevel.TRUSTED,
    )

    assert score_untrusted.overall_score > score_trusted.overall_score
    assert score_untrusted.component_scores["source_trust"] > score_trusted.component_scores["source_trust"]
    assert any("UNTRUSTED" in f for f in score_untrusted.factors)
    assert any("TRUSTED" in f for f in score_trusted.factors)


def test_provenance_record_source_trust_integration(risk_engine: RiskEngine) -> None:
    inj_res = InjectionAnalysisResult(
        confidence=0.50,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_001",
                description="Suspicious command",
                risk_score=0.50,
            )
        ],
    )
    prov_record = ProvenanceRecord(
        sequence_number=1,
        current_hash="abc123hash",
        input_hash="input123hash",
        action_taken=Action.ALLOW,
        risk_level=RiskLevel.MEDIUM,
        source_type=SourceType.WEBSITE,
        trust_level=TrustLevel.UNTRUSTED,
    )
    score = risk_engine.evaluate(injection_res=inj_res, provenance_record=prov_record)
    assert score.component_scores["source_trust"] == 1.00
    assert any("UNTRUSTED" in f for f in score.factors)


# ============================================================================
# Prompt 7 Requirement 1: Agent Permissions & Capability Evaluation
# ============================================================================

def test_agent_permissions_elevated_role(risk_engine: RiskEngine) -> None:
    inj_res = InjectionAnalysisResult(
        confidence=0.40,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_001",
                description="Minor pattern",
                risk_score=0.40,
            )
        ],
    )
    admin_ctx = GuardrailContext(metadata={"role": "admin"})
    score_admin = risk_engine.evaluate(injection_res=inj_res, context=admin_ctx)

    standard_ctx = GuardrailContext(metadata={"role": "guest"})
    score_standard = risk_engine.evaluate(injection_res=inj_res, context=standard_ctx)

    assert score_admin.overall_score > score_standard.overall_score
    assert any("Elevated administrative" in f for f in score_admin.factors)


def test_agent_permissions_read_only_dampener(risk_engine: RiskEngine) -> None:
    inj_res = InjectionAnalysisResult(
        confidence=0.40,
        findings=[
            DetectionFinding(
                detector=DetectorType.INJECTION,
                rule_id="INJ_001",
                description="Minor pattern",
                risk_score=0.40,
            )
        ],
    )
    read_only_ctx = GuardrailContext(metadata={"permissions": "read_only"})
    score_ro = risk_engine.evaluate(injection_res=inj_res, context=read_only_ctx)
    assert any("Read-only permissions applied" in f for f in score_ro.factors)


# ============================================================================
# Prompt 7 Requirement 1: Requested Action Risk Evaluation
# ============================================================================

def test_requested_action_destructive_increases_risk(risk_engine: RiskEngine) -> None:
    score = risk_engine.evaluate(requested_action="delete_database_cluster")
    assert score.component_scores["requested_action"] >= 0.85
    assert score.overall_score > 0.0
    assert any("Requested action assessed" in f for f in score.factors)


def test_requested_action_read_only_low_risk(risk_engine: RiskEngine) -> None:
    score = risk_engine.evaluate(requested_action="read_system_logs")
    assert score.component_scores["requested_action"] <= 0.20
    assert score.level == RiskLevel.SAFE


# ============================================================================
# Prompt 7 Requirement 1: Direct Findings List Support
# ============================================================================

def test_evaluate_direct_findings_list(risk_engine: RiskEngine) -> None:
    findings = [
        DetectionFinding(
            detector=DetectorType.INJECTION,
            rule_id="INJ_DIRECT_001",
            description="Direct injection finding",
            risk_score=0.70,
        ),
        DetectionFinding(
            detector=DetectorType.PII,
            rule_id="PII_DIRECT_001",
            description="Direct PII finding",
            risk_score=0.50,
        ),
    ]
    score = risk_engine.evaluate(findings=findings)
    assert score.component_scores["injection"] == 0.70
    assert score.component_scores["pii"] >= 0.50
    assert score.recommended_action == Action.MASK


# ============================================================================
# Prompt 7 Requirement 5: Configurable Weights & Thresholds
# ============================================================================

def test_custom_weights_at_initialization() -> None:
    # Custom weights prioritizing secrets heavily
    custom_weights = {
        "injection": 0.10,
        "secret": 0.80,
        "dlp": 0.05,
        "pii": 0.05,
    }
    engine = RiskEngine(weights=custom_weights)
    assert engine.weights["secret"] == 0.80
    assert engine.weights["injection"] == 0.10

    sec_res = SecretAnalysisResult(
        has_secrets=True,
        secret_count=1,
        findings=[
            DetectionFinding(
                detector=DetectorType.SECRET,
                rule_id="SEC_001",
                description="Test secret",
                risk_score=0.80,
            )
        ],
        sanitized_text="secret",
    )
    score = engine.evaluate(secret_res=sec_res)
    # 0.80 * 0.80 = 0.64
    assert score.overall_score == pytest.approx(0.64, abs=0.02)


def test_dynamic_weights_update(risk_engine: RiskEngine) -> None:
    risk_engine.update_weights(injection=0.90, secret=0.05)
    assert risk_engine.weights["injection"] == 0.90
    assert risk_engine.weights["secret"] == 0.05


def test_dynamic_thresholds_update(risk_engine: RiskEngine) -> None:
    # Relax thresholds: warn at 0.60, block at 0.90
    risk_engine.update_thresholds(warn=0.60, block=0.90)
    assert risk_engine.thresholds["warn"] == 0.60
    assert risk_engine.thresholds["block"] == 0.90

    # Also support 0-100 scale input
    risk_engine.update_thresholds(warn=70.0, block=95.0)
    assert risk_engine.thresholds["warn"] == 0.70
    assert risk_engine.thresholds["block"] == 0.95


def test_reset_configuration(risk_engine: RiskEngine) -> None:
    risk_engine.update_weights(injection=0.99)
    risk_engine.update_thresholds(block=0.99)
    risk_engine.reset_configuration()
    assert risk_engine.weights["injection"] == risk_engine.config.weight_injection
    assert risk_engine.thresholds["block"] == risk_engine.config.risk_block_threshold
