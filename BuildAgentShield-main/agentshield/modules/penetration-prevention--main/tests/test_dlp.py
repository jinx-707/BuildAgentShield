"""
Comprehensive Unit Tests for the AgentShield Data Loss Prevention (DLP) Engine.

Covers:
  * Data classification across all four tiers (PUBLIC, INTERNAL, CONFIDENTIAL,
    RESTRICTED).
  * Detection of sensitive information before release to external tools.
  * Integration with the existing PII Detector and Secret Scanner.
  * Configurable ALLOW / WARN / MASK / BLOCK decisions.
  * Standardized ``DetectionFinding`` objects and security decisions.
  * Redaction / masking of sensitive content and blocking scenarios.
  * Backward-compatible ``scan`` contract consumed by the gateway guards.
"""

from __future__ import annotations

import pytest

from core.config import AgentShieldConfig
from core.dlp_engine import DLPDecision, DLPEngine
from core.pii_detector import PIIDetector
from core.schemas import (
    Action,
    DLPAnalysisResult,
    DetectionFinding,
    DetectorType,
    DLPViolationError,
    PIIType,
    SensitivityLevel,
)
from core.secret_scanner import SecretScanner


# ============================================================================
# Fixtures
# ============================================================================

# Real detectors are module-scoped so the heavy Presidio / spaCy NLP engine and
# the secret rules are only initialized once for the whole suite.
@pytest.fixture(scope="module")
def pii_detector() -> PIIDetector:
    return PIIDetector(AgentShieldConfig())


@pytest.fixture(scope="module")
def secret_scanner() -> SecretScanner:
    return SecretScanner(AgentShieldConfig())


@pytest.fixture
def dlp() -> DLPEngine:
    """DLP-only engine. Ceiling at CONFIDENTIAL so MASK is reachable for
    CONFIDENTIAL content while RESTRICTED still blocks."""
    config = AgentShieldConfig(dlp_max_allowed_sensitivity=SensitivityLevel.CONFIDENTIAL)
    return DLPEngine(config)


@pytest.fixture
def dlp_default_ceiling() -> DLPEngine:
    """DLP-only engine with the default ceiling (INTERNAL): CONFIDENTIAL and
    RESTRICTED content both block."""
    return DLPEngine(AgentShieldConfig())


@pytest.fixture
def dlp_pii(pii_detector: PIIDetector) -> DLPEngine:
    config = AgentShieldConfig(dlp_max_allowed_sensitivity=SensitivityLevel.CONFIDENTIAL)
    return DLPEngine(config=config, pii_detector=pii_detector)


@pytest.fixture
def dlp_secret(secret_scanner: SecretScanner) -> DLPEngine:
    config = AgentShieldConfig(dlp_max_allowed_sensitivity=SensitivityLevel.CONFIDENTIAL)
    return DLPEngine(config=config, secret_scanner=secret_scanner)


@pytest.fixture
def dlp_integrated(
    pii_detector: PIIDetector, secret_scanner: SecretScanner
) -> DLPEngine:
    config = AgentShieldConfig(dlp_max_allowed_sensitivity=SensitivityLevel.CONFIDENTIAL)
    return DLPEngine(
        config=config, pii_detector=pii_detector, secret_scanner=secret_scanner
    )


# ============================================================================
# 1. Data Classification — all four sensitivity tiers (DLP rules only)
# ============================================================================

def test_classify_public_benign_content(dlp: DLPEngine) -> None:
    text = "The quarterly weather summary is mostly sunny with light rain."
    assert dlp.classify(text) == SensitivityLevel.PUBLIC


def test_enforce_public_allows_unchanged_text(dlp: DLPEngine) -> None:
    text = "Please explain the difference between TCP and UDP protocols."
    decision = dlp.enforce(text)

    assert decision.sensitivity == SensitivityLevel.PUBLIC
    assert decision.action == Action.ALLOW
    assert not decision.violates_policy
    assert decision.findings == []
    assert decision.sanitized_text == text  # nothing to redact


def test_classify_internal_corporate_domain(dlp: DLPEngine) -> None:
    text = "Fetch the build logs from host.build-agent.internal over the VPN."
    assert dlp.classify(text) == SensitivityLevel.INTERNAL


def test_enforce_internal_warns_within_policy(dlp: DLPEngine) -> None:
    text = "Fetch the build logs from host.build-agent.internal over the VPN."
    decision = dlp.enforce(text)

    assert decision.sensitivity == SensitivityLevel.INTERNAL
    # Ceiling is CONFIDENTIAL, so INTERNAL does not violate policy -> WARN
    assert decision.action == Action.WARN
    assert not decision.violates_policy
    assert len(decision.findings) == 1
    assert decision.findings[0].detector == DetectorType.DLP
    assert decision.findings[0].rule_id == "DLP_INFRA_001"


def test_classify_confidential_iban(dlp: DLPEngine) -> None:
    text = "Settle the invoice to IBAN GB29NWBK60161331926819 by Friday."
    assert dlp.classify(text) == SensitivityLevel.CONFIDENTIAL


def test_enforce_confidential_masks_when_allowed(dlp: DLPEngine) -> None:
    text = "Settle the invoice to IBAN GB29NWBK60161331926819 by Friday."
    decision = dlp.enforce(text)

    assert decision.sensitivity == SensitivityLevel.CONFIDENTIAL
    # Ceiling CONFIDENTIAL: CONFIDENTIAL is permitted -> MASK (not BLOCK)
    assert decision.action == Action.MASK
    assert not decision.violates_policy
    assert len(decision.findings) == 1
    assert decision.findings[0].rule_id == "DLP_FIN_001"
    # Redaction applied
    assert "GB29NWBK60161331926819" not in decision.sanitized_text
    assert "[DLP_REDACTED_CONFIDENTIAL]" in decision.sanitized_text


def test_classify_restricted_db_connection_string(dlp: DLPEngine) -> None:
    text = "Connecting to postgres://master:SecretPass123!@finance.internal.corp:5432/payroll"
    assert dlp.classify(text) == SensitivityLevel.RESTRICTED


def test_enforce_restricted_blocks(dlp: DLPEngine) -> None:
    text = "Connecting to postgres://master:SecretPass123!@finance.internal.corp:5432/payroll"
    decision = dlp.enforce(text)

    assert decision.sensitivity == SensitivityLevel.RESTRICTED
    assert decision.violates_policy
    assert decision.action == Action.BLOCK
    assert len(decision.findings) == 1
    assert decision.findings[0].rule_id == "DLP_CONN_001"
    assert "SecretPass123!" not in decision.sanitized_text
    assert "[DLP_REDACTED_RESTRICTED]" in decision.sanitized_text


def test_classify_restricted_healthcare_mrn(dlp: DLPEngine) -> None:
    text = "Patient MRN: 12345678 was admitted overnight for observation."
    assert dlp.classify(text) == SensitivityLevel.RESTRICTED


# ============================================================================
# 2. Configurable ALLOW / WARN / MASK / BLOCK decisions
# ============================================================================

def test_default_action_mapping_covers_all_four_actions(dlp: DLPEngine) -> None:
    assert dlp.sensitivity_actions == {
        SensitivityLevel.PUBLIC: Action.ALLOW,
        SensitivityLevel.INTERNAL: Action.WARN,
        SensitivityLevel.CONFIDENTIAL: Action.MASK,
        SensitivityLevel.RESTRICTED: Action.BLOCK,
    }


def test_default_ceiling_blocks_confidential_and_restricted(
    dlp_default_ceiling: DLPEngine,
) -> None:
    iban = "Settle the invoice to IBAN GB29NWBK60161331926819 by Friday."
    decision = dlp_default_ceiling.enforce(iban)

    # Default ceiling is INTERNAL: CONFIDENTIAL exceeds it -> BLOCK
    assert decision.sensitivity == SensitivityLevel.CONFIDENTIAL
    assert decision.violates_policy
    assert decision.action == Action.BLOCK


def test_sensitivity_actions_override_forces_block_on_confidential() -> None:
    config = AgentShieldConfig(dlp_max_allowed_sensitivity=SensitivityLevel.CONFIDENTIAL)
    engine = DLPEngine(
        config=config,
        sensitivity_actions={
            SensitivityLevel.PUBLIC: Action.ALLOW,
            SensitivityLevel.INTERNAL: Action.ALLOW,
            SensitivityLevel.CONFIDENTIAL: Action.BLOCK,
            SensitivityLevel.RESTRICTED: Action.BLOCK,
        },
    )
    decision = engine.enforce("Settle the invoice to IBAN GB29NWBK60161331926819 by Friday.")

    # Within policy ceiling, but the configured action for CONFIDENTIAL is BLOCK
    assert not decision.violates_policy
    assert decision.sensitivity == SensitivityLevel.CONFIDENTIAL
    assert decision.action == Action.BLOCK


def test_set_sensitivity_action_changes_decision_at_runtime(dlp: DLPEngine) -> None:
    text = "Settle the invoice to IBAN GB29NWBK60161331926819 by Friday."

    # Initially CONFIDENTIAL -> MASK
    assert dlp.enforce(text).action == Action.MASK

    dlp.set_sensitivity_action(SensitivityLevel.CONFIDENTIAL, Action.BLOCK)
    assert dlp.enforce(text).action == Action.BLOCK


def test_set_max_allowed_sensitivity_relaxes_blocking(dlp_default_ceiling: DLPEngine) -> None:
    text = "Settle the invoice to IBAN GB29NWBK60161331926819 by Friday."

    # Default ceiling INTERNAL: CONFIDENTIAL blocks
    assert dlp_default_ceiling.enforce(text).action == Action.BLOCK

    # Raise the ceiling so CONFIDENTIAL is now permitted -> MASK
    dlp_default_ceiling.set_max_allowed_sensitivity(SensitivityLevel.CONFIDENTIAL)
    decision = dlp_default_ceiling.enforce(text)
    assert decision.action == Action.MASK
    assert not decision.violates_policy


def test_partial_sensitivity_actions_falls_back_to_block() -> None:
    config = AgentShieldConfig(dlp_max_allowed_sensitivity=SensitivityLevel.CONFIDENTIAL)
    # Only PUBLIC mapped; every other tier must fall back to BLOCK (fail-closed)
    engine = DLPEngine(
        config=config,
        sensitivity_actions={SensitivityLevel.PUBLIC: Action.ALLOW},
    )
    decision = engine.enforce("Fetch the build logs from host.build-agent.internal over the VPN.")

    assert decision.sensitivity == SensitivityLevel.INTERNAL
    assert not decision.violates_policy  # INTERNAL is within CONFIDENTIAL ceiling
    # Missing mapping for INTERNAL -> fail-closed BLOCK
    assert decision.action == Action.BLOCK


# ============================================================================
# 3. Standardized DetectionFinding objects across detectors
# ============================================================================

def test_dlp_findings_are_standardized(dlp: DLPEngine) -> None:
    decision = dlp.enforce("Connecting to postgres://u:p@db.internal.corp:5432/main")
    assert decision.findings
    finding = decision.findings[0]
    assert isinstance(finding, DetectionFinding)
    assert finding.detector == DetectorType.DLP
    assert finding.rule_id == "DLP_CONN_001"
    assert 0.0 <= finding.risk_score <= 1.0
    # Indexes coherent with the source text
    assert finding.start_index is not None and finding.end_index is not None


def test_pii_integration_emits_pii_finding(dlp_pii: DLPEngine) -> None:
    decision = dlp_pii.enforce("Please reach alice@example.com for the meeting notes.")

    assert decision.pii_count >= 1
    pii_findings = [f for f in decision.findings if f.detector == DetectorType.PII]
    assert pii_findings
    assert pii_findings[0].metadata.get("pii_type") == PIIType.EMAIL.value


def test_secret_integration_emits_secret_finding(dlp_secret: DLPEngine) -> None:
    decision = dlp_secret.enforce("Authenticate using AWS key AKIAIOSFODNN7EXAMPLE for the upload.")

    assert decision.secret_count >= 1
    secret_findings = [f for f in decision.findings if f.detector == DetectorType.SECRET]
    assert secret_findings


def test_integrated_findings_aggregate_multiple_detectors(dlp_integrated: DLPEngine) -> None:
    text = "Connecting to postgres://master:SecretPass123!@finance.internal.corp:5432/payroll"
    decision = dlp_integrated.enforce(text)

    detectors = {f.detector for f in decision.findings}
    # DLP flags the connection URI, the secret scanner flags the embedded credentials
    assert DetectorType.DLP in detectors
    assert DetectorType.SECRET in detectors
    assert len(decision.findings) >= 2


def test_decision_exposes_underlying_dlp_result(dlp: DLPEngine) -> None:
    decision = dlp.enforce("Settle the invoice to IBAN GB29NWBK60161331926819 by Friday.")
    assert isinstance(decision.dlp_result, DLPAnalysisResult)
    assert decision.dlp_result.highest_sensitivity == SensitivityLevel.CONFIDENTIAL


# ============================================================================
# 4. PII Detector integration — classification escalation
# ============================================================================

def test_pii_email_escalates_to_internal_warn(dlp_pii: DLPEngine) -> None:
    decision = dlp_pii.enforce("Please reach alice@example.com for the meeting notes.")

    assert decision.sensitivity == SensitivityLevel.INTERNAL
    assert decision.action == Action.WARN  # within CONFIDENTIAL ceiling
    assert "alice@example.com" not in decision.sanitized_text
    assert "[EMAIL_1]" in decision.sanitized_text


def test_pii_ssn_escalates_to_confidential_mask(dlp_pii: DLPEngine) -> None:
    decision = dlp_pii.enforce("SSN on file: 123-45-6789.")

    assert decision.sensitivity == SensitivityLevel.CONFIDENTIAL
    assert decision.action == Action.MASK
    assert "123-45-6789" not in decision.sanitized_text
    assert "[SSN_1]" in decision.sanitized_text


def test_pii_credit_card_escalates_to_confidential_mask(dlp_pii: DLPEngine) -> None:
    decision = dlp_pii.enforce("Payment card on account: 4111 1111 1111 1111.")

    assert decision.sensitivity == SensitivityLevel.CONFIDENTIAL
    assert decision.action == Action.MASK
    assert "4111 1111 1111 1111" not in decision.sanitized_text
    assert "XXXX-XXXX-XXXX-1111" in decision.sanitized_text


def test_pii_aadhaar_escalates_to_restricted_block(dlp_pii: DLPEngine) -> None:
    decision = dlp_pii.enforce("Applicant Aadhaar number is 2345 6789 0124.")

    assert decision.sensitivity == SensitivityLevel.RESTRICTED
    assert decision.action == Action.BLOCK
    assert "2345 6789 0124" not in decision.sanitized_text


def test_bulk_pii_escalates_to_confidential(dlp_pii: DLPEngine) -> None:
    # Five email addresses together cross the bulk-exfiltration threshold.
    text = (
        "Recipients: alice@example.com, bob@example.com, carol@example.com, "
        "dave@example.com, and eve@example.com."
    )
    decision = dlp_pii.enforce(text)

    assert decision.pii_count >= 5
    # Each email is INTERNAL; bulk PII escalates the tier to at least CONFIDENTIAL
    assert decision.sensitivity.value in (
        SensitivityLevel.CONFIDENTIAL.value,
        SensitivityLevel.RESTRICTED.value,
    )


# ============================================================================
# 5. Secret Scanner integration — credentials never leave the org
# ============================================================================

def test_secret_aws_key_escalates_to_restricted_block(dlp_secret: DLPEngine) -> None:
    decision = dlp_secret.enforce("Authenticate using AWS key AKIAIOSFODNN7EXAMPLE for the upload.")

    assert decision.sensitivity == SensitivityLevel.RESTRICTED
    assert decision.violates_policy
    assert decision.action == Action.BLOCK
    assert "AKIAIOSFODNN7EXAMPLE" not in decision.sanitized_text
    assert "[REDACTED_AWS_ACCESS_KEY]" in decision.sanitized_text


def test_secret_openai_key_blocks(dlp_secret: DLPEngine) -> None:
    text = "Call the model with key sk-proj-abcdef1234567890GHijkl123456."
    decision = dlp_secret.enforce(text)

    assert decision.sensitivity == SensitivityLevel.RESTRICTED
    assert decision.action == Action.BLOCK
    assert "sk-proj-abcdef1234567890GHijkl123456" not in decision.sanitized_text


def test_no_injection_means_pii_not_escalated(dlp: DLPEngine) -> None:
    """Without injected detectors the engine behaves as the legacy DLP
    classifier: PII is not detected, so an email stays PUBLIC/ALLOW."""
    decision = dlp.enforce("Please reach alice@example.com for the meeting notes.")

    assert decision.sensitivity == SensitivityLevel.PUBLIC
    assert decision.action == Action.ALLOW
    assert decision.pii_count == 0
    # Text is unchanged because no DLP rule matched and no PII detector ran
    assert "alice@example.com" in decision.sanitized_text


# ============================================================================
# 6. Redaction / masking guarantees (defense in depth)
# ============================================================================

def test_redaction_never_leaks_raw_secret(dlp_secret: DLPEngine) -> None:
    text = "password = 'UltraSecretP@ssw0rd!2026' and key AKIAIOSFODNN7EXAMPLE"
    decision = dlp_secret.enforce(text)

    assert decision.action == Action.BLOCK
    assert "UltraSecretP@ssw0rd!2026" not in decision.sanitized_text
    assert "AKIAIOSFODNN7EXAMPLE" not in decision.sanitized_text
    # Finding previews must not expose raw credentials either
    for finding in decision.findings:
        assert "UltraSecretP@ssw0rd!2026" not in (finding.match_preview or "")
        assert "AKIAIOSFODNN7EXAMPLE" not in (finding.match_preview or "")


def test_redaction_layers_pii_and_dlp(dlp_integrated: DLPEngine) -> None:
    text = "Email alice@example.com about the CONFIDENTIAL merger."
    decision = dlp_integrated.enforce(text)

    # PII (email -> INTERNAL) plus DLP marking (CONFIDENTIAL) -> highest CONFIDENTIAL
    assert decision.sensitivity == SensitivityLevel.CONFIDENTIAL
    assert "alice@example.com" not in decision.sanitized_text
    assert "[EMAIL_1]" in decision.sanitized_text
    assert "[DLP_REDACTED_CONFIDENTIAL]" in decision.sanitized_text


def test_redaction_blocks_db_credentials_in_integrated_mode(dlp_integrated: DLPEngine) -> None:
    text = "Connecting to postgres://master:SecretPass123!@finance.internal.corp:5432/payroll"
    decision = dlp_integrated.enforce(text)

    assert decision.action == Action.BLOCK
    assert "SecretPass123!" not in decision.sanitized_text


# ============================================================================
# 7. Blocking scenarios
# ============================================================================

def test_block_decision_when_exceeding_ceiling(dlp: DLPEngine) -> None:
    text = "Connecting to postgres://master:SecretPass123!@finance.internal.corp:5432/payroll"
    decision = dlp.enforce(text)

    assert decision.action == Action.BLOCK
    assert decision.violates_policy
    assert "BLOCK" in decision.reason


def test_raise_on_block_raises_dlp_violation_error(dlp: DLPEngine) -> None:
    text = "Connecting to postgres://master:SecretPass123!@finance.internal.corp:5432/payroll"
    with pytest.raises(DLPViolationError) as exc_info:
        dlp.enforce(text, raise_on_block=True)

    assert exc_info.value.action == Action.BLOCK
    assert exc_info.value.findings  # carries the standardized findings
    assert exc_info.value.risk_score >= 0.0


def test_raise_on_block_does_not_raise_when_allowed(dlp: DLPEngine) -> None:
    decision = dlp.enforce("The weather is sunny today.", raise_on_block=True)
    assert decision.action == Action.ALLOW


def test_empty_text_is_allowed_public() -> None:
    engine = DLPEngine(AgentShieldConfig())
    decision = engine.enforce("")

    assert decision.action == Action.ALLOW
    assert decision.sensitivity == SensitivityLevel.PUBLIC
    assert decision.findings == []
    assert decision.sanitized_text == ""


# ============================================================================
# 8. Backward-compatible scan() contract (consumed by the gateway guards)
# ============================================================================

def test_scan_returns_standardized_dlp_result(dlp: DLPEngine) -> None:
    text = "Connecting to postgres://master:SecretPass123!@finance.internal.corp:5432/payroll"
    result = dlp.scan(text)

    assert isinstance(result, DLPAnalysisResult)
    assert result.highest_sensitivity == SensitivityLevel.RESTRICTED
    assert result.violates_policy  # exceeds CONFIDENTIAL ceiling
    assert len(result.findings) == 1
    assert result.findings[0].detector == DetectorType.DLP
    assert "SecretPass123!" not in result.sanitized_text


def test_scan_public_content_has_no_findings(dlp: DLPEngine) -> None:
    result = dlp.scan("The weather is sunny today.")
    assert result.highest_sensitivity == SensitivityLevel.PUBLIC
    assert not result.violates_policy
    assert result.findings == []
    assert result.sanitized_text == "The weather is sunny today."


def test_scan_disabled_returns_public_unchanged() -> None:
    config = AgentShieldConfig(enable_dlp=False)
    engine = DLPEngine(config)
    text = "Connecting to postgres://master:SecretPass123!@finance.internal.corp:5432/payroll"

    result = engine.scan(text)
    assert result.highest_sensitivity == SensitivityLevel.PUBLIC
    assert not result.violates_policy
    assert result.findings == []
    # With DLP disabled, nothing is redacted
    assert result.sanitized_text == text


def test_scan_empty_string() -> None:
    result = DLPEngine(AgentShieldConfig()).scan("")
    assert result.highest_sensitivity == SensitivityLevel.PUBLIC
    assert result.sanitized_text == ""
    assert result.findings == []


def test_custom_keyword_detected_as_confidential() -> None:
    config = AgentShieldConfig(
        dlp_max_allowed_sensitivity=SensitivityLevel.CONFIDENTIAL,
        custom_dlp_keywords=["PROJECT_TITAN_SECRET"],
    )
    engine = DLPEngine(config)
    result = engine.scan("The PROJECT_TITAN_SECRET roadmap is on the shared drive.")

    assert result.highest_sensitivity == SensitivityLevel.CONFIDENTIAL
    assert any(f.rule_id == "DLP_KEYWORD_001" for f in result.findings)
    assert "PROJECT_TITAN_SECRET" not in result.sanitized_text


# ============================================================================
# 9. Asynchronous interfaces
# ============================================================================

@pytest.mark.anyio
async def test_scan_async_returns_dlp_result(dlp: DLPEngine) -> None:
    text = "Connecting to postgres://master:SecretPass123!@finance.internal.corp:5432/payroll"
    result = await dlp.scan_async(text)
    assert isinstance(result, DLPAnalysisResult)
    assert result.highest_sensitivity == SensitivityLevel.RESTRICTED


@pytest.mark.anyio
async def test_enforce_async_returns_decision(dlp_integrated: DLPEngine) -> None:
    text = "Authenticate using AWS key AKIAIOSFODNN7EXAMPLE for the upload."
    decision = await dlp_integrated.enforce_async(text)
    assert isinstance(decision, DLPDecision)
    assert decision.action == Action.BLOCK
    assert decision.secret_count >= 1
