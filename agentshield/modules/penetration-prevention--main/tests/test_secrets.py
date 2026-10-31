"""
Comprehensive Unit Tests for AgentShield Secret & Credential Scanner.
Covers AWS, OpenAI, GitHub, Slack, Private Keys, JWTs, Database Credentials,
Passwords, Bearer Tokens, Shannon Entropy, and Safe Masking.
"""

from __future__ import annotations

import re
import pytest

from core.config import AgentShieldConfig
from core.schemas import DetectorType, SecretType
from core.secret_scanner import SecretRule, SecretScanner


@pytest.fixture
def scanner() -> SecretScanner:
    config = AgentShieldConfig()
    return SecretScanner(config)


# ============================================================================
# 1. Cloud Provider Credentials (AWS)
# ============================================================================

def test_aws_access_key_detection(scanner: SecretScanner) -> None:
    text = "Deploying with credentials AWS_KEY=AKIAIOSFODNN7EXAMPLE for S3 sync."
    result = scanner.scan(text)

    assert result.has_secrets
    assert result.secret_count == 1
    assert result.findings[0].metadata["secret_type"] == SecretType.AWS_ACCESS_KEY.value
    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_text
    assert "[REDACTED_AWS_ACCESS_KEY]" in result.sanitized_text
    # Ensure safe preview never outputs full secret
    assert result.findings[0].match_preview == "AKIA****MPLE"


def test_aws_temporary_sts_key(scanner: SecretScanner) -> None:
    text = "STS session credentials: ASIAIOSFODNN7EXAMPLE12"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.AWS_ACCESS_KEY.value for f in result.findings)


def test_aws_secret_access_key(scanner: SecretScanner) -> None:
    text = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.AWS_SECRET_KEY.value for f in result.findings)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in result.sanitized_text


# ============================================================================
# 2. OpenAI API Keys
# ============================================================================

def test_openai_api_key_detection(scanner: SecretScanner) -> None:
    text = "Use this key sk-proj-abc123xyz4567890abcdef123456 to query the model."
    result = scanner.scan(text)

    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.OPENAI_API_KEY.value for f in result.findings)
    assert "sk-proj-abc123xyz4567890abcdef123456" not in result.sanitized_text
    assert "[REDACTED_OPENAI_API_KEY]" in result.sanitized_text
    assert "sk-proj****3456" in result.findings[0].match_preview


# ============================================================================
# 3. GitHub Tokens (Classic, Fine-grained, OAuth)
# ============================================================================

def test_github_pat_detection(scanner: SecretScanner) -> None:
    text = "Cloning repo using token ghp_1234567890abcdefghijklmnopqrstuvwxyz from GitHub."
    result = scanner.scan(text)

    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.GITHUB_PAT.value for f in result.findings)
    assert "[REDACTED_GITHUB_PAT]" in result.sanitized_text
    assert "ghp_****wxyz" in result.findings[0].match_preview


def test_github_fine_grained_pat(scanner: SecretScanner) -> None:
    pat = "github_pat_11AABCDEF0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    text = f"Token: {pat}"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.GITHUB_PAT.value for f in result.findings)
    assert pat not in result.sanitized_text


def test_github_oauth_token(scanner: SecretScanner) -> None:
    text = "GitHub OAuth token: gho_1234567890abcdefghijklmnopqrstuvwxyz"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.GITHUB_PAT.value for f in result.findings)


# ============================================================================
# 4. Slack Credentials
# ============================================================================

def test_slack_token_detection(scanner: SecretScanner) -> None:
    token = "xoxb-" + "123456789012" + "-" + "1234567890123" + "-" + "abcdefghijklmnopqrstuvwx"
    text = f"Posting alert via {token} webhook."
    result = scanner.scan(text)

    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.SLACK_TOKEN.value for f in result.findings)
    assert token not in result.sanitized_text


def test_slack_webhook_url(scanner: SecretScanner) -> None:
    url = (
        "https://hooks.slack.com/services/"
        + "T00000000"
        + "/"
        + "B00000000"
        + "/"
        + "XXXXXXXXXXXXXXXXXXXXXXXX"
    )
    text = f"Webhook endpoint: {url}"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.SLACK_TOKEN.value for f in result.findings)
    assert url not in result.sanitized_text


# ============================================================================
# 5. Cryptographic Private Keys
# ============================================================================

def test_private_key_block_detection(scanner: SecretScanner) -> None:
    key_block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA04rQ3X1Z7Bv8...test...key...data...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    result = scanner.scan(f"Server configuration:\n{key_block}")

    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.SSH_PRIVATE_KEY.value for f in result.findings)
    assert "[REDACTED_SSH_PRIVATE_KEY]" in result.sanitized_text
    assert result.findings[0].match_preview == "-----BEGIN PRIVATE KEY----- [MASKED]"


def test_pgp_private_key_block(scanner: SecretScanner) -> None:
    pgp_key = (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
        "lQO+BF2X...test...pgp...data...\n"
        "-----END PGP PRIVATE KEY BLOCK-----"
    )
    result = scanner.scan(f"PGP backup:\n{pgp_key}")
    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.SSH_PRIVATE_KEY.value for f in result.findings)


# ============================================================================
# 6. JSON Web Tokens (JWT)
# ============================================================================

def test_jwt_token_detection(scanner: SecretScanner) -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    text = f"Bearer token header: {jwt}"
    result = scanner.scan(text)

    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.JWT_TOKEN.value for f in result.findings)
    assert jwt not in result.sanitized_text
    assert "eyJ****[MASKED_JWT]" in result.findings[0].match_preview


# ============================================================================
# 7. Database Credentials & Connection URIs
# ============================================================================

def test_database_connection_credentials(scanner: SecretScanner) -> None:
    db_uri = "postgres://dbadmin:SuperSecretPassword123!@db.internal.corp:5432/production"
    text = f"Connecting to database: {db_uri}"
    result = scanner.scan(text)

    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.DATABASE_CREDENTIALS.value for f in result.findings)
    assert "SuperSecretPassword123!" not in result.sanitized_text
    assert "[REDACTED_DATABASE_CREDENTIALS]" in result.sanitized_text
    # Passwords should have ZERO characters revealed
    db_finding = next(f for f in result.findings if f.metadata["secret_type"] == SecretType.DATABASE_CREDENTIALS.value)
    assert db_finding.match_preview == "********"


# ============================================================================
# 8. Plaintext Passwords
# ============================================================================

def test_password_assignment_detection(scanner: SecretScanner) -> None:
    text = 'Setting config: db_password = "UltraComplexP@ssw0rd!2026"'
    result = scanner.scan(text)

    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.PASSWORD.value for f in result.findings)
    assert "UltraComplexP@ssw0rd!2026" not in result.sanitized_text
    assert "[REDACTED_PASSWORD]" in result.sanitized_text
    # Password preview must be strictly masked
    pwd_finding = next(f for f in result.findings if f.metadata["secret_type"] == SecretType.PASSWORD.value)
    assert pwd_finding.match_preview == "********"


# ============================================================================
# 9. Bearer & Access Tokens
# ============================================================================

def test_bearer_token_detection(scanner: SecretScanner) -> None:
    text = "Authorization: Bearer ya29.a0AfH6SMAexampleTokenValue123456789"
    result = scanner.scan(text)

    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.BEARER_TOKEN.value for f in result.findings)
    assert "ya29.a0AfH6SMAexampleTokenValue123456789" not in result.sanitized_text
    assert "[REDACTED_BEARER_TOKEN]" in result.sanitized_text


# ============================================================================
# 10. Shannon Entropy Analysis
# ============================================================================

def test_shannon_entropy_calculation(scanner: SecretScanner) -> None:
    # Natural repetitive string has low entropy
    low_entropy = "aaaaaaaaabbbbbbbbccccccccc"
    h_low = scanner.calculate_shannon_entropy(low_entropy)
    assert h_low < 2.0

    # Cryptographically random base64 string has high entropy
    high_entropy = "q8R+3xL9vK2/mP1zT0oB7nU4="
    h_high = scanner.calculate_shannon_entropy(high_entropy)
    assert h_high > 4.0


def test_high_entropy_standalone_string_detection(scanner: SecretScanner) -> None:
    random_token = "4fA8bK9mP2xR7vL0wQ5yT1zN8sD3jG6h"
    text = f"Random session string: {random_token}"
    result = scanner.scan(text)

    assert result.has_secrets
    assert any(f.metadata["secret_type"] == SecretType.HIGH_ENTROPY.value for f in result.findings)
    assert random_token not in result.sanitized_text


# ============================================================================
# 11. Safe Redaction & Zero Secret Exposure
# ============================================================================

def test_safe_redaction_does_not_expose_raw_secrets(scanner: SecretScanner) -> None:
    secrets_text = (
        "Credentials:\n"
        "password = 'ConfidentialUserSecret123!'\n"
        "AKIAIOSFODNN7EXAMPLE\n"
        "sk-proj-9999888877776666555544443333\n"
    )
    result = scanner.scan(secrets_text)

    # Verify no raw secrets survive in sanitized text
    assert "ConfidentialUserSecret123!" not in result.sanitized_text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_text
    assert "sk-proj-9999888877776666555544443333" not in result.sanitized_text

    # Verify finding previews don't expose full passwords
    for f in result.findings:
        assert "ConfidentialUserSecret123!" not in (f.match_preview or "")


# ============================================================================
# 12. Configurable Secret Rules API
# ============================================================================

def test_add_custom_secret_rule(scanner: SecretScanner) -> None:
    custom_rule = SecretRule(
        rule_id="CUSTOM_SEC_001",
        pattern=re.compile(r"\b(CORP_INTERNAL_SECRET_[0-9A-F]{16})\b"),
        secret_type=SecretType.GENERIC_SECRET,
        risk_weight=0.99,
        description="Internal corporate master secret format",
        extract_group=1,
    )
    scanner.add_rule(custom_rule)

    text = "Key: CORP_INTERNAL_SECRET_0123456789ABCDEF"
    result = scanner.scan(text)
    assert result.has_secrets
    assert any(f.rule_id == "CUSTOM_SEC_001" for f in result.findings)
    assert "CORP_INTERNAL_SECRET_0123456789ABCDEF" not in result.sanitized_text


def test_disable_and_enable_secret_rule(scanner: SecretScanner) -> None:
    text = "AWS Key: AKIAIOSFODNN7EXAMPLE"
    assert scanner.scan(text).has_secrets

    # Disable AWS rule
    scanner.disable_rule("SEC_AWS_001")
    assert not any(f.rule_id == "SEC_AWS_001" for f in scanner.scan(text).findings)

    # Re-enable rule
    scanner.enable_rule("SEC_AWS_001")
    assert any(f.rule_id == "SEC_AWS_001" for f in scanner.scan(text).findings)


def test_dynamic_entropy_threshold_configuration(scanner: SecretScanner) -> None:
    scanner.set_entropy_threshold(5.5)
    assert scanner.config.secret_entropy_threshold == 5.5

    with pytest.raises(ValueError):
        scanner.set_entropy_threshold(10.0)


# ============================================================================
# 13. Asynchronous Interface
# ============================================================================

@pytest.mark.anyio
async def test_async_secret_scan(scanner: SecretScanner) -> None:
    text = "API key: sk-abcdef123456789012345678"
    result = await scanner.scan_async(text)
    assert result.has_secrets
    assert result.findings[0].detector == DetectorType.SECRET
