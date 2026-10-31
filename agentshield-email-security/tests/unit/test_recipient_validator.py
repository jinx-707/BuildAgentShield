"""Unit tests for RecipientValidator."""

from app.schemas.email import EmailAddress
from app.security.recipient_validator import RecipientValidator


def test_valid_standard_recipient():
    validator = RecipientValidator(trusted_domains=["mycompany.com"])
    recipients = [EmailAddress(email="colleague@mycompany.com", name="Colleague")]
    result = validator.validate_recipients(recipients)

    assert result.is_valid is True
    assert result.risk_level == "LOW"
    assert result.is_external is False
    assert len(result.invalid_recipients) == 0


def test_external_recipient_categorization():
    validator = RecipientValidator(trusted_domains=["mycompany.com"])
    recipients = [EmailAddress(email="client@external-partner.com", name="Client")]
    result = validator.validate_recipients(recipients)

    assert result.is_valid is True
    assert result.is_external is True
    assert result.risk_level == "MEDIUM"
    assert "client@external-partner.com" in result.external_recipients


def test_reject_crlf_injection():
    validator = RecipientValidator()
    valid, reason = validator.validate_address("user@example.com\r\nBcc: evil@attacker.com")
    assert valid is False
    assert "CRLF" in reason or "control characters" in reason


def test_reject_disposable_email_domain():
    validator = RecipientValidator()
    recipients = [EmailAddress(email="bot@mailinator.com")]
    result = validator.validate_recipients(recipients)

    assert result.is_valid is False
    assert "bot@mailinator.com" in result.invalid_recipients
    assert result.risk_level == "CRITICAL"


def test_reject_punycode_homograph_attack():
    validator = RecipientValidator()
    # punycode simulation
    valid, reason = validator.validate_address("admin@xn--microsft-96a.com")
    assert valid is False
    assert "homograph" in reason or "punycode" in reason


def test_empty_recipients_list_rejected():
    validator = RecipientValidator()
    result = validator.validate_recipients([])
    assert result.is_valid is False
    assert "cannot be empty" in result.reasons[0]

