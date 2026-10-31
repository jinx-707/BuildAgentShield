"""
Unit tests for AgentShield PII Detector & Redactor.
Tests Microsoft Presidio Analyzer and Anonymizer integration,
Indian PII patterns (Aadhaar, PAN), names, locations, credit cards,
SSNs, phones, emails, and all redaction modes (MASK, HASH, TOKEN, FULL_REDACT).
"""

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
import pytest

from core.config import AgentShieldConfig
from core.pii_detector import PIIDetector, validate_verhoeff
from core.schemas import DetectorType, PIIType, RedactionMode


@pytest.fixture
def pii_detector() -> PIIDetector:
    config = AgentShieldConfig(pii_redaction_mode=RedactionMode.MASK)
    return PIIDetector(config)


def test_email_detection_and_masking(pii_detector: PIIDetector) -> None:
    text = "Send customer statements to alice.smith@corp.example.com immediately."
    result = pii_detector.scan(text)

    assert result.has_pii
    assert result.pii_count == 1
    assert result.findings[0].detector == DetectorType.PII
    assert result.findings[0].metadata["pii_type"] == PIIType.EMAIL.value
    assert "alice.smith@corp.example.com" not in result.sanitized_text
    assert "[EMAIL_1]" in result.sanitized_text


def test_phone_number_detection(pii_detector: PIIDetector) -> None:
    text = "Contact support at +1 (555) 234-5678 for assistance."
    result = pii_detector.scan(text)

    assert result.has_pii
    assert any(f.metadata["pii_type"] == PIIType.PHONE_NUMBER.value for f in result.findings)
    assert "+1 (555) 234-5678" not in result.sanitized_text


def test_ssn_detection_valid_and_invalid(pii_detector: PIIDetector) -> None:
    # Valid SSN format
    valid_text = "Tax ID is 123-45-6789 on the file."
    result_valid = pii_detector.scan(valid_text)
    assert result_valid.has_pii
    assert any(f.metadata["pii_type"] == PIIType.SSN.value for f in result_valid.findings)
    assert "123-45-6789" not in result_valid.sanitized_text

    # Bogus SSN (000 prefix is invalid in US SSN format)
    bogus_text = "Tracking code 000-45-6789"
    result_bogus = pii_detector.scan(bogus_text)
    assert not any(f.metadata.get("pii_type") == PIIType.SSN.value for f in result_bogus.findings)


def test_credit_card_luhn_checksum(pii_detector: PIIDetector) -> None:
    # Valid Visa test number (passes Luhn)
    valid_card_text = "Payment card number: 4111 1111 1111 1111."
    result_valid = pii_detector.scan(valid_card_text)
    assert result_valid.has_pii
    assert any(f.metadata["pii_type"] == PIIType.CREDIT_CARD.value for f in result_valid.findings)
    assert "XXXX-XXXX-XXXX-1111" in result_valid.sanitized_text

    # Random 16 digits that fail Luhn
    invalid_card_text = "Serial number: 4532 0150 1234 5674"
    result_invalid = pii_detector.scan(invalid_card_text)
    assert not any(f.metadata.get("pii_type") == PIIType.CREDIT_CARD.value for f in result_invalid.findings)


def test_ipv4_and_ipv6_detection(pii_detector: PIIDetector) -> None:
    text = "Client connected from 192.168.1.100 and gateway 2001:0db8:85a3:0000:0000:8a2e:0370:7334."
    result = pii_detector.scan(text)
    assert result.has_pii
    ip_findings = [f for f in result.findings if f.metadata.get("pii_type") == PIIType.IP_ADDRESS.value]
    assert len(ip_findings) == 2


def test_multiple_pii_items_in_composite_string(pii_detector: PIIDetector) -> None:
    text = "User bob@example.com called from 555-890-1234 regarding card 4111-1111-1111-1111."
    result = pii_detector.scan(text)
    assert result.pii_count >= 3
    assert "bob@example.com" not in result.sanitized_text
    assert "555-890-1234" not in result.sanitized_text


def test_hash_and_token_redaction_modes() -> None:
    # Token mode
    config_token = AgentShieldConfig(pii_redaction_mode=RedactionMode.TOKEN)
    detector_token = PIIDetector(config_token)
    res_token = detector_token.scan("Email: test@example.com")
    assert "<PII:EMAIL:1>" in res_token.sanitized_text

    # Hash mode
    config_hash = AgentShieldConfig(pii_redaction_mode=RedactionMode.HASH)
    detector_hash = PIIDetector(config_hash)
    res_hash = detector_hash.scan("Email: test@example.com")
    assert "[EMAIL_HASH_" in res_hash.sanitized_text


def test_full_redact_mode() -> None:
    config_full = AgentShieldConfig(pii_redaction_mode=RedactionMode.FULL_REDACT)
    detector_full = PIIDetector(config_full)
    res_full = detector_full.scan("Contact me at user@testcorp.com immediately.")
    assert res_full.has_pii
    assert "user@testcorp.com" not in res_full.sanitized_text
    assert "[REDACTED]" in res_full.sanitized_text


def test_person_name_detection_and_redaction(pii_detector: PIIDetector) -> None:
    text = "Meeting scheduled between Alice Johnson and Dr. Robert Oppenheimer."
    result = pii_detector.scan(text)

    assert result.has_pii
    person_findings = [f for f in result.findings if f.metadata.get("pii_type") == PIIType.PERSON.value]
    assert len(person_findings) >= 1
    assert "Alice Johnson" not in result.sanitized_text or "Robert Oppenheimer" not in result.sanitized_text
    assert "[PERSON_" in result.sanitized_text


def test_location_and_address_detection(pii_detector: PIIDetector) -> None:
    # Street address and city
    text = "Please ship package to 742 Evergreen Terrace in Springfield."
    result = pii_detector.scan(text)

    assert result.has_pii
    loc_findings = [f for f in result.findings if f.metadata.get("pii_type") == PIIType.LOCATION.value]
    assert len(loc_findings) >= 1
    assert "742 Evergreen Terrace" not in result.sanitized_text or "Springfield" not in result.sanitized_text
    assert "[LOCATION_" in result.sanitized_text


def test_indian_aadhaar_detection_valid_and_checksum(pii_detector: PIIDetector) -> None:
    # 2345 6789 0124 is a mathematically valid Verhoeff 12-digit number
    assert validate_verhoeff("234567890124") is True
    valid_text = "Applicant Aadhaar number is 2345 6789 0124."
    result_valid = pii_detector.scan(valid_text)

    assert result_valid.has_pii
    aadhaar_findings = [f for f in result_valid.findings if f.metadata.get("pii_type") == PIIType.AADHAAR.value]
    assert len(aadhaar_findings) == 1
    assert "2345 6789 0124" not in result_valid.sanitized_text
    assert "[AADHAAR_1]" in result_valid.sanitized_text

    # Invalid checksum (ending with 9 fails Verhoeff)
    assert validate_verhoeff("234567890129") is False
    invalid_text = "Tracking ID 2345 6789 0129 was rejected."
    result_invalid = pii_detector.scan(invalid_text)
    assert not any(f.metadata.get("pii_type") == PIIType.AADHAAR.value for f in result_invalid.findings)


def test_indian_pan_detection_valid_and_invalid(pii_detector: PIIDetector) -> None:
    # Valid PAN: 4th char 'P' indicates individual taxpayer
    valid_text = "Permanent Account Number is ABCPK1234F for filing."
    result_valid = pii_detector.scan(valid_text)

    assert result_valid.has_pii
    pan_findings = [f for f in result_valid.findings if f.metadata.get("pii_type") == PIIType.PAN.value]
    assert len(pan_findings) == 1
    assert "ABCPK1234F" not in result_valid.sanitized_text
    assert "[PAN_1]" in result_valid.sanitized_text

    # Invalid PAN: 4th char 'Z' is not a valid legal status in Indian Income Tax
    invalid_text = "Invalid code ABCZK1234F"
    result_invalid = pii_detector.scan(invalid_text)
    assert not any(f.metadata.get("pii_type") == PIIType.PAN.value for f in result_invalid.findings)


def test_indian_pii_composite_string(pii_detector: PIIDetector) -> None:
    text = "Citizen Priya Sharma with PAN ABCPK1234F and Aadhaar 2345-6789-0124 contacted support@bank.in."
    result = pii_detector.scan(text)

    assert result.has_pii
    assert result.pii_count >= 3
    found_types = {f.metadata["pii_type"] for f in result.findings}
    assert PIIType.PAN.value in found_types
    assert PIIType.AADHAAR.value in found_types
    assert PIIType.EMAIL.value in found_types

    assert "ABCPK1234F" not in result.sanitized_text
    assert "2345-6789-0124" not in result.sanitized_text
    assert "support@bank.in" not in result.sanitized_text


def test_presidio_engine_direct_integration(pii_detector: PIIDetector) -> None:
    """Verifies that Presidio Analyzer and Anonymizer are authentically initialized."""
    assert isinstance(pii_detector.analyzer, AnalyzerEngine)
    assert isinstance(pii_detector.anonymizer, AnonymizerEngine)

    registered_names = {r.name for r in pii_detector.analyzer.registry.recognizers}
    assert "IndianAadhaarRecognizer" in registered_names
    assert "IndianPanRecognizer" in registered_names
    assert "StreetAddressRecognizer" in registered_names


@pytest.mark.anyio
async def test_async_pii_scan(pii_detector: PIIDetector) -> None:
    text = "Customer email is lead@domain.com."
    result = await pii_detector.scan_async(text)
    assert result.has_pii
    assert "[EMAIL_1]" in result.sanitized_text
