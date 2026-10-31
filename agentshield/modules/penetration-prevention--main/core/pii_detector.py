"""
AgentShield Personally Identifiable Information (PII) Detector & Redactor.
Powered by Microsoft Presidio Analyzer and Anonymizer engines with extended
support for global and Indian identity documents (Aadhaar, PAN), names,
physical addresses, credit cards, phones, emails, and government IDs.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import ipaddress
import re
from typing import Any

from presidio_analyzer import (
    AnalyzerEngine,
    EntityRecognizer,
    Pattern,
    PatternRecognizer,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import EmailRecognizer, UsSsnRecognizer
import tldextract
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import (
    OperatorConfig,
    RecognizerResult as AnonRecognizerResult,
)

from core.config import AgentShieldConfig, setup_logger
from core.schemas import (
    DetectionFinding,
    DetectorType,
    PIIAnalysisResult,
    PIIType,
    RedactionMode,
)

logger = setup_logger("agentshield.pii")


# ============================================================================
# Checksum Algorithms & Helpers
# ============================================================================

# Verhoeff algorithm multiplication and permutation matrices
VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def validate_verhoeff(number_str: str) -> bool:
    """
    Validates a number string using the Verhoeff dihedral group algorithm.
    Used for Indian Aadhaar 12th digit checksum verification.
    """
    c = 0
    for i, digit in enumerate(reversed(number_str)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(digit)]]
    return c == 0


def luhn_checksum_valid(number_str: str) -> bool:
    """
    Validates a credit card number using Luhn's Mod 10 algorithm.
    Rejects false-positive matches (such as random serial numbers).
    """
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, digit in enumerate(digits[:-1]):
        if i % 2 == parity:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit

    return (checksum + digits[-1]) % 10 == 0


def is_valid_ip(ip_str: str) -> bool:
    """Validates real IPv4 or IPv6 address string."""
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


# ============================================================================
# Custom Presidio Recognizers
# ============================================================================

class AadhaarRecognizer(PatternRecognizer):
    """
    Microsoft Presidio Recognizer for Indian Aadhaar numbers.
    Matches 12-digit UID numbers with space, hyphen, or dense formats,
    enforcing leading digit constraints and Verhoeff checksum verification.
    """

    def __init__(self) -> None:
        patterns = [
            Pattern(
                name="aadhaar_spaced",
                regex=r"\b[2-9][0-9]{3}\s[0-9]{4}\s[0-9]{4}\b",
                score=0.85,
            ),
            Pattern(
                name="aadhaar_hyphen",
                regex=r"\b[2-9][0-9]{3}-[0-9]{4}-[0-9]{4}\b",
                score=0.85,
            ),
            Pattern(
                name="aadhaar_dense",
                regex=r"\b[2-9][0-9]{11}\b",
                score=0.75,
            ),
        ]
        context = [
            "aadhaar",
            "aadhar",
            "uidai",
            "uid",
            "identity",
            "citizen",
            "gov",
        ]
        super().__init__(
            supported_entity="IN_AADHAAR",
            patterns=patterns,
            context=context,
            name="IndianAadhaarRecognizer",
        )

    def validate_result(self, pattern_text: str) -> bool:
        clean = re.sub(r"[\s-]", "", pattern_text)
        if len(clean) != 12 or not clean.isdigit():
            return False
        if clean[0] in ("0", "1"):
            return False
        return validate_verhoeff(clean)


class PanRecognizer(PatternRecognizer):
    """
    Microsoft Presidio Recognizer for Indian Permanent Account Numbers (PAN).
    Validates the 10-character alphanumeric structure `[A-Z]{5}[0-9]{4}[A-Z]`
    where the 4th character denotes taxpayer legal status.
    """

    VALID_4TH_CHARS = frozenset("PCHFATBLJGpchfatbljg")

    def __init__(self) -> None:
        patterns = [
            Pattern(
                name="pan_standard",
                regex=r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]\b",
                score=0.85,
            )
        ]
        context = [
            "pan",
            "pan card",
            "pan number",
            "permanent account number",
            "income tax",
            "tax id",
            "taxpayer",
        ]
        super().__init__(
            supported_entity="IN_PAN",
            patterns=patterns,
            context=context,
            name="IndianPanRecognizer",
        )

    def validate_result(self, pattern_text: str) -> bool:
        clean = pattern_text.strip()
        if len(clean) != 10:
            return False
        return clean[3] in self.VALID_4TH_CHARS


class RobustSsnRecognizer(UsSsnRecognizer):
    """
    Enhanced US SSN Recognizer with format validation.
    Avoids Presidio's default blanket invalidation of canonical example strings
    while strictly disallowing invalid SSN area codes (000, 666, 9xx)
    and invalid zeros (00 group, 0000 group).
    """

    def invalidate_result(self, pattern_text: str) -> bool:
        digits = "".join(c for c in pattern_text if c.isdigit())
        if len(digits) != 9:
            return True
        if digits[:3] in ("000", "666") or digits[0] == "9":
            return True
        if digits[3:5] == "00" or digits[5:] == "0000":
            return True
        return False


class RobustEmailRecognizer(EmailRecognizer):
    """
    Enhanced EmailRecognizer that ensures robust detection for global and
    country-code TLDs (including multi-part SLDs like bank.in or co.uk)
    and prevents dropped findings when followed by punctuation.
    """

    def validate_result(self, pattern_text: str) -> bool:
        res = tldextract.extract(pattern_text)
        if res.fqdn != "":
            return True
        parts = pattern_text.split("@")
        if len(parts) == 2 and "." in parts[1]:
            domain = parts[1].strip(".,;:!? ")
            return len(domain) >= 3 and "." in domain
        return False


class StreetAddressRecognizer(PatternRecognizer):
    """
    Presidio Recognizer for physical street addresses and locations.
    Detects house/building numbers paired with standard street suffixes.
    """

    def __init__(self) -> None:
        patterns = [
            Pattern(
                name="street_address",
                regex=r"\b\d{1,5}\s+[A-Za-z0-9\s.,]{2,35}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Circle|Cir|Terrace|Ter)\b",
                score=0.75,
            )
        ]
        context = [
            "address",
            "street",
            "lives at",
            "located",
            "residence",
            "ship to",
            "delivered to",
            "office",
        ]
        super().__init__(
            supported_entity="LOCATION",
            patterns=patterns,
            context=context,
            name="StreetAddressRecognizer",
        )


# ============================================================================
# PIIDetector Engine
# ============================================================================

class PIIDetector:
    """
    Unified PII detection and redaction engine powered by Microsoft Presidio.
    Detects:
      - Emails
      - Phone numbers (international and local)
      - Names (PERSON)
      - Physical addresses and locations (LOCATION)
      - Credit cards (with Luhn validation)
      - Government identifiers: US SSN, US Passport, Indian Aadhaar, Indian PAN
      - IP addresses (IPv4 & IPv6)
    Supports MASK, HASH, TOKEN, and FULL_REDACT redaction modes via Presidio Anonymizer.
    """

    # Mapping from Presidio entity types to AgentShield PIIType and rule ID
    ENTITY_MAPPING: dict[str, tuple[PIIType, str]] = {
        "EMAIL_ADDRESS": (PIIType.EMAIL, "PII_EMAIL_001"),
        "EMAIL": (PIIType.EMAIL, "PII_EMAIL_001"),
        "PHONE_NUMBER": (PIIType.PHONE_NUMBER, "PII_PHONE_001"),
        "PERSON": (PIIType.PERSON, "PII_PERSON_001"),
        "LOCATION": (PIIType.LOCATION, "PII_LOCATION_001"),
        "CREDIT_CARD": (PIIType.CREDIT_CARD, "PII_CARD_001"),
        "US_SSN": (PIIType.SSN, "PII_SSN_001"),
        "US_PASSPORT": (PIIType.US_PASSPORT, "PII_PASSPORT_001"),
        "IP_ADDRESS": (PIIType.IP_ADDRESS, "PII_IP_001"),
        "IN_AADHAAR": (PIIType.AADHAAR, "PII_AADHAAR_001"),
        "IN_PAN": (PIIType.PAN, "PII_PAN_001"),
        "US_DRIVER_LICENSE": (PIIType.DRIVER_LICENSE, "PII_LICENSE_001"),
    }

    # Common non-person nouns that might get misidentified by capitalized sentence starts
    DISALLOWED_PERSON_WORDS = frozenset({
        "email",
        "phone",
        "ssn",
        "pan",
        "aadhaar",
        "serial",
        "card",
        "tax",
        "user",
        "admin",
        "support",
        "client",
        "customer",
        "account",
        "payment",
    })

    def __init__(self, config: AgentShieldConfig | None = None) -> None:
        self.config = config or AgentShieldConfig()
        self._init_presidio()

    def _init_presidio(self) -> None:
        """Configures Microsoft Presidio Analyzer and Anonymizer engines."""
        # 1. Initialize NLP engine provider with spaCy en_core_web_sm
        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()

        # 2. Build AnalyzerEngine with registered recognizers
        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

        # Replace default UsSsnRecognizer and EmailRecognizer with robust versions
        self.analyzer.registry.recognizers = [
            r
            for r in self.analyzer.registry.recognizers
            if not (
                isinstance(r, (UsSsnRecognizer, EmailRecognizer))
                or "US_SSN" in r.supported_entities
                or "EMAIL_ADDRESS" in r.supported_entities
            )
        ]
        self.analyzer.registry.add_recognizer(RobustSsnRecognizer())
        self.analyzer.registry.add_recognizer(RobustEmailRecognizer())

        # Register custom Indian PII & street address recognizers
        self.analyzer.registry.add_recognizer(AadhaarRecognizer())
        self.analyzer.registry.add_recognizer(PanRecognizer())
        self.analyzer.registry.add_recognizer(StreetAddressRecognizer())

        # 3. Build Presidio AnonymizerEngine
        self.anonymizer = AnonymizerEngine()
        logger.info("Presidio Analyzer & Anonymizer initialized successfully.")

    @staticmethod
    def luhn_checksum_valid(number_str: str) -> bool:
        """Validates credit card checksum using Luhn's algorithm."""
        return luhn_checksum_valid(number_str)

    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """Validates IPv4 or IPv6 string."""
        return is_valid_ip(ip_str)

    @staticmethod
    def validate_verhoeff(num_str: str) -> bool:
        """Validates Verhoeff checksum algorithm for Aadhaar."""
        return validate_verhoeff(num_str)

    def _resolve_overlapping_matches(
        self, matches: list[RecognizerResult], text: str
    ) -> list[RecognizerResult]:
        """
        Deduplicates overlapping Presidio matches.
        Prioritizes specific domain entities (Aadhaar, Credit Card, PAN, Email, Phone, SSN)
        over generic or partial matches (Location, Person, DateTime).
        """
        # Specificity weight for priority resolution
        priority_map = {
            "IN_AADHAAR": 100,
            "IN_PAN": 95,
            "CREDIT_CARD": 90,
            "IP_ADDRESS": 85,
            "EMAIL_ADDRESS": 80,
            "EMAIL": 80,
            "US_SSN": 75,
            "PHONE_NUMBER": 70,
            "US_PASSPORT": 65,
            "LOCATION": 50,
            "PERSON": 45,
        }

        # Filter out false positive PERSON, PHONE, and URI-embedded email matches
        cleaned_matches: list[RecognizerResult] = []
        for m in matches:
            matched_text = text[m.start : m.end].strip()
            if m.entity_type == "PERSON" and matched_text.lower() in self.DISALLOWED_PERSON_WORDS:
                continue
            if m.entity_type == "PHONE_NUMBER" and is_valid_ip(matched_text):
                continue
            # Ignore false-positive emails inside URI credentials (e.g. postgres://user:pass@host)
            if m.entity_type in ("EMAIL_ADDRESS", "EMAIL"):
                prefix = text[max(0, m.start - 60) : m.start]
                if "://" in prefix and " " not in prefix.split("://")[-1]:
                    continue
            cleaned_matches.append(m)

        # Sort matches primarily by start index, then priority desc, score desc, length desc
        sorted_matches = sorted(
            cleaned_matches,
            key=lambda m: (
                m.start,
                -priority_map.get(m.entity_type, 10),
                -m.score,
                -(m.end - m.start),
            ),
        )

        resolved: list[RecognizerResult] = []
        last_end = -1
        for m in sorted_matches:
            if m.start >= last_end:
                resolved.append(m)
                last_end = m.end
            else:
                # Overlap detected: compare with existing previous match
                prev = resolved[-1]
                prev_prio = priority_map.get(prev.entity_type, 10)
                curr_prio = priority_map.get(m.entity_type, 10)

                if curr_prio > prev_prio or (curr_prio == prev_prio and m.score > prev.score):
                    resolved[-1] = m
                    last_end = m.end

        return resolved

    def scan(self, text: str) -> PIIAnalysisResult:
        """
        Synchronously scans text using Presidio Analyzer, redacts findings
        using Presidio Anonymizer according to the configured mode, and returns
        standardized AgentShield findings.
        """
        if not text or not self.config.enable_pii_detection:
            return PIIAnalysisResult(has_pii=False, pii_count=0, sanitized_text=text)

        # Target entities for Presidio Analyzer
        target_entities = list(self.ENTITY_MAPPING.keys())

        # 1. Run Presidio Analyzer
        raw_results = self.analyzer.analyze(
            text=text,
            entities=target_entities,
            language="en",
        )

        # 2. Resolve overlaps and filter matches
        filtered_results = self._resolve_overlapping_matches(raw_results, text)

        if not filtered_results:
            return PIIAnalysisResult(
                has_pii=False,
                pii_count=0,
                findings=[],
                sanitized_text=text,
                replacement_map={},
            )

        # 3. Formulate redactions and operator configurations for Presidio Anonymizer
        findings: list[DetectionFinding] = []
        replacement_map: dict[str, str] = {}
        redaction_mode = self.config.pii_redaction_mode

        anon_results: list[AnonRecognizerResult] = []
        operators: dict[str, OperatorConfig] = {}

        # Counter per PII type for readable numbering (e.g., EMAIL_1, PERSON_1)
        type_counters: dict[str, int] = defaultdict(int)

        for idx, match in enumerate(filtered_results, start=1):
            val = text[match.start : match.end]
            pii_type, rule_id = self.ENTITY_MAPPING.get(
                match.entity_type, (PIIType.EMAIL, "PII_GENERIC_001")
            )
            type_counters[pii_type.value] += 1
            item_idx = type_counters[pii_type.value]

            # Generate redaction replacement according to mode
            if redaction_mode == RedactionMode.MASK:
                if pii_type == PIIType.CREDIT_CARD:
                    clean_digits = re.sub(r"[ -]", "", val)
                    replacement = f"XXXX-XXXX-XXXX-{clean_digits[-4:]}"
                else:
                    replacement = f"[{pii_type.value.upper()}_{item_idx}]"
            elif redaction_mode == RedactionMode.HASH:
                hash_digest = hashlib.sha256(val.encode()).hexdigest()[:8]
                replacement = f"[{pii_type.value.upper()}_HASH_{hash_digest}]"
            elif redaction_mode == RedactionMode.TOKEN:
                replacement = f"<PII:{pii_type.value.upper()}:{item_idx}>"
            else:  # FULL_REDACT
                replacement = "[REDACTED]"

            replacement_map[val] = replacement

            # Distinct operator key for Presidio Anonymizer
            anon_entity_key = f"{match.entity_type}_{idx}"
            anon_results.append(
                AnonRecognizerResult(
                    entity_type=anon_entity_key,
                    start=match.start,
                    end=match.end,
                    score=match.score,
                )
            )
            operators[anon_entity_key] = OperatorConfig(
                "replace", {"new_value": replacement}
            )

            findings.append(
                DetectionFinding(
                    detector=DetectorType.PII,
                    rule_id=rule_id,
                    description=f"Identified {pii_type.value} sensitive data",
                    risk_score=round(float(match.score), 2),
                    start_index=match.start,
                    end_index=match.end,
                    redacted_value=replacement,
                    match_preview=replacement,
                    metadata={
                        "pii_type": pii_type.value,
                        "presidio_entity": match.entity_type,
                        "presidio_score": round(float(match.score), 2),
                    },
                )
            )

        # 4. Execute Presidio Anonymizer
        anonymized_engine_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=anon_results,
            operators=operators,
        )
        sanitized_text = anonymized_engine_result.text

        logger.debug(
            "Presidio PII scan completed. Identified %d items across %d entities.",
            len(findings),
            len(type_counters),
        )

        return PIIAnalysisResult(
            has_pii=len(findings) > 0,
            pii_count=len(findings),
            findings=findings,
            sanitized_text=sanitized_text,
            replacement_map=replacement_map,
        )

    async def scan_async(self, text: str) -> PIIAnalysisResult:
        """
        Asynchronous non-blocking invocation.
        Delegates to ``scan`` via ``asyncio.to_thread`` so the Presidio NLP
        pipeline does not block the event loop during inference.
        """
        import asyncio as _asyncio
        return await _asyncio.to_thread(self.scan, text)
