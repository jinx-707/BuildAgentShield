"""Development mock implementation of InspectionClient.

WARNING:
This mock is for local development and test suites ONLY.
It DOES NOT provide real security enforcement and must NEVER be used in production.
"""

import logging
import re
from typing import Union
from app.integrations.inspection_client import BaseInspectionClient
from app.schemas.email import EmailDraftRequest, EmailMessage, EmailSendRequest
from app.schemas.security import InspectionOutcome, InspectionResult

logger = logging.getLogger("agentshield.mocks.inspector")


class MockInspectionClient(BaseInspectionClient):
    """Development mock inspection client with heuristic patterns for test suites."""

    IS_DEVELOPMENT_MOCK: bool = True

    def __init__(self):
        logger.warning(
            "*** SECURITY WARNING: MockInspectionClient ACTIVE. THIS IS A TEST MOCK ONLY. ***"
        )
        self.injection_pattern = re.compile(
            r"(ignore\s+(all\s+)?previous\s+instructions|system\s+prompt\s+override|developer\s+mode\s+enabled|"
            r"forward\s+all\s+(confidential|sensitive)\s+documents|reveal\s+(the\s+)?(user'?s?\s+)?api\s+key|"
            r"send\s+every\s+email\s+in\s+this\s+mailbox|ignore\s+agentshield)",
            re.IGNORECASE,
        )
        self.credit_card_pattern = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
        self.ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
        self.api_key_pattern = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,})\b")
        self.phish_pattern = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    async def inspect_incoming_email(self, email: EmailMessage) -> InspectionResult:
        content = f"{email.subject} {email.snippet} {email.body_text or ''} {email.body_html or ''}"
        flags = []
        prompt_injection = False
        suspicious_urls = []

        if self.injection_pattern.search(content) or "MOCK_INJECTION" in content:
            flags.append("PROMPT_INJECTION_SUSPECT")
            prompt_injection = True

        for m in self.phish_pattern.finditer(content):
            flags.append("SUSPICIOUS_PHISHING_URL")
            suspicious_urls.append(m.group(0))

        safe = len(flags) == 0
        outcome = InspectionOutcome.ALLOW if safe else InspectionOutcome.REQUIRE_APPROVAL

        return InspectionResult(
            safe=safe,
            outcome=outcome,
            flags=flags,
            risk_findings=flags,
            prompt_injection_detected=prompt_injection,
            suspicious_urls=suspicious_urls,
            details={"mock_inspected": True, "message_id": email.id},
        )

    async def inspect_outgoing_email(
        self, draft: Union[EmailDraftRequest, EmailSendRequest]
    ) -> InspectionResult:
        content = f"{draft.subject or ''} {draft.body_text or ''} {draft.body_html or ''}"
        flags = []
        pii_detected = []

        if "MOCK_DLP_VIOLATION" in content:
            flags.append("EXPLICIT_TEST_DLP_MARKER")

        if self.credit_card_pattern.search(content):
            flags.append("CREDIT_CARD_NUMBER_DETECTED")
            pii_detected.append("CREDIT_CARD")

        if self.ssn_pattern.search(content):
            flags.append("SSN_DETECTED")
            pii_detected.append("SSN")

        if self.api_key_pattern.search(content):
            flags.append("API_KEY_LEAKAGE_DETECTED")
            pii_detected.append("API_KEY")

        safe = len(flags) == 0
        outcome = InspectionOutcome.ALLOW if safe else InspectionOutcome.BLOCK

        return InspectionResult(
            safe=safe,
            outcome=outcome,
            flags=flags,
            risk_findings=flags,
            pii_detected=pii_detected,
            details={"mock_inspected": True, "direction": "outgoing"},
        )

    async def inspect_attachment(
        self, filename: str, content_type: str, data: bytes
    ) -> InspectionResult:
        flags = []
        if filename.endswith(".forbidden") or b"MALICIOUS_ATTACHMENT" in data or b"MZ" == data[:2]:
            flags.append("MALICIOUS_TEST_PAYLOAD")

        safe = len(flags) == 0
        outcome = InspectionOutcome.ALLOW if safe else InspectionOutcome.QUARANTINE

        return InspectionResult(
            safe=safe,
            outcome=outcome,
            flags=flags,
            risk_findings=flags,
            details={"filename": filename, "mock_inspected": True},
        )
