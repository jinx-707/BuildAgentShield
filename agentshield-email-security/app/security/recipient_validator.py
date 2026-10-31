"""Recipient validation engine: Syntax, domain reputation, and boundary enforcement."""

import logging
import re
from typing import List, Optional, Set
from app.schemas.email import EmailAddress
from app.schemas.security import RecipientValidationResult

logger = logging.getLogger("agentshield.security.recipient")

# Basic RFC 5322 compliant regex for safe address parsing
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

# Known disposable / throwaway email provider domains
DISPOSABLE_DOMAINS: Set[str] = {
    "mailinator.com",
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "throwawaymail.com",
    "yopmail.com",
    "sharklasers.com",
    "getairmail.com",
    "trashmail.com",
}


class RecipientValidator:
    """Validates destination recipient addresses against security, boundary, and abuse policies."""

    def __init__(
        self,
        trusted_domains: Optional[List[str]] = None,
        blocked_domains: Optional[List[str]] = None,
    ):
        self.trusted_domains = set(d.lower() for d in (trusted_domains or []))
        self.blocked_domains = set(d.lower() for d in (blocked_domains or [])) | DISPOSABLE_DOMAINS

    def validate_address(self, email: str) -> tuple[bool, Optional[str]]:
        """Validate single address format and hygiene."""
        email_clean = email.strip()

        # Reject control characters and header injection attempts (CRLF)
        if any(c in email_clean for c in ["\r", "\n", "\0", "%0d", "%0a"]):
            return False, "Recipient address contains illegal control characters or CRLF sequence"

        if not EMAIL_REGEX.match(email_clean):
            return False, "Address fails RFC 5322 syntax validation"

        parts = email_clean.split("@")
        if len(parts) != 2:
            return False, "Malformed email structure"

        domain = parts[1].lower()

        # Check Punycode / IDN homograph attack indicator
        if domain.startswith("xn--") or any(ord(c) > 127 for c in domain):
            return False, "Internationalized/punycode domain detected (potential homograph attack)"

        if domain in self.blocked_domains:
            return False, f"Domain '{domain}' is on security blocked or disposable domain list"

        return True, None

    def validate_recipients(
        self, recipients: List[EmailAddress]
    ) -> RecipientValidationResult:
        """Validate a collection of recipients, assessing syntax, boundaries, and risk."""
        if not recipients:
            return RecipientValidationResult(
                is_valid=False,
                invalid_recipients=[],
                external_recipients=[],
                is_external=False,
                risk_level="HIGH",
                reasons=["Recipient list cannot be empty"],
            )

        invalid: List[str] = []
        external: List[str] = []
        reasons: List[str] = []

        for addr in recipients:
            valid, reason = self.validate_address(addr.email)
            if not valid:
                invalid.append(addr.email)
                reasons.append(f"{addr.email}: {reason}")
            else:
                domain = addr.email.split("@")[1].lower()
                if self.trusted_domains and domain not in self.trusted_domains:
                    external.append(addr.email)

        is_external = len(external) > 0
        risk_level = "LOW"

        if invalid:
            risk_level = "CRITICAL"
        elif is_external and len(external) > 5:
            risk_level = "HIGH"
            reasons.append("High volume of external recipients")
        elif is_external:
            risk_level = "MEDIUM"

        return RecipientValidationResult(
            is_valid=len(invalid) == 0,
            invalid_recipients=invalid,
            external_recipients=external,
            is_external=is_external,
            risk_level=risk_level,
            reasons=reasons,
        )

