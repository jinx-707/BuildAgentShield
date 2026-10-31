"""
Validates email recipients against policy.
"""
from __future__ import annotations

import re
from typing import NamedTuple

from app.capabilities.online.email.email_policy import EmailPolicy
from app.core.exceptions import UnauthorizedRecipientError

_EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)


class RecipientValidationResult(NamedTuple):
    valid: bool
    blocked_recipients: list[str]
    reason: str


def validate_recipients(
    recipients: list[str],
    cc: list[str],
    bcc: list[str],
    policy: EmailPolicy,
) -> RecipientValidationResult:
    """
    Validate all recipient fields against email policy.
    Returns RecipientValidationResult or raises UnauthorizedRecipientError.
    """
    all_recipients = recipients + cc + bcc
    blocked: list[str] = []

    for addr in all_recipients:
        addr = addr.strip().lower()

        # Format validation
        if not _EMAIL_REGEX.match(addr):
            raise UnauthorizedRecipientError(
                f"Invalid email address format: {addr}"
            )

        # Blocked addresses
        if addr in [b.lower() for b in policy.blocked_addresses]:
            blocked.append(addr)
            continue

        # Check approved list
        approved = [a.lower() for a in policy.approved_recipients]
        if addr in approved:
            continue

        # Check approved domains
        domain = addr.split("@", 1)[1]
        approved_domains = [d.lower() for d in policy.approved_domains]
        if domain in approved_domains:
            continue

        # External recipient policy
        if not policy.allow_external_recipients:
            raise UnauthorizedRecipientError(
                f"Recipient '{addr}' is not in approved list or approved domains. "
                "External recipients are not permitted by current policy."
            )

    if blocked:
        raise UnauthorizedRecipientError(
            f"Blocked recipient(s): {blocked}"
        )

    return RecipientValidationResult(
        valid=True,
        blocked_recipients=[],
        reason="",
    )


def validate_sender(sender: str, policy: EmailPolicy) -> bool:
    """Validate the sender account is in the allowed list."""
    if not policy.allowed_sender_accounts:
        # If no list configured, allow any sender (warn)
        return True
    return sender.lower() in [s.lower() for s in policy.allowed_sender_accounts]
