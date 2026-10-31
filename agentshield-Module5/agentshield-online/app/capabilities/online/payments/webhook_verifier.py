"""
Webhook verifier — verifies payment provider webhook signatures.
Uses the raw request body — NEVER the parsed/modified body.
"""
from __future__ import annotations

import logging
from typing import Any

from app.capabilities.online.payments.payment_provider import PaymentProvider
from app.core.exceptions import WebhookVerificationError

logger = logging.getLogger(__name__)


class WebhookVerifier:
    """
    Verifies webhook signatures from payment providers.

    Rules:
    - Always uses raw request body bytes
    - Constant-time comparison (delegated to provider)
    - Rejects invalid signatures immediately
    - Does not trust browser-side success reports
    """

    def __init__(
        self,
        provider: PaymentProvider,
        webhook_secret: str,
    ) -> None:
        self._provider = provider
        self._webhook_secret = webhook_secret

    def verify(
        self,
        raw_body: bytes,
        signature: str,
    ) -> None:
        """
        Verify webhook signature.
        Raises WebhookVerificationError if invalid.
        """
        if not signature:
            raise WebhookVerificationError(
                "Webhook signature header is missing"
            )

        if not self._webhook_secret:
            raise WebhookVerificationError(
                f"Webhook secret not configured for provider '{self._provider.provider_name()}'"
            )

        valid = self._provider.verify_webhook_signature(
            raw_body=raw_body,
            signature=signature,
            secret=self._webhook_secret,
        )

        if not valid:
            logger.warning(
                "Webhook signature verification FAILED for provider %s",
                self._provider.provider_name(),
            )
            raise WebhookVerificationError(
                f"Invalid webhook signature for provider '{self._provider.provider_name()}'"
            )

        logger.info(
            "Webhook signature verified OK for provider %s",
            self._provider.provider_name(),
        )
