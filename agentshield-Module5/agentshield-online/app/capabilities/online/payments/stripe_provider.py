"""
Stripe Test Mode provider (optional adapter).
WARNING: TEST CREDENTIALS ONLY. Never use live keys.
"""
from __future__ import annotations

import logging
from typing import Any

from app.capabilities.online.payments.payment_provider import PaymentProvider
from app.core.exceptions import PaymentProviderError, RealMoneyProtectionError

logger = logging.getLogger(__name__)


class StripeProvider(PaymentProvider):
    """
    Stripe payment provider — test mode only.

    Requires:
        STRIPE_SECRET_KEY     = sk_test_XXXX
        STRIPE_WEBHOOK_SECRET = whsec_XXXX

    Refuses to operate if secret_key does not start with 'sk_test_'.
    """

    def __init__(self, secret_key: str) -> None:
        if secret_key and not secret_key.startswith("sk_test_"):
            raise RealMoneyProtectionError(
                "CRITICAL: Stripe secret_key must start with 'sk_test_'. "
                "Live payment processing is forbidden in this module."
            )
        self._secret_key = secret_key

    def _stripe(self) -> Any:
        try:
            import stripe  # type: ignore
            stripe.api_key = self._secret_key
            return stripe
        except ImportError:
            raise PaymentProviderError(
                "stripe package not installed. Run: pip install stripe"
            )

    async def create_order(
        self,
        amount_minor: int,
        currency: str,
        receipt: str,
        notes: dict[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if not self._secret_key:
            return self._mock_intent(amount_minor, currency, receipt)
        try:
            stripe = self._stripe()
            kwargs: dict[str, Any] = {
                "amount": amount_minor,
                "currency": currency.lower(),
                "metadata": notes or {},
                "automatic_payment_methods": {"enabled": True},
            }
            if idempotency_key:
                kwargs["idempotency_key"] = idempotency_key
            intent = stripe.PaymentIntent.create(**kwargs)
            logger.info(
                "Stripe test PaymentIntent created: id=%s amount=%s %s",
                intent.id, amount_minor, currency
            )
            return dict(intent)
        except PaymentProviderError:
            raise
        except Exception as e:
            raise PaymentProviderError(f"Stripe create_order failed: {e}")

    async def get_order(self, provider_order_id: str) -> dict[str, Any]:
        if not self._secret_key:
            return {"id": provider_order_id, "status": "requires_payment_method"}
        try:
            stripe = self._stripe()
            intent = stripe.PaymentIntent.retrieve(provider_order_id)
            return dict(intent)
        except Exception as e:
            raise PaymentProviderError(f"Stripe get_order failed: {e}")

    async def get_payment_status(self, provider_payment_id: str) -> dict[str, Any]:
        return await self.get_order(provider_payment_id)

    async def verify_payment(
        self,
        provider_order_id: str,
        provider_payment_id: str,
        provider_signature: str,
    ) -> bool:
        if not self._secret_key:
            return False
        try:
            stripe = self._stripe()
            intent = stripe.PaymentIntent.retrieve(provider_order_id)
            return intent.get("status") == "succeeded"
        except Exception:
            return False

    def verify_webhook_signature(
        self,
        raw_body: bytes,
        signature: str,
        secret: str,
    ) -> bool:
        """
        Verify Stripe webhook signature via stripe.Webhook.construct_event.
        Uses raw body bytes — NEVER the parsed body.
        """
        if not secret:
            return False
        try:
            stripe = self._stripe()
            stripe.Webhook.construct_event(
                payload=raw_body,
                sig_header=signature,
                secret=secret,
            )
            return True
        except Exception as e:
            logger.warning("Stripe webhook verification failed: %s", e)
            return False

    def provider_name(self) -> str:
        return "stripe"

    def _mock_intent(
        self, amount: int, currency: str, receipt: str
    ) -> dict[str, Any]:
        import uuid
        return {
            "id": f"pi_mock_{uuid.uuid4().hex[:10]}",
            "object": "payment_intent",
            "amount": amount,
            "currency": currency.lower(),
            "status": "requires_payment_method",
            "_mock": True,
        }
