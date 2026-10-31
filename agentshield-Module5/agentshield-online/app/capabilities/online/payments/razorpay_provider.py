"""
Razorpay Test Mode provider.
WARNING: TEST CREDENTIALS ONLY. Never use live keys.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any

from app.capabilities.online.payments.payment_provider import PaymentProvider
from app.core.exceptions import PaymentProviderError, RealMoneyProtectionError

logger = logging.getLogger(__name__)


class RazorpayProvider(PaymentProvider):
    """
    Razorpay payment provider — test mode only.

    Requires:
        RAZORPAY_KEY_ID   = rzp_test_XXXX
        RAZORPAY_KEY_SECRET = XXXX
        RAZORPAY_WEBHOOK_SECRET = XXXX

    Refuses to operate if key_id does not start with 'rzp_test_'.
    """

    def __init__(self, key_id: str, key_secret: str) -> None:
        # HARD GUARD: refuse live credentials
        if key_id and not key_id.startswith("rzp_test_"):
            raise RealMoneyProtectionError(
                "CRITICAL: Razorpay key_id must start with 'rzp_test_'. "
                "Live payment processing is forbidden in this module."
            )
        self._key_id = key_id
        self._key_secret = key_secret

    def _client(self) -> Any:
        try:
            import razorpay  # type: ignore
            client = razorpay.Client(auth=(self._key_id, self._key_secret))
            return client
        except ImportError:
            raise PaymentProviderError(
                "razorpay package not installed. Run: pip install razorpay"
            )

    async def create_order(
        self,
        amount_minor: int,
        currency: str,
        receipt: str,
        notes: dict[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Create Razorpay test order."""
        if not self._key_id:
            return self._mock_order(amount_minor, currency, receipt)

        try:
            client = self._client()
            data: dict[str, Any] = {
                "amount": amount_minor,
                "currency": currency.upper(),
                "receipt": receipt[:40],  # Razorpay max 40 chars
                "notes": notes or {},
            }
            order = client.order.create(data=data)
            logger.info(
                "Razorpay test order created: id=%s amount=%s %s",
                order.get("id"), amount_minor, currency
            )
            return order
        except PaymentProviderError:
            raise
        except Exception as e:
            raise PaymentProviderError(
                f"Razorpay create_order failed: {type(e).__name__}: {str(e)[:200]}"
            )

    async def get_order(self, provider_order_id: str) -> dict[str, Any]:
        if not self._key_id:
            return {"id": provider_order_id, "status": "created"}
        try:
            client = self._client()
            return client.order.fetch(provider_order_id)
        except Exception as e:
            raise PaymentProviderError(f"Razorpay get_order failed: {e}")

    async def get_payment_status(self, provider_payment_id: str) -> dict[str, Any]:
        if not self._key_id:
            return {"id": provider_payment_id, "status": "created"}
        try:
            client = self._client()
            return client.payment.fetch(provider_payment_id)
        except Exception as e:
            raise PaymentProviderError(f"Razorpay get_payment failed: {e}")

    async def verify_payment(
        self,
        provider_order_id: str,
        provider_payment_id: str,
        provider_signature: str,
    ) -> bool:
        """
        Verify Razorpay payment signature.
        HMAC-SHA256(order_id|payment_id, key_secret)
        """
        if not self._key_secret:
            return False
        try:
            expected = hmac.new(
                self._key_secret.encode("utf-8"),
                f"{provider_order_id}|{provider_payment_id}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(expected, provider_signature)
        except Exception as e:
            logger.error("Razorpay payment verification error: %s", e)
            return False

    def verify_webhook_signature(
        self,
        raw_body: bytes,
        signature: str,
        secret: str,
    ) -> bool:
        """
        Verify Razorpay webhook signature.
        Uses exact raw_body bytes — NEVER the parsed/modified body.
        Constant-time comparison.
        """
        if not secret:
            logger.warning("Razorpay webhook verification: no secret configured")
            return False
        try:
            expected = hmac.new(
                secret.encode("utf-8"),
                raw_body,
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(expected, signature)
        except Exception as e:
            logger.error("Razorpay webhook verification error: %s", e)
            return False

    def provider_name(self) -> str:
        return "razorpay"

    def _mock_order(
        self, amount: int, currency: str, receipt: str
    ) -> dict[str, Any]:
        """Mock order when no credentials are configured (local dev)."""
        import uuid
        return {
            "id": f"order_mock_{uuid.uuid4().hex[:10]}",
            "entity": "order",
            "amount": amount,
            "currency": currency.upper(),
            "receipt": receipt,
            "status": "created",
            "attempts": 0,
            "_mock": True,
        }
