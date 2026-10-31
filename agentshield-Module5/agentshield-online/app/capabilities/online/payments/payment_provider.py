"""
Abstract payment provider interface.
All payment operations go through this interface.
TEST MODE ONLY — no real money.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from decimal import Decimal
from typing import Any


class PaymentProvider(ABC):
    """
    Provider-independent payment interface.
    Implemented by: RazorpayProvider, StripeProvider.
    """

    @abstractmethod
    async def create_order(
        self,
        amount_minor: int,       # smallest currency unit (paise, cents)
        currency: str,
        receipt: str,
        notes: dict[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Create a payment order. Returns provider order data."""

    @abstractmethod
    async def get_order(self, provider_order_id: str) -> dict[str, Any]:
        """Retrieve order status from provider."""

    @abstractmethod
    async def get_payment_status(self, provider_payment_id: str) -> dict[str, Any]:
        """Retrieve payment status."""

    @abstractmethod
    async def verify_payment(
        self,
        provider_order_id: str,
        provider_payment_id: str,
        provider_signature: str,
    ) -> bool:
        """Verify payment signature/integrity."""

    @abstractmethod
    def verify_webhook_signature(
        self,
        raw_body: bytes,
        signature: str,
        secret: str,
    ) -> bool:
        """Verify webhook signature using constant-time comparison."""

    @abstractmethod
    def provider_name(self) -> str:
        """Return provider identifier."""
