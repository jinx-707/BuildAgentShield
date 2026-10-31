"""
Transaction validator — validates PaymentRequest schema and business rules.
Uses Decimal for all monetary values. No floating-point arithmetic.
"""
from __future__ import annotations

import re
from decimal import Decimal, ROUND_DOWN
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.exceptions import PaymentError, SpendingLimitExceededError


# Allowed currencies
_ALLOWED_CURRENCIES = frozenset(["INR", "USD", "EUR", "GBP", "SGD", "AED"])

# Minor unit multipliers
_MINOR_UNITS: dict[str, int] = {
    "INR": 100,   # paise
    "USD": 100,   # cents
    "EUR": 100,
    "GBP": 100,
    "SGD": 100,
    "AED": 100,
}


class PaymentRequest(BaseModel):
    """
    Validated payment request.
    All amounts are Decimal. Currency must be in allowed list.
    """
    agent_id: str = Field(..., min_length=1, max_length=128)
    tenant_id: str = Field(..., min_length=1, max_length=128)
    merchant_id: str = Field(..., min_length=1, max_length=64)
    amount: Decimal = Field(..., gt=Decimal("0"))
    currency: str = Field(..., min_length=3, max_length=3)
    purpose: str = Field(..., min_length=1, max_length=256)
    order_reference: str = Field(..., min_length=1, max_length=64)
    idempotency_key: str | None = None

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        v = v.upper().strip()
        if v not in _ALLOWED_CURRENCIES:
            raise ValueError(
                f"Currency '{v}' is not in allowed list: {sorted(_ALLOWED_CURRENCIES)}"
            )
        return v

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: Decimal) -> Decimal:
        if v <= Decimal("0"):
            raise ValueError("Amount must be greater than zero")
        # Enforce max 2 decimal places
        rounded = v.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
        return rounded

    @field_validator("purpose")
    @classmethod
    def validate_purpose(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Purpose cannot be empty")
        # Prevent injection in purpose field
        if len(v) > 256:
            raise ValueError("Purpose too long (max 256 chars)")
        return v

    @field_validator("order_reference")
    @classmethod
    def validate_order_reference(cls, v: str) -> str:
        # Alphanumeric, hyphens, underscores only
        if not re.match(r'^[a-zA-Z0-9_\-]+$', v):
            raise ValueError(
                "order_reference must contain only alphanumeric characters, hyphens, underscores"
            )
        return v

    def to_minor_units(self) -> int:
        """Convert amount to smallest currency unit (integer). No floating point."""
        multiplier = _MINOR_UNITS.get(self.currency, 100)
        return int(self.amount * multiplier)


def validate_transaction_limits(
    request: PaymentRequest,
    max_transaction_minor: int,
    max_daily_minor: int,
    current_daily_total_minor: int,
) -> None:
    """
    Validate per-transaction and daily spending limits.
    All values in minor currency units (integer).
    Raises PaymentError if limits exceeded.
    """
    amount_minor = request.to_minor_units()

    if amount_minor > max_transaction_minor:
        raise SpendingLimitExceededError(
            f"Transaction amount {amount_minor} exceeds maximum "
            f"per-transaction limit {max_transaction_minor} (minor units)"
        )

    projected_daily = current_daily_total_minor + amount_minor
    if projected_daily > max_daily_minor:
        raise SpendingLimitExceededError(
            f"Transaction would exceed daily spending limit. "
            f"Current: {current_daily_total_minor}, "
            f"Transaction: {amount_minor}, "
            f"Limit: {max_daily_minor} (minor units)"
        )
