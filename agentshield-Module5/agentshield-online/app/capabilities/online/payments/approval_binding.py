"""
Exact-action approval binding for payments.
Computes a cryptographic fingerprint of the exact transaction.
Any change to the transaction details invalidates the approval.
"""
from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any


def compute_payment_fingerprint(
    agent_id: str,
    tenant_id: str,
    merchant_id: str,
    amount_minor: int,
    currency: str,
    purpose: str,
    order_reference: str,
    provider: str,
) -> str:
    """
    Canonical SHA-256 fingerprint of a payment transaction.

    Bound to:
    - agent_id
    - tenant_id
    - merchant_id
    - amount (minor units — no floating point)
    - currency
    - purpose
    - order_reference
    - provider

    Any change to any field produces a different hash.
    This hash is used for exact-action approval binding.
    """
    canonical = json.dumps(
        {
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "merchant_id": merchant_id,
            "amount_minor": amount_minor,       # integer, no float
            "currency": currency.upper(),
            "purpose": purpose.strip(),
            "order_reference": order_reference.strip(),
            "provider": provider,
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
