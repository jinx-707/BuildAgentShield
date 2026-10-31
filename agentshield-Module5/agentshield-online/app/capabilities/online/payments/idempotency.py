"""
Durable idempotency for payment requests.
Prevents duplicate payment orders.
Uses the database — NOT in-memory dicts.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import DuplicateTransactionError

logger = logging.getLogger(__name__)


def compute_idempotency_key(
    agent_id: str,
    tenant_id: str,
    merchant_id: str,
    amount_minor: int,
    currency: str,
    order_reference: str,
) -> str:
    """
    Compute a deterministic idempotency key from request parameters.
    Bound to agent + tenant — cannot be replayed by a different agent.
    """
    canonical = json.dumps(
        {
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "merchant_id": merchant_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "order_reference": order_reference,
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class IdempotencyStore:
    """
    Durable idempotency store backed by the database.
    Uses INSERT OR IGNORE (SQLite) / ON CONFLICT DO NOTHING (PostgreSQL)
    to atomically detect duplicates.
    """

    def __init__(self, ttl_hours: int = 24) -> None:
        self._ttl = timedelta(hours=ttl_hours)

    async def check_and_insert(
        self,
        session: AsyncSession,
        idempotency_key: str,
        agent_id: str,
        tenant_id: str,
        request_fingerprint: str,
        payment_id: str,
    ) -> tuple[bool, str | None]:
        """
        Attempt to insert idempotency record.

        Returns:
            (is_new, existing_payment_id)
            is_new=True  → first time seeing this key, record inserted
            is_new=False → duplicate, existing_payment_id contains the original
        """
        expires_at = datetime.utcnow() + self._ttl
        now = datetime.utcnow()

        # Check for existing non-expired record
        result = await session.execute(
            text(
                "SELECT payment_id, request_fingerprint FROM payment_idempotency "
                "WHERE idempotency_key = :key "
                "  AND agent_id = :agent_id "
                "  AND tenant_id = :tenant_id "
                "  AND expires_at > :now"
            ),
            {
                "key": idempotency_key,
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "now": now.isoformat(),
            },
        )
        existing = result.fetchone()

        if existing:
            existing_pid, stored_fp = existing
            if stored_fp != request_fingerprint:
                raise DuplicateTransactionError(
                    f"Idempotency key collision with different request fingerprint. "
                    "Do not reuse idempotency keys for different transactions."
                )
            return False, existing_pid

        # Insert new record
        try:
            await session.execute(
                text(
                    "INSERT INTO payment_idempotency "
                    "(idempotency_key, agent_id, tenant_id, payment_id, "
                    " request_fingerprint, created_at, expires_at) "
                    "VALUES (:key, :agent_id, :tenant_id, :payment_id, "
                    "        :fingerprint, :created_at, :expires_at)"
                ),
                {
                    "key": idempotency_key,
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "payment_id": payment_id,
                    "fingerprint": request_fingerprint,
                    "created_at": now.isoformat(),
                    "expires_at": expires_at.isoformat(),
                },
            )
            return True, None
        except Exception as e:
            # Handle unique constraint violation (race condition)
            logger.warning("Idempotency insert conflict: %s", e)
            # Re-query to get the winner
            result = await session.execute(
                text(
                    "SELECT payment_id FROM payment_idempotency "
                    "WHERE idempotency_key = :key AND agent_id = :agent_id "
                    "  AND tenant_id = :tenant_id AND expires_at > :now"
                ),
                {
                    "key": idempotency_key,
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "now": datetime.utcnow().isoformat(),
                },
            )
            row = result.fetchone()
            if row:
                return False, row[0]
            raise
