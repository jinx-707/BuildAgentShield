"""
Transaction store — persists payment transaction records and enforces state machine.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.decisions import PaymentState, is_valid_transition
from app.core.exceptions import InvalidTransactionStateError
from app.core.result_models import PaymentOrderResult, PaymentStatusResult

logger = logging.getLogger(__name__)


class TransactionStore:
    """
    Stores and manages payment transaction lifecycle.
    Enforces valid state transitions.
    """

    async def create(
        self,
        session: AsyncSession,
        agent_id: str,
        tenant_id: str,
        merchant_id: str,
        amount_minor: int,
        currency: str,
        purpose: str,
        order_reference: str,
        provider: str,
        idempotency_key: str,
        action_hash: str,
    ) -> str:
        """Create a new payment transaction record. Returns payment_id."""
        payment_id = f"pay_{uuid.uuid4().hex[:14]}"
        now = datetime.utcnow().isoformat()

        await session.execute(
            text(
                "INSERT INTO payment_transactions ("
                "  payment_id, agent_id, tenant_id, merchant_id, "
                "  amount_minor, currency, purpose, order_reference, "
                "  provider, idempotency_key, action_hash, state, "
                "  provider_order_id, created_at, updated_at"
                ") VALUES ("
                "  :payment_id, :agent_id, :tenant_id, :merchant_id, "
                "  :amount_minor, :currency, :purpose, :order_reference, "
                "  :provider, :idempotency_key, :action_hash, :state, "
                "  NULL, :created_at, :updated_at"
                ")"
            ),
            {
                "payment_id": payment_id,
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "merchant_id": merchant_id,
                "amount_minor": amount_minor,
                "currency": currency,
                "purpose": purpose,
                "order_reference": order_reference,
                "provider": provider,
                "idempotency_key": idempotency_key,
                "action_hash": action_hash,
                "state": PaymentState.CREATED.value,
                "created_at": now,
                "updated_at": now,
            },
        )
        return payment_id

    async def transition(
        self,
        session: AsyncSession,
        payment_id: str,
        new_state: PaymentState,
        provider_order_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Transition payment to a new state.
        Enforces valid state machine transitions.
        """
        result = await session.execute(
            text(
                "SELECT state, provider_order_id FROM payment_transactions "
                "WHERE payment_id = :payment_id FOR UPDATE"
            ),
            {"payment_id": payment_id},
        )
        row = result.fetchone()
        if not row:
            raise InvalidTransactionStateError(
                f"Payment transaction '{payment_id}' not found"
            )

        current_state = PaymentState(row[0])
        if not is_valid_transition(current_state, new_state):
            raise InvalidTransactionStateError(
                f"Invalid payment state transition: {current_state} → {new_state}. "
                "This transition is not permitted."
            )

        update_fields = ["state = :state", "updated_at = :updated_at"]
        params: dict[str, Any] = {
            "payment_id": payment_id,
            "state": new_state.value,
            "updated_at": datetime.utcnow().isoformat(),
        }

        if provider_order_id:
            update_fields.append("provider_order_id = :provider_order_id")
            params["provider_order_id"] = provider_order_id

        await session.execute(
            text(
                f"UPDATE payment_transactions SET {', '.join(update_fields)} "
                f"WHERE payment_id = :payment_id"
            ),
            params,
        )
        logger.info(
            "Payment state transition: %s %s → %s",
            payment_id, current_state.value, new_state.value
        )

    async def get(
        self,
        session: AsyncSession,
        payment_id: str,
    ) -> dict[str, Any] | None:
        result = await session.execute(
            text(
                "SELECT payment_id, agent_id, tenant_id, merchant_id, "
                "amount_minor, currency, purpose, state, provider, "
                "provider_order_id, action_hash, created_at, updated_at "
                "FROM payment_transactions WHERE payment_id = :payment_id"
            ),
            {"payment_id": payment_id},
        )
        row = result.fetchone()
        if not row:
            return None
        columns = [
            "payment_id", "agent_id", "tenant_id", "merchant_id",
            "amount_minor", "currency", "purpose", "state", "provider",
            "provider_order_id", "action_hash", "created_at", "updated_at",
        ]
        return dict(zip(columns, row))

    async def is_webhook_processed(
        self,
        session: AsyncSession,
        event_id: str,
    ) -> bool:
        """Check if a webhook event has already been processed (idempotency)."""
        result = await session.execute(
            text(
                "SELECT 1 FROM processed_webhooks WHERE event_id = :event_id"
            ),
            {"event_id": event_id},
        )
        return result.fetchone() is not None

    async def mark_webhook_processed(
        self,
        session: AsyncSession,
        event_id: str,
        payment_id: str,
        event_type: str,
    ) -> None:
        await session.execute(
            text(
                "INSERT INTO processed_webhooks (event_id, payment_id, event_type, processed_at) "
                "VALUES (:event_id, :payment_id, :event_type, :processed_at)"
            ),
            {
                "event_id": event_id,
                "payment_id": payment_id,
                "event_type": event_type,
                "processed_at": datetime.utcnow().isoformat(),
            },
        )
