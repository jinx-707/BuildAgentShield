"""
Spending limits enforcement.
Uses SQLite/PostgreSQL with row-level locking for atomic concurrent enforcement.
Concurrent requests cannot exceed the daily budget.
"""
from __future__ import annotations

import logging
from datetime import datetime, date
from decimal import Decimal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import SpendingLimitExceededError

logger = logging.getLogger(__name__)


class SpendingLimitsEnforcer:
    """
    Enforces per-agent daily spending limits atomically using DB transactions.
    Uses SELECT FOR UPDATE to prevent concurrent bypass.
    """

    def __init__(
        self,
        max_transaction_minor: int,
        daily_limit_minor: int,
    ) -> None:
        self._max_txn = max_transaction_minor
        self._daily = daily_limit_minor

    async def check_and_reserve(
        self,
        session: AsyncSession,
        agent_id: str,
        tenant_id: str,
        amount_minor: int,
        currency: str,
    ) -> None:
        """
        Atomically check and reserve spending capacity.
        Uses SELECT FOR UPDATE to block concurrent requests.

        If this call succeeds, the amount is reserved.
        The caller MUST release the session transaction (commit/rollback) after payment.

        Raises SpendingLimitExceededError if limit would be exceeded.
        """
        today = date.today().isoformat()

        # Try to get existing record with row lock
        result = await session.execute(
            text(
                "SELECT total_spent_minor FROM agent_daily_spending "
                "WHERE agent_id = :agent_id AND tenant_id = :tenant_id "
                "  AND currency = :currency AND spend_date = :date "
                "FOR UPDATE"
            ),
            {
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "currency": currency,
                "date": today,
            },
        )
        row = result.fetchone()
        current_total = row[0] if row else 0

        # Check single transaction limit
        if amount_minor > self._max_txn:
            raise SpendingLimitExceededError(
                f"Transaction amount {amount_minor} exceeds per-transaction limit {self._max_txn}"
            )

        # Check daily limit
        projected = current_total + amount_minor
        if projected > self._daily:
            raise SpendingLimitExceededError(
                f"Transaction would exceed daily spending limit. "
                f"Used: {current_total}, Requested: {amount_minor}, "
                f"Daily limit: {self._daily} minor units"
            )

        # Update or insert
        if row:
            await session.execute(
                text(
                    "UPDATE agent_daily_spending "
                    "SET total_spent_minor = total_spent_minor + :amount "
                    "WHERE agent_id = :agent_id AND tenant_id = :tenant_id "
                    "  AND currency = :currency AND spend_date = :date"
                ),
                {
                    "amount": amount_minor,
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "currency": currency,
                    "date": today,
                },
            )
        else:
            await session.execute(
                text(
                    "INSERT INTO agent_daily_spending "
                    "(agent_id, tenant_id, currency, spend_date, total_spent_minor) "
                    "VALUES (:agent_id, :tenant_id, :currency, :date, :amount)"
                ),
                {
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "currency": currency,
                    "date": today,
                    "amount": amount_minor,
                },
            )

    async def get_daily_total(
        self,
        session: AsyncSession,
        agent_id: str,
        tenant_id: str,
        currency: str,
    ) -> int:
        """Return the agent's total spending for today in minor units."""
        today = date.today().isoformat()
        result = await session.execute(
            text(
                "SELECT total_spent_minor FROM agent_daily_spending "
                "WHERE agent_id = :agent_id AND tenant_id = :tenant_id "
                "  AND currency = :currency AND spend_date = :date"
            ),
            {
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "currency": currency,
                "date": today,
            },
        )
        row = result.fetchone()
        return row[0] if row else 0
