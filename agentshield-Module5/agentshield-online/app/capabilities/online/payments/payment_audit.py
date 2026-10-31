"""
Payment audit — records all payment lifecycle events.
"""
from __future__ import annotations

import logging
from datetime import datetime
from decimal import Decimal
from typing import Any

from app.integrations.ports import AuditEvent, AuditPort

logger = logging.getLogger(__name__)


class PaymentAudit:
    def __init__(self, audit: AuditPort) -> None:
        self._audit = audit

    async def record_payment_event(
        self,
        event_type: str,
        payment_id: str,
        agent_id: str,
        tenant_id: str,
        request_id: str,
        decision: str,
        status: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        await self._audit.record(
            AuditEvent(
                event_type=f"PAYMENT_{event_type}",
                agent_id=agent_id,
                tenant_id=tenant_id,
                capability="payments",
                operation=event_type.lower(),
                decision=decision,
                status=status,
                request_id=request_id,
                resource=payment_id,
                reason=reason,
                metadata=metadata or {},
                timestamp=datetime.utcnow(),
            )
        )
