"""Development mock implementation of AuditClient.

WARNING:
This mock is for local development and test suites ONLY.
It stores audit events in memory and DOES NOT provide an immutable SIEM record.
"""

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from app.integrations.audit_client import BaseAuditClient

logger = logging.getLogger("agentshield.mocks.audit")


class MockAuditClient(BaseAuditClient):
    """Development in-memory mock audit client."""

    IS_DEVELOPMENT_MOCK: bool = True

    def __init__(self):
        logger.warning(
            "*** SECURITY WARNING: MockAuditClient ACTIVE. IN-MEMORY AUDIT ONLY. ***"
        )
        self.recorded_events: List[Dict[str, Any]] = []

    async def record_event(
        self,
        tenant_id: str,
        agent_id: str,
        event_type: str,
        status: str,
        metadata: Dict[str, Any],
        account_id: Optional[UUID] = None,
        policy_decision_id: Optional[str] = None,
        inspection_reference_id: Optional[str] = None,
    ) -> str:
        event_id = f"mock-audit-{uuid4()}"
        event_payload = {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "account_id": str(account_id) if account_id else None,
            "event_type": event_type,
            "status": status,
            "metadata": metadata,
            "policy_decision_id": policy_decision_id,
            "inspection_reference_id": inspection_reference_id,
        }
        self.recorded_events.append(event_payload)
        logger.info(
            f"[MOCK AUDIT] Event {event_type} status={status} tenant={tenant_id} agent={agent_id}"
        )
        return event_id

    def clear(self) -> None:
        """Clear recorded events between tests."""
        self.recorded_events.clear()

