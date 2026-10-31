"""AuditClient interface and remote HTTP client for centralized AgentShield audit logging."""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from uuid import UUID
import httpx
from app.config import get_settings

logger = logging.getLogger("agentshield.email.audit")


class AuditError(Exception):
    """Raised when audit recording fails."""
    pass


class BaseAuditClient(ABC):
    """Abstract interface for recording security-relevant email audit events."""

    @abstractmethod
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
        """Record an audit trail entry and return audit log ID."""
        pass


class HttpAuditClient(BaseAuditClient):
    """Remote production HTTP client for AgentShield Central SIEM / Audit service."""

    def __init__(self, service_url: Optional[str] = None, timeout: float = 4.0):
        settings = get_settings()
        self.service_url = service_url or settings.AUDIT_SERVICE_URL
        self.timeout = timeout
        self.internal_token = settings.INTERNAL_SERVICE_TOKEN

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
        if not self.service_url:
            logger.warning("Audit service URL not configured; writing event locally only")
            return "local-only"

        payload = {
            "component": "agentshield-email-security",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "account_id": str(account_id) if account_id else None,
            "event_type": event_type,
            "status": status,
            "policy_decision_id": policy_decision_id,
            "inspection_reference_id": inspection_reference_id,
            "metadata": metadata,
        }

        url = f"{self.service_url.rstrip('/')}/events"
        headers = {"Authorization": f"Bearer {self.internal_token}"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code not in (200, 201):
                    logger.error(f"Audit service rejected event: {resp.status_code}")
                    return "error"
                data = resp.json()
                return data.get("event_id", "recorded")
        except Exception as e:
            logger.error(f"Failed to transmit audit record to SIEM: {e}")
            return "failed-transmission"

