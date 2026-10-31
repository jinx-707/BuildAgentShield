"""Replaceable Human Approval Client interface and implementations."""

import base64
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.repository import ApprovalRepository
from app.schemas.approval import ApprovalResponse, ApprovalStatus
from app.schemas.email import EmailAttachmentInput


def calculate_canonical_content_hash(subject: str, body_text: str) -> str:
    """Calculate deterministic SHA-256 hash of canonical subject and body text."""
    canonical_repr = f"subject:{subject.strip()}\nbody:{body_text.strip()}".encode("utf-8")
    return hashlib.sha256(canonical_repr).hexdigest()


def calculate_attachment_hashes(attachments: List[EmailAttachmentInput]) -> List[str]:
    """Calculate SHA-256 hashes of attachment contents."""
    hashes = []
    for att in attachments:
        try:
            data = base64.b64decode(att.content_base64)
            hashes.append(hashlib.sha256(data).hexdigest())
        except Exception:
            pass
    return sorted(hashes)


class BaseApprovalClient(ABC):
    """Abstract interface contract for managing human approval workflows."""

    @abstractmethod
    async def request_approval(
        self,
        tenant_id: str,
        agent_id: str,
        account_id: UUID,
        action_type: str,
        target_resource: str,
        subject: str,
        recipients: List[str],
        content_hash: str,
        attachment_hashes: List[str],
        reason: str,
        payload_summary: Dict[str, Any],
        ttl_hours: int = 24,
    ) -> ApprovalResponse:
        """Register a new human approval request."""
        pass

    @abstractmethod
    async def get_approval(
        self, approval_id: UUID, tenant_id: str, agent_id: str
    ) -> Optional[ApprovalResponse]:
        """Fetch approval record status."""
        pass

    @abstractmethod
    async def verify_and_consume(
        self,
        approval_id: UUID,
        tenant_id: str,
        agent_id: str,
        account_id: UUID,
        action_type: str,
        content_hash: str,
        attachment_hashes: List[str],
        recipients: List[str],
    ) -> Tuple[bool, str]:
        """Atomically verify and consume an approval."""
        pass


class LocalDatabaseApprovalClient(BaseApprovalClient):
    """Approval client backed by local PostgreSQL/SQLite database with atomic checks."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = ApprovalRepository(session)

    async def request_approval(
        self,
        tenant_id: str,
        agent_id: str,
        account_id: UUID,
        action_type: str,
        target_resource: str,
        subject: str,
        recipients: List[str],
        content_hash: str,
        attachment_hashes: List[str],
        reason: str,
        payload_summary: Dict[str, Any],
        ttl_hours: int = 24,
    ) -> ApprovalResponse:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
        record = await self.repo.create_approval(
            tenant_id=tenant_id,
            agent_id=agent_id,
            account_id=account_id,
            action_type=action_type,
            target_resource=target_resource,
            subject=subject,
            recipients=recipients,
            content_hash=content_hash,
            attachment_hashes=attachment_hashes,
            reason=reason,
            payload_summary=payload_summary,
            expires_at=expires_at,
        )
        return ApprovalResponse(
            approval_id=record.id,
            tenant_id=record.tenant_id,
            agent_id=record.agent_id,
            account_id=record.account_id,
            action_type=record.action_type,
            status=ApprovalStatus(record.status),
            subject=record.subject,
            recipients=record.recipients,
            content_hash_sha256=record.content_hash,
            attachment_hashes_sha256=record.attachment_hashes,
            reason=record.reason,
            approved_by=record.approved_by,
            created_at=record.created_at,
            expires_at=record.expires_at,
            used=record.used,
        )

    async def get_approval(
        self, approval_id: UUID, tenant_id: str, agent_id: str
    ) -> Optional[ApprovalResponse]:
        record = await self.repo.get_approval(approval_id, tenant_id, agent_id)
        if not record:
            return None
        return ApprovalResponse(
            approval_id=record.id,
            tenant_id=record.tenant_id,
            agent_id=record.agent_id,
            account_id=record.account_id,
            action_type=record.action_type,
            status=ApprovalStatus(record.status),
            subject=record.subject,
            recipients=record.recipients,
            content_hash_sha256=record.content_hash,
            attachment_hashes_sha256=record.attachment_hashes,
            reason=record.reason,
            approved_by=record.approved_by,
            created_at=record.created_at,
            expires_at=record.expires_at,
            used=record.used,
        )

    async def verify_and_consume(
        self,
        approval_id: UUID,
        tenant_id: str,
        agent_id: str,
        account_id: UUID,
        action_type: str,
        content_hash: str,
        attachment_hashes: List[str],
        recipients: List[str],
    ) -> Tuple[bool, str]:
        return await self.repo.consume_approval_atomically(
            approval_id=approval_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
            account_id=account_id,
            action_type=action_type,
            content_hash=content_hash,
            attachment_hashes=attachment_hashes,
            recipients=recipients,
        )

