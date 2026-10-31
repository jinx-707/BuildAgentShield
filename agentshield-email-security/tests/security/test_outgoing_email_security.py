"""Security tests for Outgoing Email: Unauthorized Recipients, DLP, Approval Tampering, Replay, Expiry."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.models import OAuthAccount
from app.database.repository import ApprovalRepository
from app.integrations.approval_client import (
    calculate_canonical_content_hash,
)
from app.providers.gmail.client import GmailClient


@pytest.mark.asyncio
async def test_unauthorized_recipient_blocked(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount
):
    """Outgoing email to blocked/disposable recipient is rejected."""
    payload = {
        "account_id": str(seed_oauth_account.id),
        "to": [{"email": "target@mailinator.com"}],
        "subject": "Hello",
        "body_text": "Normal body content",
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    assert "INVALID_RECIPIENT" in str(response.json()["detail"])


@pytest.mark.asyncio
async def test_bcc_recipient_manipulation_blocked(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount
):
    """BCC to a blocked/malicious address is caught by recipient validation."""
    payload = {
        "account_id": str(seed_oauth_account.id),
        "to": [{"email": "colleague@example.com"}],
        "bcc": [{"email": "leaker@tempmail.com"}],
        "subject": "Project files",
        "body_text": "Here are files",
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    assert "INVALID_RECIPIENT" in str(response.json()["detail"])


@pytest.mark.asyncio
async def test_content_modified_after_approval_is_blocked(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, db_session: AsyncSession
):
    """If the email body is altered after human approval was granted, transmission is blocked."""
    approval_repo = ApprovalRepository(db_session)
    orig_subject = "Executive Memo"
    orig_body = "Original approved content."
    approved_hash = calculate_canonical_content_hash(orig_subject, orig_body)

    approval = await approval_repo.create_approval(
        tenant_id="test-tenant",
        agent_id="test-agent",
        account_id=seed_oauth_account.id,
        action_type="send",
        target_resource=f"account:{seed_oauth_account.id}",
        subject=orig_subject,
        recipients=["partner@example.com"],
        content_hash=approved_hash,
        attachment_hashes=[],
        reason="Test approval",
        payload_summary={},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        initial_status="APPROVED",
    )
    await db_session.commit()

    # Attempt to send with MODIFIED body text
    payload = {
        "account_id": str(seed_oauth_account.id),
        "approval_id": str(approval.id),
        "to": [{"email": "partner@example.com"}],
        "subject": orig_subject,
        "body_text": "TAMPERED BODY: Sending unauthorized extra information!",
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    detail = str(response.json()["detail"])
    assert "modified after approval" in detail.lower() or "INVALID_APPROVAL" in detail


@pytest.mark.asyncio
async def test_recipient_modified_after_approval_is_blocked(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, db_session: AsyncSession
):
    """If recipients are changed after human approval was granted, transmission is blocked."""
    approval_repo = ApprovalRepository(db_session)
    subject = "Executive Memo"
    body = "Approved memo body."
    approved_hash = calculate_canonical_content_hash(subject, body)

    approval = await approval_repo.create_approval(
        tenant_id="test-tenant",
        agent_id="test-agent",
        account_id=seed_oauth_account.id,
        action_type="send",
        target_resource=f"account:{seed_oauth_account.id}",
        subject=subject,
        recipients=["trusted.partner@example.com"],
        content_hash=approved_hash,
        attachment_hashes=[],
        reason="Test approval",
        payload_summary={},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        initial_status="APPROVED",
    )
    await db_session.commit()

    # Attempt to send to an unapproved recipient
    payload = {
        "account_id": str(seed_oauth_account.id),
        "approval_id": str(approval.id),
        "to": [{"email": "different.recipient@example.com"}],
        "subject": subject,
        "body_text": body,
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    assert "recipient" in str(response.json()["detail"]).lower()


@pytest.mark.asyncio
async def test_approval_replay_and_duplicate_send_is_blocked(
    async_client: AsyncClient,
    seed_oauth_account: OAuthAccount,
    db_session: AsyncSession,
    monkeypatch,
):
    """An approval is single-use: replay or concurrent duplicate send is rejected."""
    async def mock_send(*args, **kwargs):
        return {"id": "msg-sent-ok", "threadId": "th-ok"}

    monkeypatch.setattr(GmailClient, "send_email", mock_send)

    approval_repo = ApprovalRepository(db_session)
    subject = "Status Update"
    body = "Weekly status update."
    approved_hash = calculate_canonical_content_hash(subject, body)

    approval = await approval_repo.create_approval(
        tenant_id="test-tenant",
        agent_id="test-agent",
        account_id=seed_oauth_account.id,
        action_type="send",
        target_resource=f"account:{seed_oauth_account.id}",
        subject=subject,
        recipients=["partner@example.com"],
        content_hash=approved_hash,
        attachment_hashes=[],
        reason="Test single use",
        payload_summary={},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        initial_status="APPROVED",
    )
    await db_session.commit()

    payload = {
        "account_id": str(seed_oauth_account.id),
        "approval_id": str(approval.id),
        "to": [{"email": "partner@example.com"}],
        "subject": subject,
        "body_text": body,
    }

    # First send succeeds and consumes approval
    first_resp = await async_client.post("/online/email/send", json=payload)
    assert first_resp.status_code == 200

    # Second send with same approval MUST fail (anti-replay defense)
    second_resp = await async_client.post("/online/email/send", json=payload)
    assert second_resp.status_code == 403
    assert "already been consumed" in str(second_resp.json()["detail"]).lower() or "replay" in str(second_resp.json()["detail"]).lower()


@pytest.mark.asyncio
async def test_expired_approval_is_blocked(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, db_session: AsyncSession
):
    """An approval past its TTL expiration is rejected."""
    approval_repo = ApprovalRepository(db_session)
    subject = "Expired Action"
    body = "Expired content."
    approved_hash = calculate_canonical_content_hash(subject, body)

    approval = await approval_repo.create_approval(
        tenant_id="test-tenant",
        agent_id="test-agent",
        account_id=seed_oauth_account.id,
        action_type="send",
        target_resource=f"account:{seed_oauth_account.id}",
        subject=subject,
        recipients=["partner@example.com"],
        content_hash=approved_hash,
        attachment_hashes=[],
        reason="Expired test",
        payload_summary={},
        # Expired 2 hours ago
        expires_at=datetime.now(timezone.utc) - timedelta(hours=2),
        initial_status="APPROVED",
    )
    await db_session.commit()

    payload = {
        "account_id": str(seed_oauth_account.id),
        "approval_id": str(approval.id),
        "to": [{"email": "partner@example.com"}],
        "subject": subject,
        "body_text": body,
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    assert "expired" in str(response.json()["detail"]).lower()

