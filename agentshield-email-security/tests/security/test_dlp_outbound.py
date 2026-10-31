"""Security tests for Outbound DLP and attachment defense."""

import base64
import pytest
from httpx import AsyncClient
from app.database.models import OAuthAccount


@pytest.mark.asyncio
async def test_send_blocked_when_credit_card_detected(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount
):
    """Outbound send with Luhn-valid credit card number MUST be blocked by DLP."""
    payload = {
        "account_id": str(seed_oauth_account.id),
        "to": [{"email": "client@example.com"}],
        "subject": "Payment info",
        "body_text": "Please charge card 4532-0151-1283-0366 for the transaction.",
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    detail = str(response.json()["detail"])
    assert "DLP_DATA_LEAKAGE" in detail or "confidential" in detail.lower()


@pytest.mark.asyncio
async def test_send_blocked_when_ssn_detected(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount
):
    """Outbound send with SSN MUST be blocked by DLP."""
    payload = {
        "account_id": str(seed_oauth_account.id),
        "to": [{"email": "hr@example.com"}],
        "subject": "Candidate SSN",
        "body_text": "The candidate SSN is 123-45-6789.",
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    assert "DLP_DATA_LEAKAGE" in str(response.json()["detail"])


@pytest.mark.asyncio
async def test_send_blocked_when_executable_attachment_attached(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount
):
    """Outbound send with dangerous executable attachment MUST be blocked."""
    payload = {
        "account_id": str(seed_oauth_account.id),
        "to": [{"email": "partner@example.com"}],
        "subject": "Tools for you",
        "body_text": "Attached is the installer.",
        "attachments": [
            {
                "filename": "installer.exe",
                "content_type": "application/octet-stream",
                "content_base64": base64.b64encode(b"MZ executable").decode("ascii"),
            }
        ],
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 403
    assert "ATTACHMENT_DISALLOWED" in str(response.json()["detail"])

