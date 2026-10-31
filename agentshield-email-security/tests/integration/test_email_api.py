"""Integration tests for Email operations endpoints."""

from uuid import uuid4
import pytest
from httpx import AsyncClient
from app.database.models import OAuthAccount
from app.providers.gmail.client import GmailClient


@pytest.mark.asyncio
async def test_list_accounts(async_client: AsyncClient, seed_oauth_account: OAuthAccount):
    response = await async_client.get("/online/email/accounts")
    assert response.status_code == 200
    accounts = response.json()
    assert len(accounts) == 1
    acc = accounts[0]
    assert acc["id"] == str(seed_oauth_account.id)
    assert acc["account_email"] == "agent.test@example.com"
    assert acc["provider"] == "google"
    assert "access_token" not in acc
    assert "refresh_token" not in acc


@pytest.mark.asyncio
async def test_read_messages(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, monkeypatch
):
    # Mock GmailClient methods
    async def mock_list(self, query=None, max_results=10, page_token=None, include_spam_trash=False):
        raw_msg = {
            "id": "msg-inbox-1",
            "snippet": "Test subject snippet",
            "payload": {
                "headers": [
                    {"name": "From", "value": "boss@example.com"},
                    {"name": "To", "value": "agent.test@example.com"},
                    {"name": "Subject", "value": "Quarterly review"},
                ],
                "parts": [{"mimeType": "text/plain", "body": {"data": "VGVzdCBib2R5"}}],
            },
        }
        return [raw_msg], None

    monkeypatch.setattr(GmailClient, "list_messages", mock_list)

    response = await async_client.get(
        "/online/email/messages",
        params={"account_id": str(seed_oauth_account.id)},
    )
    assert response.status_code == 200
    messages = response.json()
    assert len(messages) == 1
    assert messages[0]["id"] == "msg-inbox-1"
    assert messages[0]["subject"] == "Quarterly review"


@pytest.mark.asyncio
async def test_search_messages(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, monkeypatch
):
    async def mock_list(self, query=None, max_results=10, page_token=None, include_spam_trash=False):
        raw_msg = {
            "id": "msg-search-result",
            "snippet": "Urgent ticket",
            "payload": {
                "headers": [
                    {"name": "From", "value": "customer@example.com"},
                    {"name": "Subject", "value": "Urgent ticket #456"},
                ],
                "parts": [],
            },
        }
        return [raw_msg], None

    monkeypatch.setattr(GmailClient, "list_messages", mock_list)

    payload = {
        "account_id": str(seed_oauth_account.id),
        "query": "ticket #456",
        "max_results": 5,
    }
    response = await async_client.post("/online/email/search", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert len(data["messages"]) == 1
    assert data["messages"][0]["id"] == "msg-search-result"


@pytest.mark.asyncio
async def test_create_draft(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, monkeypatch
):
    async def mock_create_draft(self, to, cc, bcc, subject, body_text, body_html=None, thread_id=None):
        return {"id": "draft-101", "message": {"id": "msg-draft-101"}}

    monkeypatch.setattr(GmailClient, "create_draft", mock_create_draft)

    payload = {
        "account_id": str(seed_oauth_account.id),
        "to": [{"email": "client@example.com", "name": "Client"}],
        "subject": "Proposal Draft",
        "body_text": "Here is the proposal as requested.",
    }
    response = await async_client.post("/online/email/draft", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["draft_id"] == "draft-101"
    assert data["subject"] == "Proposal Draft"
    assert data["status"] == "drafted"


@pytest.mark.asyncio
async def test_send_email_success(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, monkeypatch
):
    async def mock_send(self, to, cc, bcc, subject, body_text, body_html=None, thread_id=None, attachments=None):
        return {"id": "msg-sent-999", "threadId": "th-sent-999"}

    monkeypatch.setattr(GmailClient, "send_email", mock_send)

    payload = {
        "account_id": str(seed_oauth_account.id),
        "to": [{"email": "client@example.com", "name": "Client"}],
        "subject": "Service confirmation",
        "body_text": "Your subscription is confirmed.",
    }
    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["message_id"] == "msg-sent-999"
    assert data["status"] == "sent"


@pytest.mark.asyncio
async def test_forward_email_success(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, monkeypatch
):
    async def mock_get_message(self, message_id):
        return {
            "id": message_id,
            "snippet": "Original text",
            "payload": {
                "headers": [
                    {"name": "From", "value": "sender@example.com"},
                    {"name": "Subject", "value": "Original subject"},
                ],
                "parts": [{"mimeType": "text/plain", "body": {"data": "T3JpZ2luYWwgY29udGVudA=="}}],
            },
        }

    async def mock_forward(self, original_message_id, to, cc, additional_comment=None, forward_attachments=True):
        return {"id": "msg-fwd-888"}

    monkeypatch.setattr(GmailClient, "get_message", mock_get_message)
    monkeypatch.setattr(GmailClient, "forward_email", mock_forward)

    payload = {
        "account_id": str(seed_oauth_account.id),
        "original_message_id": "orig-msg-123",
        "to": [{"email": "escalation@example.com"}],
        "additional_comment": "Please review this ticket.",
    }
    response = await async_client.post("/online/email/forward", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["message_id"] == "msg-fwd-888"
    assert data["status"] == "forwarded"

