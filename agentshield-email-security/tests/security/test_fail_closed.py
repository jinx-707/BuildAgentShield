"""Security tests verifying strict fail-closed posture when security services are unavailable."""

import pytest
from httpx import AsyncClient
from app.database.models import OAuthAccount
from app.integrations.inspection_client import InspectionServiceUnavailableError
from app.integrations.policy_client import PolicyServiceUnavailableError
from mocks.mock_inspector import MockInspectionClient
from mocks.mock_policy import MockPolicyClient


@pytest.mark.asyncio
async def test_fail_closed_when_policy_service_is_down(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, monkeypatch
):
    """When the central policy service is unreachable, all actions MUST fail closed."""
    async def mock_unreachable(*args, **kwargs):
        raise PolicyServiceUnavailableError("Central Policy Service unreachable (connection timeout)")

    monkeypatch.setattr(MockPolicyClient, "authorize_send", mock_unreachable)

    payload = {
        "account_id": str(seed_oauth_account.id),
        "to": [{"email": "partner@example.com"}],
        "subject": "Status update",
        "body_text": "Everything is running smoothly.",
    }

    response = await async_client.post("/online/email/send", json=payload)
    # Must fail closed with 503 Service Unavailable, NEVER allowing delivery!
    assert response.status_code == 503
    assert "fail-closed" in str(response.json()["detail"]).lower()


@pytest.mark.asyncio
async def test_fail_closed_when_inspection_service_is_down(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount, monkeypatch
):
    """When the inspection / DLP service is unreachable, outbound send MUST fail closed."""
    async def mock_inspection_down(*args, **kwargs):
        raise InspectionServiceUnavailableError("Inspection engine unavailable")

    monkeypatch.setattr(MockInspectionClient, "inspect_outgoing_email", mock_inspection_down)

    payload = {
        "account_id": str(seed_oauth_account.id),
        "to": [{"email": "partner@example.com"}],
        "subject": "Status update",
        "body_text": "Clean body text.",
    }

    response = await async_client.post("/online/email/send", json=payload)
    assert response.status_code == 503
    assert "fail-closed" in str(response.json()["detail"]).lower()
