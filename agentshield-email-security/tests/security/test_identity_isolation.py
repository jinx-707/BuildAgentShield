"""Security tests for multi-tenant and agent identity isolation boundaries."""

import pytest
from httpx import AsyncClient
from app.database.models import OAuthAccount


@pytest.mark.asyncio
async def test_tenant_cannot_access_another_tenants_mailbox(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount
):
    """A caller from Tenant B must never be able to read or query Tenant A's account."""
    # Seed account is owned by "test-tenant" and "test-agent"
    # Create request with spoofed or different tenant header
    headers = {
        "Authorization": "Bearer dev-secret-token",
        "X-Tenant-ID": "malicious-tenant-b",
        "X-Agent-ID": "agent-rogue",
    }

    # 1. Attempt to list accounts
    list_resp = await async_client.get("/online/email/accounts", headers=headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 0  # Should see 0 accounts!

    # 2. Attempt direct ID reference access to Tenant A's mailbox
    get_resp = await async_client.get(
        "/online/email/messages",
        params={"account_id": str(seed_oauth_account.id)},
        headers=headers,
    )
    assert get_resp.status_code == 404
    assert "not found" in str(get_resp.json()["detail"]).lower()


@pytest.mark.asyncio
async def test_agent_cannot_access_another_agents_mailbox_in_same_tenant(
    async_client: AsyncClient, seed_oauth_account: OAuthAccount
):
    """Agent 2 in the same tenant must not access Agent 1's mailbox."""
    headers = {
        "Authorization": "Bearer dev-secret-token",
        "X-Tenant-ID": "test-tenant",  # Same tenant
        "X-Agent-ID": "different-agent-999",  # Different agent
    }

    get_resp = await async_client.get(
        "/online/email/messages",
        params={"account_id": str(seed_oauth_account.id)},
        headers=headers,
    )
    assert get_resp.status_code == 404

