"""
Unit tests — Secret broker and mock provider.
"""

from __future__ import annotations

import pytest

from app.capabilities.offline.environment.secret_broker import SecretBroker
from app.capabilities.offline.environment.secret_provider import MockSecretProvider
from app.core.exceptions import SecretAccessDeniedError


@pytest.fixture
def provider():
    return MockSecretProvider(secrets={
        "db-password": "super-secret-db-pass",
        "api-token": "tok_abcdefgh",
    })


@pytest.fixture
def broker(provider):
    return SecretBroker(
        provider=provider,
        permitted_secrets={
            "db-password": ["agent-db"],
            "api-token": ["agent-api", "agent-db"],
        },
    )


class TestSecretBroker:
    @pytest.mark.asyncio
    async def test_retrieves_permitted_secret(self, broker):
        value = await broker.retrieve("db-password", agent_id="agent-db")
        assert value == "super-secret-db-pass"

    @pytest.mark.asyncio
    async def test_denies_unpermitted_agent(self, broker):
        with pytest.raises(SecretAccessDeniedError):
            await broker.retrieve("db-password", agent_id="agent-other")

    @pytest.mark.asyncio
    async def test_denies_nonexistent_secret(self, broker):
        with pytest.raises(SecretAccessDeniedError):
            await broker.retrieve("nonexistent-secret", agent_id="agent-db")

    @pytest.mark.asyncio
    async def test_denies_empty_agent_id(self, broker):
        with pytest.raises(SecretAccessDeniedError):
            await broker.retrieve("db-password", agent_id="")

    @pytest.mark.asyncio
    async def test_multiple_agents_for_same_secret(self, broker):
        v1 = await broker.retrieve("api-token", agent_id="agent-api")
        v2 = await broker.retrieve("api-token", agent_id="agent-db")
        assert v1 == v2

    @pytest.mark.asyncio
    async def test_check_permission_permitted(self, broker):
        assert await broker.check_permission("db-password", "agent-db") is True

    @pytest.mark.asyncio
    async def test_check_permission_denied(self, broker):
        assert await broker.check_permission("db-password", "agent-other") is False

    @pytest.mark.asyncio
    async def test_wildcard_permission(self):
        provider = MockSecretProvider(secrets={"shared": "value"})
        broker = SecretBroker(provider=provider, permitted_secrets={"shared": ["*"]})
        value = await broker.retrieve("shared", agent_id="any-agent")
        assert value == "value"
