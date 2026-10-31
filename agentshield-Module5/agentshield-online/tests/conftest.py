"""
Shared test fixtures.
All tests use mocks — no real network calls, no real payments, no real emails.
"""
from __future__ import annotations

import asyncio
import os
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

# Set test environment before importing app
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("PAYMENT_MODE", "test")
os.environ.setdefault("LOCAL_AUTH_ENABLED", "true")
os.environ.setdefault("LOCAL_DEV_API_KEY", "test-key")
os.environ.setdefault("CLAMAV_ENABLED", "false")
os.environ.setdefault("SEARCH_PROVIDER", "mock")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_agentshield.db")

from app.integrations.local_security_adapter import (
    LocalContentInspectionAdapter,
    LocalDataInspectionAdapter,
)
from app.integrations.local_policy_adapter import LocalPolicyAdapter
from app.integrations.local_approval_adapter import LocalApprovalAdapter
from app.integrations.local_audit_adapter import LocalAuditAdapter
from app.integrations.secret_provider import LocalEnvSecretProvider
from app.core.security_context import build_security_context


@pytest.fixture
def content_inspector():
    return LocalContentInspectionAdapter()


@pytest.fixture
def data_inspector():
    return LocalDataInspectionAdapter()


@pytest.fixture
def policy():
    return LocalPolicyAdapter()


@pytest.fixture
def approval():
    return LocalApprovalAdapter()


@pytest.fixture
def audit():
    return LocalAuditAdapter()


@pytest.fixture
def secret_provider():
    return LocalEnvSecretProvider()


@pytest.fixture
def make_ctx():
    """Factory for SecurityContext instances."""
    def _make(
        agent_id="agent_test",
        tenant_id="tenant_test",
        capability="test",
        operation="test",
        resource=None,
    ):
        return build_security_context(
            agent_id=agent_id,
            tenant_id=tenant_id,
            capability=capability,
            operation=operation,
            resource=resource,
        )
    return _make
