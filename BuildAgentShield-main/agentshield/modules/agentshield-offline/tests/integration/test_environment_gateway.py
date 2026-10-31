"""
Integration tests — Environment Protection Gateway.
"""

from __future__ import annotations

import pytest

from app.core.contracts import (
    EnvironmentInspectRequest,
    ResponseStatus,
    SecretAccessRequest,
    SecurityDecision,
)


class TestEnvironmentGatewayIntegration:
    @pytest.mark.asyncio
    async def test_allows_permitted_variable(self, environment_gateway):
        req = EnvironmentInspectRequest(
            agent_id="test-agent",
            tool_name="environment_inspect",
            operation="inspect",
            variable_names=["TZ", "LANG"],
        )
        resp = await environment_gateway.inspect(req)
        assert resp.decision == SecurityDecision.ALLOW
        assert "TZ" in resp.result["allowed_variables"]
        assert "LANG" in resp.result["allowed_variables"]

    @pytest.mark.asyncio
    async def test_denies_sensitive_variable(self, environment_gateway):
        req = EnvironmentInspectRequest(
            agent_id="test-agent",
            tool_name="environment_inspect",
            operation="inspect",
            variable_names=["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY"],
        )
        resp = await environment_gateway.inspect(req)
        assert resp.decision == SecurityDecision.ALLOW  # response always returned
        # But the variables should be in denied list
        denied = resp.result["denied_variables"]
        assert "OPENAI_API_KEY" in denied
        assert "AWS_SECRET_ACCESS_KEY" in denied

    @pytest.mark.asyncio
    async def test_response_never_includes_values(self, environment_gateway):
        """The response must never contain actual variable values."""
        req = EnvironmentInspectRequest(
            agent_id="test-agent",
            tool_name="environment_inspect",
            operation="inspect",
            variable_names=["TZ", "OPENAI_API_KEY"],
        )
        resp = await environment_gateway.inspect(req)
        # Check that no values appear in the result
        result_str = str(resp.result)
        # Should not contain any actual env var values from the host
        import os
        tz_value = os.environ.get("TZ", "")
        if tz_value:
            assert tz_value not in result_str

    @pytest.mark.asyncio
    async def test_retrieves_permitted_secret(self, environment_gateway):
        req = SecretAccessRequest(
            agent_id="test-agent",
            tool_name="secret_access",
            operation="retrieve",
            secret_id="test-secret",
            purpose="unit test",
        )
        resp = await environment_gateway.access_secret(req)
        assert resp.decision == SecurityDecision.ALLOW
        assert resp.result["retrieved"] is True
        # Secret value must NOT be in the response
        assert "test-value-123" not in str(resp.result)

    @pytest.mark.asyncio
    async def test_denies_unpermitted_secret(self, environment_gateway):
        req = SecretAccessRequest(
            agent_id="other-agent",
            tool_name="secret_access",
            operation="retrieve",
            secret_id="test-secret",
            purpose="unauthorized attempt",
        )
        resp = await environment_gateway.access_secret(req)
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.asyncio
    async def test_denies_nonexistent_secret(self, environment_gateway):
        req = SecretAccessRequest(
            agent_id="test-agent",
            tool_name="secret_access",
            operation="retrieve",
            secret_id="nonexistent-secret-xyz",
        )
        resp = await environment_gateway.access_secret(req)
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.asyncio
    async def test_mixed_allowed_denied_variables(self, environment_gateway):
        req = EnvironmentInspectRequest(
            agent_id="test-agent",
            tool_name="environment_inspect",
            operation="inspect",
            variable_names=["TZ", "OPENAI_API_KEY", "LANG", "DATABASE_URL"],
        )
        resp = await environment_gateway.inspect(req)
        allowed = set(resp.result["allowed_variables"])
        denied = set(resp.result["denied_variables"].keys())
        assert "TZ" in allowed
        assert "LANG" in allowed
        assert "OPENAI_API_KEY" in denied
        assert "DATABASE_URL" in denied
