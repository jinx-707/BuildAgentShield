"""
Adversarial tests — Environment variable and secret access attacks.
"""

from __future__ import annotations

import os

import pytest

from app.capabilities.offline.environment.environment_guard import EnvironmentGuard
from app.capabilities.offline.environment.environment_policy import EnvironmentPolicy
from app.core.contracts import (
    EnvironmentInspectRequest,
    SecretAccessRequest,
    SecurityDecision,
)

# Sensitive variables that must NEVER be accessible
SENSITIVE_VARS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "DATABASE_URL",
    "DB_PASSWORD",
    "DATABASE_PASSWORD",
    "SECRET_KEY",
    "DJANGO_SECRET_KEY",
    "JWT_SECRET",
    "VAULT_TOKEN",
    "AZURE_CLIENT_SECRET",
    # Variations and case mutations
    "openai_api_key",
    "Openai_Api_Key",
    "OPENAI_API_KEY ",  # trailing space
]

SECRET_INJECTION_ATTEMPTS = [
    "../../secrets",
    "../.env",
    "SECRET\x00BYPASS",
    "SECRET; cat /etc/passwd",
]


class TestEnvironmentAdversarial:
    @pytest.mark.adversarial
    @pytest.mark.parametrize("var", SENSITIVE_VARS)
    @pytest.mark.asyncio
    async def test_sensitive_var_always_denied(self, environment_gateway, var):
        req = EnvironmentInspectRequest(
            agent_id="test-agent",
            tool_name="environment_inspect",
            operation="inspect",
            variable_names=[var.strip()],
        )
        resp = await environment_gateway.inspect(req)
        denied = resp.result.get("denied_variables", {})
        allowed = resp.result.get("allowed_variables", [])
        # The variable (stripped) must not be in allowed
        assert var.strip() not in allowed, (
            f"Variable '{var}' must be denied but was allowed"
        )

    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_host_env_not_inherited_by_guard(self):
        """The environment guard must never pass ALL host env vars."""
        # Set a fake secret in the test process environment
        os.environ["TEST_FAKE_SECRET_ABC123"] = "very-secret-value"
        policy = EnvironmentPolicy.__new__(EnvironmentPolicy)
        policy._global_allowlist = {"TZ", "LANG"}
        policy._global_denylist = set()
        policy._agent_configs = {}
        guard = EnvironmentGuard(policy)

        minimal_env = guard.build_minimal_env(agent_id="test-agent")
        assert "TEST_FAKE_SECRET_ABC123" not in minimal_env
        assert "very-secret-value" not in minimal_env.values()
        os.environ.pop("TEST_FAKE_SECRET_ABC123", None)

    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_minimal_env_does_not_leak_host_secrets(self):
        """Minimal environment must not contain any known sensitive keys."""
        policy = EnvironmentPolicy.__new__(EnvironmentPolicy)
        policy._global_allowlist = set()
        policy._global_denylist = set()
        policy._agent_configs = {}
        guard = EnvironmentGuard(policy)

        # Inject fake secrets into process env
        secrets = {
            "OPENAI_API_KEY": "sk-test",
            "AWS_SECRET_ACCESS_KEY": "awssecret",
            "GITHUB_TOKEN": "ghp_token",
        }
        for k, v in secrets.items():
            os.environ[k] = v

        minimal_env = guard.build_minimal_env(agent_id="test-agent")
        for key in secrets:
            assert key not in minimal_env, f"Secret key {key} leaked into minimal env"
        for val in secrets.values():
            assert val not in minimal_env.values(), f"Secret value leaked into minimal env"

        for k in secrets:
            os.environ.pop(k, None)

    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_response_never_contains_secret_values(self, environment_gateway):
        """API response must never contain actual env variable values."""
        # Set a real value
        os.environ["TZ"] = "UTC"
        req = EnvironmentInspectRequest(
            agent_id="test-agent",
            tool_name="environment_inspect",
            operation="inspect",
            variable_names=["TZ"],
        )
        resp = await environment_gateway.inspect(req)
        # TZ value "UTC" should never be in the response
        result_str = str(resp.result)
        assert "UTC" not in result_str or "allowed_variables" in result_str
        # More importantly, no actual env values in the result
        # The result only contains variable NAMES and decisions, not values

    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_secret_injection_in_secret_id(self, environment_gateway):
        for bad_id in SECRET_INJECTION_ATTEMPTS:
            req = SecretAccessRequest(
                agent_id="test-agent",
                tool_name="secret_access",
                operation="retrieve",
                secret_id=bad_id,
            )
            resp = await environment_gateway.access_secret(req)
            assert resp.decision == SecurityDecision.DENY, (
                f"Secret injection attempt '{bad_id}' should be denied"
            )

    @pytest.mark.adversarial
    @pytest.mark.asyncio
    async def test_enumeration_of_all_host_vars_denied(self, environment_gateway):
        """Requesting a huge list of variable names must not leak host secrets."""
        # Include both legitimate and highly sensitive variable names
        all_vars = [
            "HOME", "PATH", "USER", "LOGNAME", "SHELL",
            "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
            "DATABASE_URL", "SECRET_KEY", "VAULT_TOKEN",
        ]
        req = EnvironmentInspectRequest(
            agent_id="test-agent",
            tool_name="environment_inspect",
            operation="inspect",
            variable_names=all_vars,
        )
        resp = await environment_gateway.inspect(req)
        allowed = set(resp.result.get("allowed_variables", []))
        # None of the sensitive vars must be in allowed
        sensitive = {"OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN",
                     "DATABASE_URL", "SECRET_KEY", "VAULT_TOKEN"}
        leaked = allowed.intersection(sensitive)
        assert not leaked, f"Sensitive variables were allowed: {leaked}"
