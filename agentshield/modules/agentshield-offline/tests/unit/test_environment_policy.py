"""
Unit tests — Environment variable policy.
"""

from __future__ import annotations

import pytest

from app.capabilities.offline.environment.environment_policy import EnvironmentPolicy


@pytest.fixture
def policy_with_allowlist():
    """Policy with an explicit allowlist."""
    p = EnvironmentPolicy.__new__(EnvironmentPolicy)
    p._global_allowlist = {"TZ", "LANG", "PYTHONPATH", "HOME"}
    p._global_denylist = set()
    p._agent_configs = {}
    return p


@pytest.fixture
def policy_no_allowlist():
    """Policy with no allowlist — deny by default."""
    p = EnvironmentPolicy.__new__(EnvironmentPolicy)
    p._global_allowlist = set()
    p._global_denylist = set()
    p._agent_configs = {}
    return p


class TestEnvironmentPolicy:
    # --- Always-denied secrets ---
    def test_denies_openai_key(self, policy_with_allowlist):
        allowed, reason = policy_with_allowlist.is_allowed("OPENAI_API_KEY")
        assert not allowed
        assert "denylist" in reason.lower() or "unconditional" in reason.lower()

    def test_denies_aws_secret(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("AWS_SECRET_ACCESS_KEY")
        assert not allowed

    def test_denies_github_token(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("GITHUB_TOKEN")
        assert not allowed

    def test_denies_database_url(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("DATABASE_URL")
        assert not allowed

    def test_denies_jwt_secret(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("JWT_SECRET")
        assert not allowed

    # --- Sensitive patterns ---
    def test_denies_custom_password_var(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("MY_APP_PASSWORD")
        assert not allowed

    def test_denies_custom_token_var(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("STRIPE_API_TOKEN")
        assert not allowed

    def test_denies_anything_with_secret(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("APP_SECRET_STUFF")
        assert not allowed

    # --- Allowlist behavior ---
    def test_allows_tz(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("TZ")
        assert allowed

    def test_allows_lang(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("LANG")
        assert allowed

    def test_denies_unlisted_var(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("SOME_RANDOM_VAR")
        assert not allowed

    # --- No allowlist — deny by default ---
    def test_deny_by_default_no_allowlist(self, policy_no_allowlist):
        allowed, _ = policy_no_allowlist.is_allowed("TZ")
        assert not allowed

    def test_deny_by_default_with_random_var(self, policy_no_allowlist):
        allowed, _ = policy_no_allowlist.is_allowed("FOOBAR")
        assert not allowed

    # --- Case insensitivity ---
    def test_case_insensitive_deny(self, policy_with_allowlist):
        allowed, _ = policy_with_allowlist.is_allowed("openai_api_key")
        assert not allowed
