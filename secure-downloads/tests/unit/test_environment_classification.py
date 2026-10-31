"""
F3 regression: environment classification must fail closed.

Rules (config/settings.py):
* ENVIRONMENT is normalized (strip + case-fold) and mapped to one of the
  canonical values: development, test, staging, production.
* Empty, whitespace-only, unknown, and missing values raise ValidationError —
  nothing is silently treated as "development".
* "production" and "staging" (and their aliases prod/stage/preprod/...)
  enforce the full production security policy.
* "development" (dev/local) and "test" keep the documented flexibility.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from config.settings import (
    ENVIRONMENT_ALIASES,
    PRODUCTION_LIKE_ENVIRONMENTS,
    Settings,
    classify_environment,
    security_issues,
)

PROD_BASE = dict(
    api_auth_token="secret-token",
    database_url="sqlite+aiosqlite:///:memory:",
    egress_proxy_url="http://proxy.internal:3128",
    egress_proxy_health_url="http://proxy.internal:9090/health/ready",
    require_egress_proxy=True,
    allowed_domains="files.example.com",
    blocked_domains="",
    default_domain_policy="deny",
    allowed_ports="443",
    allow_private_networks=False,
    dns_preflight_enabled=True,
    # Production-like environments require a real analysis provider on the
    # attested egress path; these tests build a fully valid production config.
    analysis_provider="http",
    analysis_endpoint_url="https://analysis.example.com/v1/analyze",
    analysis_api_token="analysis-token",
    analysis_use_egress_proxy=True,
)


def make(**overrides) -> Settings:
    return Settings(_env_file=None, **{**PROD_BASE, **overrides})


class TestNormalization:
    @pytest.mark.parametrize(
        "raw,canonical",
        [
            ("production", "production"),
            ("prod", "production"),
            ("PROD", "production"),
            ("  Production  ", "production"),
            ("staging", "staging"),
            ("Stage", "staging"),
            ("PREPROD", "staging"),
            ("pre-production", "staging"),
            ("development", "development"),
            ("Dev", "development"),
            ("LOCAL", "development"),
            ("test", "test"),
            ("Tests", "test"),
        ],
    )
    def test_values_map_to_canonical_form(self, raw, canonical):
        assert classify_environment(raw) == canonical

    def test_settings_stores_the_canonical_value(self):
        settings = make(environment="  PROD ")
        assert settings.environment == "production"
        assert settings.is_production_like is True


class TestUnknownAndMissingFailClosed:
    @pytest.mark.parametrize("raw", ["", "   ", "qa", "prodction", "prodctionn", "stagin", "productionn"])
    def test_empty_or_unknown_values_are_rejected(self, raw):
        with pytest.raises(ValueError):
            classify_environment(raw)

    def test_empty_environment_string_raises_validation_error(self):
        with pytest.raises(ValidationError, match="ENVIRONMENT"):
            make(environment="")

    def test_unknown_environment_raises_not_silently_development(self):
        with pytest.raises(ValidationError, match="Unrecognized ENVIRONMENT"):
            make(environment="qa")

    def test_missing_value_fails_closed(self, monkeypatch):
        """No ENVIRONMENT at all must not default into development silently."""
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        with pytest.raises(ValidationError, match="ENVIRONMENT"):
            Settings(_env_file=None)

    def test_every_alias_is_total(self):
        for alias in ENVIRONMENT_ALIASES:
            assert classify_environment(alias) == ENVIRONMENT_ALIASES[alias]


class TestProductionLikeEnforcement:
    def test_prod_alias_enforces_production_policy(self):
        with pytest.raises(ValidationError, match="EGRESS_PROXY_URL"):
            make(environment="prod", egress_proxy_url="")

    def test_uppercase_prod_enforces_production_policy(self):
        with pytest.raises(ValidationError, match="API_AUTH_TOKEN"):
            make(environment="PRODUCTION", api_auth_token="")

    def test_staging_enforces_production_policy(self):
        with pytest.raises(ValidationError, match="EGRESS_PROXY_HEALTH_URL"):
            make(environment="staging", egress_proxy_health_url="")

    def test_staging_rejects_private_networks(self):
        with pytest.raises(ValidationError, match="ALLOW_PRIVATE_NETWORKS"):
            make(environment="Stage", allow_private_networks=True)

    def test_staging_accepts_full_production_configuration(self):
        assert make(environment="stage").is_production_like is True

    def test_production_like_set_is_exact(self):
        assert PRODUCTION_LIKE_ENVIRONMENTS == frozenset({"production", "staging"})


class TestNonProductionFlexibility:
    @pytest.mark.parametrize("environment", ["development", "dev", "local", "test", "Tests"])
    def test_documented_development_exceptions_still_apply(self, environment):
        settings = Settings(
            _env_file=None,
            environment=environment,
            api_auth_token="",
            egress_proxy_url="",
            egress_proxy_health_url="",
            require_egress_proxy=False,
            allowed_domains="",
            default_domain_policy="deny",
            dns_preflight_enabled=False,
            database_url="sqlite+aiosqlite:///:memory:",
        )
        assert not settings.is_production_like


class TestSecurityIssues:
    def test_clean_configuration_has_no_issues(self):
        assert security_issues(make(environment="production")) == []

    def test_missing_auth_token_is_an_issue(self):
        issues = security_issues(make(environment="development", api_auth_token=""))
        assert any("API_AUTH_TOKEN" in i for i in issues)

    def test_required_proxy_without_url_is_an_issue(self):
        issues = security_issues(
            make(
                environment="development",
                api_auth_token="t",
                egress_proxy_url="",
                require_egress_proxy=True,
            )
        )
        assert any("EGRESS_PROXY_URL" in i for i in issues)

    def test_proxy_without_health_url_is_an_issue(self):
        issues = security_issues(
            make(
                environment="development",
                api_auth_token="t",
                egress_proxy_url="http://p:3128",
                egress_proxy_health_url="",
            )
        )
        assert any("EGRESS_PROXY_HEALTH_URL" in i for i in issues)

    def test_issues_never_contain_secret_values(self):
        settings = make(
            environment="development",
            api_auth_token="s3cr3t-value",
            egress_proxy_url="",
            dns_preflight_enabled=False,
            allow_private_networks=True,
            allowed_domains="",
        )
        for issue in security_issues(settings):
            assert "s3cr3t-value" not in issue
