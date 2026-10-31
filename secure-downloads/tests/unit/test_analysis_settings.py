"""Fail-closed validation for document-analysis provider configuration."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from config.settings import Settings, security_issues


NON_PROD = dict(
    environment="test",
    api_auth_token="token",
    database_url="sqlite+aiosqlite:///:memory:",
    egress_proxy_url="",
    egress_proxy_health_url="",
    require_egress_proxy=False,
    allowed_domains="files.example.com",
    default_domain_policy="deny",
    dns_preflight_enabled=True,
    allow_private_networks=False,
)


def make(**overrides) -> Settings:
    return Settings(_env_file=None, **{**NON_PROD, **overrides})


def make_prod(**overrides) -> Settings:
    base = {
        **NON_PROD,
        "environment": "production",
        "egress_proxy_url": "http://proxy.internal:3128",
        "egress_proxy_health_url": "http://proxy.internal:3128/health",
        "require_egress_proxy": True,
        "analysis_provider": "http",
        "analysis_endpoint_url": "https://analysis.example.com/v1/analyze",
        "analysis_api_token": "analysis-secret-token",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


class TestProviderSelection:
    def test_disabled_is_the_default(self):
        settings = make()
        assert settings.analysis_provider == "disabled"

    def test_local_mock_builds_outside_production(self):
        assert make(analysis_provider="local_mock").analysis_provider == "local_mock"

    def test_unknown_provider_rejected(self):
        with pytest.raises(ValidationError, match="ANALYSIS_PROVIDER"):
            make(analysis_provider="vendor-x")

    def test_production_refuses_mock_and_disabled(self):
        with pytest.raises(ValidationError, match="ANALYSIS_PROVIDER must be 'http'"):
            make_prod(
                analysis_provider="local_mock",
                analysis_endpoint_url="",
                analysis_api_token="",
            )
        with pytest.raises(ValidationError, match="ANALYSIS_PROVIDER must be 'http'"):
            make_prod(
                analysis_provider="disabled",
                analysis_endpoint_url="",
                analysis_api_token="",
            )


class TestHttpConfiguration:
    def test_endpoint_required(self):
        with pytest.raises(ValidationError, match="ANALYSIS_ENDPOINT_URL"):
            make(
                analysis_provider="http",
                analysis_api_token="secret",
                analysis_endpoint_url="",
            )

    def test_token_required(self):
        with pytest.raises(ValidationError, match="ANALYSIS_API_TOKEN"):
            make(
                analysis_provider="http",
                analysis_endpoint_url="https://analysis.example.com/v1/analyze",
                analysis_api_token="",
            )

    def test_plain_http_rejected_without_local_escape_hatch(self):
        with pytest.raises(ValidationError, match="must use https"):
            make(
                analysis_provider="http",
                analysis_endpoint_url="http://analysis.example.com/v1/analyze",
                analysis_api_token="secret",
            )

    def test_plain_http_allowed_for_loopback_with_flag(self):
        settings = make(
            analysis_provider="http",
            analysis_endpoint_url="http://127.0.0.1:8080/analyze",
            analysis_api_token="secret",
            analysis_allow_insecure_local=True,
            analysis_allow_private_endpoints=True,
        )
        assert settings.analysis_endpoint_url.startswith("http://127.0.0.1")

    def test_plain_http_loopback_requires_insecure_flag(self):
        with pytest.raises(ValidationError, match="must use https"):
            make(
                analysis_provider="http",
                analysis_endpoint_url="http://127.0.0.1:8080/analyze",
                analysis_api_token="secret",
            )

    def test_plain_http_non_loopback_rejected_even_with_flag(self):
        with pytest.raises(ValidationError, match="loopback"):
            make(
                analysis_provider="http",
                analysis_endpoint_url="http://analysis.example.com/analyze",
                analysis_api_token="secret",
                analysis_allow_insecure_local=True,
            )

    def test_credentials_in_url_rejected(self):
        with pytest.raises(ValidationError, match="must not embed credentials"):
            make(
                analysis_provider="http",
                analysis_endpoint_url="https://user:pass@analysis.example.com/v1/analyze",
                analysis_api_token="secret",
            )

    def test_dead_provider_configuration_rejected(self):
        with pytest.raises(ValidationError, match="ANALYSIS_ENDPOINT_URL"):
            make(
                analysis_provider="disabled",
                analysis_endpoint_url="https://analysis.example.com/v1/analyze",
                analysis_api_token="secret",
            )


class TestProductionEgressPolicy:
    def test_mock_escape_hatches_rejected(self):
        with pytest.raises(ValidationError, match="ANALYSIS_ALLOW_INSECURE_LOCAL"):
            make_prod(analysis_allow_insecure_local=True)
        with pytest.raises(ValidationError, match="ANALYSIS_ALLOW_PRIVATE_ENDPOINTS"):
            make_prod(analysis_allow_private_endpoints=True)

    def test_analysis_must_use_egress_proxy(self):
        with pytest.raises(ValidationError, match="ANALYSIS_USE_EGRESS_PROXY"):
            make_prod(analysis_use_egress_proxy=False)

    def test_full_production_configuration_builds(self):
        settings = make_prod()
        assert settings.analysis_provider == "http"
        assert security_issues(settings) == []


class TestSecurityIssues:
    def test_local_mock_is_flagged(self):
        settings = make(analysis_provider="local_mock")
        assert any("local_mock" in issue for issue in security_issues(settings))

    def test_bypassing_egress_proxy_is_flagged(self):
        settings = make(
            analysis_provider="http",
            analysis_endpoint_url="https://analysis.example.com/v1/analyze",
            analysis_api_token="secret",
            egress_proxy_url="http://proxy.internal:3128",
            egress_proxy_health_url="http://proxy.internal:3128/health",
            analysis_use_egress_proxy=False,
        )
        assert any(
            "ANALYSIS_USE_EGRESS_PROXY" in issue for issue in security_issues(settings)
        )

    def test_insecure_local_endpoint_is_flagged(self):
        settings = make(
            analysis_provider="http",
            analysis_endpoint_url="http://127.0.0.1:8080/analyze",
            analysis_api_token="secret",
            analysis_allow_insecure_local=True,
            analysis_allow_private_endpoints=True,
        )
        joined = " ".join(security_issues(settings))
        assert "ANALYSIS_ALLOW_INSECURE_LOCAL" in joined
        assert "ANALYSIS_ALLOW_PRIVATE_ENDPOINTS" in joined
