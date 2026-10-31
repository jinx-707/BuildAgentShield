"""
Settings fail-closed tests: which configurations are actually permitted.

These pin down the "cannot be bypassed through supported configuration" claim
for the network controls.  In production the settings object refuses:

- direct egress (REQUIRE_EGRESS_PROXY=false, or no proxy URL);
- a proxy with no health endpoint, which would leave enforcement mode
  unattested;
- a disabled DNS preflight;
- ALLOW_PRIVATE_NETWORKS=true.

Outside production those are configuration choices, so the same values build.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from config.settings import Settings

PROD_BASE = dict(
    environment="production",
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
    analysis_provider="http",
    analysis_endpoint_url="https://analysis.example.com/v1/analyze",
    analysis_api_token="analysis-secret-token",
    analysis_use_egress_proxy=True,
)


def make_prod(**overrides) -> Settings:
    return Settings(_env_file=None, **{**PROD_BASE, **overrides})


class TestProductionFailClosed:
    def test_valid_production_configuration_builds(self):
        assert make_prod().egress_proxy_url == "http://proxy.internal:3128"

    def test_production_rejects_missing_proxy_url(self):
        with pytest.raises(ValidationError, match="EGRESS_PROXY_URL"):
            make_prod(egress_proxy_url="")

    def test_production_cannot_opt_out_of_proxy_requirement(self):
        with pytest.raises(ValidationError, match="REQUIRE_EGRESS_PROXY"):
            make_prod(require_egress_proxy=False)

    def test_production_rejects_proxy_without_health_endpoint(self):
        with pytest.raises(ValidationError, match="EGRESS_PROXY_HEALTH_URL"):
            make_prod(egress_proxy_health_url="")

    def test_production_rejects_disabled_dns_preflight(self):
        with pytest.raises(ValidationError, match="DNS_PREFLIGHT_ENABLED"):
            make_prod(dns_preflight_enabled=False)

    def test_production_rejects_private_networks(self):
        with pytest.raises(ValidationError, match="ALLOW_PRIVATE_NETWORKS"):
            make_prod(allow_private_networks=True)

    def test_production_still_requires_api_token(self):
        with pytest.raises(ValidationError, match="API_AUTH_TOKEN"):
            make_prod(api_auth_token="")


class TestNonProductionKeepsFlexibility:
    """Development and test configurations are not subject to the above."""

    @pytest.mark.parametrize("environment", ["development", "test"])
    def test_direct_egress_allowed_outside_production(self, environment):
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
        assert settings.require_egress_proxy is False
