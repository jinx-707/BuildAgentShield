"""Tests for domain and port policy."""
from __future__ import annotations

import pytest

from security.domain_policy import DomainPolicy, PortPolicy
from security.errors import DOMAIN_BLOCKED, PORT_NOT_ALLOWED, DownloadSecurityError


class TestDomainPolicy:
    def test_allowed_domain_passes(self):
        policy = DomainPolicy(allowed_domains="example.com", default_policy="deny")
        policy.evaluate("example.com")  # Should not raise

    def test_subdomain_not_matched_by_apex(self):
        """Apex 'example.com' should NOT match 'sub.example.com'."""
        policy = DomainPolicy(allowed_domains="example.com", default_policy="deny")
        with pytest.raises(DownloadSecurityError) as exc_info:
            policy.evaluate("sub.example.com")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_wildcard_matches_subdomain(self):
        policy = DomainPolicy(allowed_domains="*.example.com", default_policy="deny")
        policy.evaluate("cdn.example.com")  # Should not raise

    def test_wildcard_does_not_match_apex(self):
        """*.example.com should not match example.com itself."""
        policy = DomainPolicy(allowed_domains="*.example.com", default_policy="deny")
        with pytest.raises(DownloadSecurityError):
            policy.evaluate("example.com")

    def test_blocked_list_wins_over_allowed(self):
        policy = DomainPolicy(
            allowed_domains="evil.com",
            blocked_domains="evil.com",
            default_policy="allow",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            policy.evaluate("evil.com")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_default_deny_blocks_unlisted(self):
        policy = DomainPolicy(default_policy="deny")
        with pytest.raises(DownloadSecurityError) as exc_info:
            policy.evaluate("unlisted.com")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_default_allow_passes_unlisted(self):
        policy = DomainPolicy(default_policy="allow")
        policy.evaluate("anything.com")  # Should not raise

    def test_invalid_default_policy_raises(self):
        with pytest.raises(ValueError):
            DomainPolicy(default_policy="maybe")

    def test_standalone_wildcard_rejected(self):
        with pytest.raises(ValueError, match="standalone wildcard"):
            DomainPolicy(allowed_domains="*", default_policy="deny")


class TestPortPolicy:
    def test_443_allowed_by_default(self):
        policy = PortPolicy("443")
        policy.assert_allowed(443)

    def test_80_blocked_when_not_in_spec(self):
        policy = PortPolicy("443")
        with pytest.raises(DownloadSecurityError) as exc_info:
            policy.assert_allowed(80)
        assert exc_info.value.code == PORT_NOT_ALLOWED

    def test_port_range_allowed(self):
        policy = PortPolicy("8080-8090")
        policy.assert_allowed(8085)

    def test_port_range_boundary(self):
        policy = PortPolicy("8080-8090")
        policy.assert_allowed(8080)
        policy.assert_allowed(8090)

    def test_port_outside_range_blocked(self):
        policy = PortPolicy("8080-8090")
        with pytest.raises(DownloadSecurityError):
            policy.assert_allowed(8091)

    def test_multiple_ports(self):
        policy = PortPolicy("80,443,8080")
        policy.assert_allowed(80)
        policy.assert_allowed(443)
        policy.assert_allowed(8080)

    def test_invalid_port_spec_raises(self):
        with pytest.raises((ValueError, Exception)):
            PortPolicy("notaport")
