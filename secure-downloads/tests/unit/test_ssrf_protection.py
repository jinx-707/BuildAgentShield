"""Tests for SSRF and DNS protection."""
from __future__ import annotations

import pytest

from security.errors import PRIVATE_IP_BLOCKED, DownloadSecurityError
from security.ssrf import SsrfGuard
from security.url_validator import DownloadUrlValidator
from tests.conftest import FakeDnsResolver


def make_validator(**kwargs) -> DownloadUrlValidator:
    defaults = dict(
        allowed_ports="443",
        allowed_domains="trusted.example.com",
        default_domain_policy="deny",
        allow_private_networks=False,
        https_only=True,
    )
    defaults.update(kwargs)
    return DownloadUrlValidator(**defaults)


@pytest.fixture
def dns():
    return FakeDnsResolver()


@pytest.fixture
def guard(dns):
    return SsrfGuard(resolver=dns, allow_private_networks=False)


class TestDnsResolutionBlocking:
    async def test_resolves_to_private_ip_blocked(self, guard):
        dns = FakeDnsResolver({"trusted.example.com": ["192.168.1.100"]})
        g = SsrfGuard(resolver=dns, allow_private_networks=False)
        v = make_validator()
        validated = v.validate("https://trusted.example.com/file.pdf")
        with pytest.raises(DownloadSecurityError) as exc_info:
            await g.resolve_and_validate(validated)
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_resolves_to_loopback_blocked(self, guard):
        dns = FakeDnsResolver({"trusted.example.com": ["127.0.0.1"]})
        g = SsrfGuard(resolver=dns, allow_private_networks=False)
        v = make_validator()
        validated = v.validate("https://trusted.example.com/file.pdf")
        with pytest.raises(DownloadSecurityError) as exc_info:
            await g.resolve_and_validate(validated)
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_resolves_to_cloud_metadata_blocked(self, guard):
        dns = FakeDnsResolver({"trusted.example.com": ["169.254.169.254"]})
        g = SsrfGuard(resolver=dns, allow_private_networks=False)
        v = make_validator()
        validated = v.validate("https://trusted.example.com/file.pdf")
        with pytest.raises(DownloadSecurityError) as exc_info:
            await g.resolve_and_validate(validated)
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_any_address_in_list_blocked(self, guard):
        """If any returned address is blocked, the entire request is rejected."""
        dns = FakeDnsResolver(
            {"trusted.example.com": ["93.184.216.34", "10.0.0.1"]}
        )
        g = SsrfGuard(resolver=dns, allow_private_networks=False)
        v = make_validator()
        validated = v.validate("https://trusted.example.com/file.pdf")
        with pytest.raises(DownloadSecurityError) as exc_info:
            await g.resolve_and_validate(validated)
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_clean_public_ip_passes(self, guard):
        dns = FakeDnsResolver({"trusted.example.com": ["93.184.216.34"]})
        g = SsrfGuard(resolver=dns, allow_private_networks=False)
        v = make_validator()
        validated = v.validate("https://trusted.example.com/file.pdf")
        resolved = await g.resolve_and_validate(validated)
        assert "93.184.216.34" in resolved.addresses


class TestPreflightRejectsBlockedResolution:
    async def test_blocked_answer_rejected_at_preflight(self):
        """
        The preflight guard rejects a hostname whose answer contains a blocked
        address.

        This is not a rebinding test: the SsrfGuard performs one lookup per
        call and stores nothing between calls, so what it proves here is only
        that a blocked answer at preflight time stops the download before any
        network activity.  The rebinding sequence — different answers across
        successive lookups — is covered by tests/unit/test_dns_revalidation.py
        and, against a real socket, by tests/integration/test_downloader_http.py.
        """
        # Attacker controls DNS: resolves to private IP at SSRF check time.
        malicious_dns = FakeDnsResolver({"rebind.attacker.com": ["10.0.0.5"]})
        v = DownloadUrlValidator(
            allowed_ports="443",
            allowed_domains="rebind.attacker.com",
            default_domain_policy="deny",
            allow_private_networks=False,
        )
        g = SsrfGuard(resolver=malicious_dns, allow_private_networks=False)
        validated = v.validate("https://rebind.attacker.com/secret")
        with pytest.raises(DownloadSecurityError) as exc_info:
            await g.resolve_and_validate(validated)
        assert exc_info.value.code == PRIVATE_IP_BLOCKED


class TestRedirectValidation:
    async def test_redirect_to_private_ip_blocked(self):
        from security.preflight import DownloadPreflight

        v = DownloadUrlValidator(
            allowed_ports="443",
            allowed_domains="trusted.example.com,evil.example.com",
            default_domain_policy="deny",
        )
        dns = FakeDnsResolver(
            {
                "trusted.example.com": ["93.184.216.34"],
                "evil.example.com": ["10.0.0.1"],
            }
        )
        g = SsrfGuard(resolver=dns, allow_private_networks=False)
        preflight = DownloadPreflight(url_validator=v, ssrf_guard=g, dns_enabled=True)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await preflight.validate("https://evil.example.com/file.pdf")
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_redirect_revalidation_via_ssrf_guard(self):
        from security.url_validator import DownloadUrlValidator as DUV

        v = DUV(
            allowed_ports="443",
            allowed_domains="trusted.example.com",
            default_domain_policy="deny",
        )
        dns = FakeDnsResolver({"internal.corp": ["10.0.0.1"]})
        g = SsrfGuard(resolver=dns, allow_private_networks=False)

        validated = v.validate("https://trusted.example.com/file.pdf")
        # Simulate validating a redirect to an internal host.
        with pytest.raises(DownloadSecurityError):
            await g.validate_redirect("https://internal.corp/admin", validator=v)


class TestLiteralIpTargets:
    async def test_literal_private_ip_rejected_without_dns(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
            allow_private_networks=False,
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://10.0.0.1/secret")
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    async def test_literal_public_ip_with_policy_allow(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
            allow_private_networks=False,
        )
        result = v.validate("https://93.184.216.34/file.pdf")
        assert result.is_ip is True
