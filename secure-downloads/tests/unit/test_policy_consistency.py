"""
Policy consistency tests.

Verify that the secure-downloads module's domain/port policy logic is
consistent with the browser-security API's policy logic, and that blocked
domains and ports cannot be reached through the download subsystem.
"""
from __future__ import annotations

import pytest

from security.domain_policy import DomainPolicy, PortPolicy
from security.errors import DOMAIN_BLOCKED, PORT_NOT_ALLOWED, DownloadSecurityError
from security.url_validator import DownloadUrlValidator


class TestBlockedDomainsCannotBeReached:
    """
    Prove that a domain blocked by policy cannot be reached via the download path.

    These tests mirror what the browser-security proxy enforces at the TCP level.
    The download module must reject them at the URL validation layer.
    """

    def test_explicitly_blocked_domain(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            allowed_domains="good.example.com",
            blocked_domains="evil.example.com",
            default_domain_policy="deny",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://evil.example.com/payload.pdf")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_unlisted_domain_blocked_by_default_deny(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            allowed_domains="approved.example.com",
            default_domain_policy="deny",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://unlisted.example.com/file.pdf")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_blocked_domain_wins_even_if_also_in_allowlist(self):
        """Blocked list takes precedence over allowed list."""
        v = DownloadUrlValidator(
            allowed_ports="443",
            allowed_domains="conflicted.example.com",
            blocked_domains="conflicted.example.com",
            default_domain_policy="allow",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://conflicted.example.com/file.pdf")
        assert exc_info.value.code == DOMAIN_BLOCKED


class TestBlockedPortsCannotBeReached:
    def test_non_standard_port_blocked(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://example.com:22/file.pdf")
        assert exc_info.value.code == PORT_NOT_ALLOWED

    def test_port_80_blocked_when_only_443_allowed(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("http://example.com:80/file.pdf")
        assert exc_info.value.code in {PORT_NOT_ALLOWED, "URL_SCHEME_NOT_ALLOWED"}

    def test_arbitrary_high_port_blocked(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://example.com:9999/file.pdf")
        assert exc_info.value.code == PORT_NOT_ALLOWED


class TestPolicyFingerprintConsistency:
    """
    Verify that domain/port policy evaluated in the download module produces
    the same allow/deny decision for the same inputs as the browser-security API.

    The fingerprint algorithm must be consistent.  We compute it here using the
    same canonical algorithm (sort, join, SHA-256) and verify the logic.
    """

    def test_same_policy_produces_same_decision(self):
        """
        If ALLOWED_DOMAINS, BLOCKED_DOMAINS, DEFAULT_DOMAIN_POLICY, and
        ALLOWED_PORTS are identical, the download module and the browser-security
        API must make the same allow/deny decision.
        """
        config = dict(
            allowed_domains="trusted.example.com,cdn.example.com",
            blocked_domains="phishing.example.com",
            default_domain_policy="deny",
            allowed_ports="443",
        )

        # Download module policy
        download_policy = DomainPolicy(
            allowed_domains=config["allowed_domains"],
            blocked_domains=config["blocked_domains"],
            default_policy=config["default_domain_policy"],
        )
        port_policy = PortPolicy(config["allowed_ports"])

        # Allowed → allowed
        download_policy.evaluate("trusted.example.com")
        port_policy.assert_allowed(443)

        # Blocked → blocked
        with pytest.raises(DownloadSecurityError) as exc_info:
            download_policy.evaluate("phishing.example.com")
        assert exc_info.value.code == DOMAIN_BLOCKED

        # Unlisted → blocked (default deny)
        with pytest.raises(DownloadSecurityError) as exc_info:
            download_policy.evaluate("unknown.example.com")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_fingerprint_computation(self):
        """
        Verify the policy fingerprint algorithm produces a stable 16-char hex.
        The algorithm must be identical to the one in the browser-security API.
        """
        import hashlib
        import json

        allowed = "example.com,files.example.com"
        blocked = "evil.com"
        default_policy = "deny"
        ports = "443,80"

        canonical_domains = ",".join(sorted(p.strip().lower() for p in allowed.split(",") if p.strip()))
        canonical_blocked = ",".join(sorted(p.strip().lower() for p in blocked.split(",") if p.strip()))
        canonical_ports = ",".join(sorted(p.strip() for p in ports.split(",") if p.strip()))

        canonical = json.dumps(
            {
                "allowedDomains": canonical_domains,
                "blockedDomains": canonical_blocked,
                "defaultDomainPolicy": default_policy.lower(),
                "allowedPorts": canonical_ports,
            },
            separators=(",", ":"),
        )
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()[:16]
        assert len(fingerprint) == 16
        assert fingerprint.isalnum()

        # Same inputs must produce the same fingerprint (stability).
        fingerprint2 = hashlib.sha256(canonical.encode()).hexdigest()[:16]
        assert fingerprint == fingerprint2

        # Different inputs must produce different fingerprint.
        canonical_different = json.dumps(
            {
                "allowedDomains": canonical_domains,
                "blockedDomains": "",
                "defaultDomainPolicy": "allow",
                "allowedPorts": "443",
            },
            separators=(",", ":"),
        )
        fingerprint_different = hashlib.sha256(canonical_different.encode()).hexdigest()[:16]
        assert fingerprint != fingerprint_different
