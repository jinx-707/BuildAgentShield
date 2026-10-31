"""Tests for URL validation and SSRF protection."""
from __future__ import annotations

import pytest

from security.errors import (
    DOMAIN_BLOCKED,
    INVALID_URL,
    PORT_NOT_ALLOWED,
    PRIVATE_IP_BLOCKED,
    URL_SCHEME_NOT_ALLOWED,
    DownloadSecurityError,
)
from security.url_validator import DownloadUrlValidator


@pytest.fixture
def validator():
    return DownloadUrlValidator(
        allowed_ports="443",
        allowed_domains="example.com,files.example.com",
        blocked_domains="evil.com",
        default_domain_policy="deny",
        allow_private_networks=False,
        https_only=True,
    )


class TestValidUrls:
    def test_simple_https(self, validator):
        result = validator.validate("https://example.com/file.pdf")
        assert result.scheme == "https"
        assert result.hostname == "example.com"
        assert result.port == 443

    def test_subdomain_allowed(self, validator):
        result = validator.validate("https://files.example.com/doc.pdf")
        assert result.hostname == "files.example.com"

    def test_wildcard_subdomain(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            allowed_domains="*.trusted.com",
            default_domain_policy="deny",
        )
        result = v.validate("https://download.trusted.com/file.pdf")
        assert result.hostname == "download.trusted.com"

    def test_explicit_port_443_allowed(self, validator):
        result = validator.validate("https://example.com:443/file.pdf")
        assert result.port == 443


class TestSchemeValidation:
    def test_http_rejected_when_https_only(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("http://example.com/file.pdf")
        assert exc_info.value.code == URL_SCHEME_NOT_ALLOWED

    def test_ftp_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("ftp://example.com/file.pdf")
        assert exc_info.value.code == URL_SCHEME_NOT_ALLOWED

    def test_data_uri_rejected(self, validator):
        with pytest.raises(DownloadSecurityError):
            validator.validate("data:text/html,<h1>test</h1>")

    def test_javascript_uri_rejected(self, validator):
        with pytest.raises(DownloadSecurityError):
            validator.validate("javascript:alert(1)")

    def test_file_uri_rejected(self, validator):
        with pytest.raises(DownloadSecurityError):
            validator.validate("file:///etc/passwd")


class TestEmbeddedCredentials:
    def test_credentials_in_url_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("https://user:pass@example.com/file.pdf")
        assert exc_info.value.code == INVALID_URL

    def test_at_sign_in_netloc_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("https://attacker@example.com/file.pdf")
        assert exc_info.value.code == INVALID_URL


class TestUrlFormat:
    def test_empty_url_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("")
        assert exc_info.value.code == INVALID_URL

    def test_none_rejected(self, validator):
        with pytest.raises(DownloadSecurityError):
            validator.validate(None)  # type: ignore[arg-type]

    def test_too_long_url_rejected(self, validator):
        url = "https://example.com/" + "a" * 5000
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate(url)
        assert exc_info.value.code == INVALID_URL

    def test_backslash_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("https://example.com\\file.pdf")
        assert exc_info.value.code == INVALID_URL

    def test_control_character_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("https://example.com/\x00file.pdf")
        assert exc_info.value.code == INVALID_URL

    def test_newline_in_url_rejected(self, validator):
        with pytest.raises(DownloadSecurityError):
            validator.validate("https://example.com/\nHost: evil.com")


class TestDomainPolicy:
    def test_blocked_domain_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("https://evil.com/file.pdf")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_unlisted_domain_denied_by_default(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("https://notallowed.com/file.pdf")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_default_allow_policy_permits_unlisted(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
        )
        result = v.validate("https://anydomain.com/file.pdf")
        assert result.hostname == "anydomain.com"

    def test_blocked_domain_wins_over_allowed(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            allowed_domains="evil.com",
            blocked_domains="evil.com",
            default_domain_policy="allow",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://evil.com/file.pdf")
        assert exc_info.value.code == DOMAIN_BLOCKED


class TestPortPolicy:
    def test_non_443_port_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("https://example.com:8080/file.pdf")
        assert exc_info.value.code == PORT_NOT_ALLOWED

    def test_port_80_rejected_on_https_only(self, validator):
        # Port 80 is not in the allowed_ports="443" spec.
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("https://example.com:80/file.pdf")
        assert exc_info.value.code == PORT_NOT_ALLOWED

    def test_multiple_ports_allowed(self):
        v = DownloadUrlValidator(
            allowed_ports="443,8443",
            allowed_domains="example.com",
            default_domain_policy="deny",
        )
        v.validate("https://example.com:8443/file.pdf")


class TestPrivateIpBlocking:
    def test_loopback_literal_ip_rejected(self, validator):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
            allow_private_networks=False,
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://127.0.0.1/file.pdf")
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    def test_private_ip_192168_rejected(self, validator):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
            allow_private_networks=False,
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://192.168.1.1/file.pdf")
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    def test_cloud_metadata_ip_rejected(self, validator):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
            allow_private_networks=False,
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://169.254.169.254/latest/meta-data")
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    def test_ipv6_loopback_rejected(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
            allow_private_networks=False,
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://[::1]/file.pdf")
        assert exc_info.value.code == PRIVATE_IP_BLOCKED

    def test_ipv4_mapped_ipv6_rejected(self):
        """IPv4-mapped IPv6 ::ffff:127.0.0.1 must resolve to loopback."""
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
            allow_private_networks=False,
        )
        with pytest.raises(DownloadSecurityError):
            v.validate("https://[::ffff:127.0.0.1]/file.pdf")

    def test_ambiguous_decimal_ip_rejected(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://2130706433/file.pdf")  # decimal for 127.0.0.1
        assert exc_info.value.code in {INVALID_URL, PRIVATE_IP_BLOCKED}


class TestReservedHostnames:
    def test_localhost_rejected(self, validator):
        with pytest.raises(DownloadSecurityError) as exc_info:
            validator.validate("https://localhost/file.pdf")
        assert exc_info.value.code in {DOMAIN_BLOCKED, INVALID_URL}

    def test_internal_suffix_rejected(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://service.internal/file.pdf")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_local_suffix_rejected(self):
        v = DownloadUrlValidator(
            allowed_ports="443",
            default_domain_policy="allow",
        )
        with pytest.raises(DownloadSecurityError) as exc_info:
            v.validate("https://service.local/file.pdf")
        assert exc_info.value.code == DOMAIN_BLOCKED

    def test_metadata_google_rejected(self, validator):
        with pytest.raises(DownloadSecurityError):
            validator.validate("https://metadata.google.internal/computeMetadata/v1")
