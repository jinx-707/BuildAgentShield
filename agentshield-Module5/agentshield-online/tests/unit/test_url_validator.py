"""
URL validator tests — covers SSRF, private IPs, cloud metadata, bad schemes.
"""
import pytest
from app.capabilities.online.browser.url_validator import validate_url
from app.core.exceptions import SSRFAttemptError, URLValidationError


class TestBlockedSchemes:
    def test_javascript_scheme_blocked(self):
        with pytest.raises(URLValidationError, match="javascript"):
            validate_url("javascript:alert(1)")

    def test_file_scheme_blocked(self):
        with pytest.raises(URLValidationError, match="file"):
            validate_url("file:///etc/passwd")

    def test_data_scheme_blocked(self):
        with pytest.raises(URLValidationError, match="data"):
            validate_url("data:text/html,<script>alert(1)</script>")

    def test_ftp_scheme_blocked(self):
        with pytest.raises(URLValidationError, match="ftp"):
            validate_url("ftp://example.com/file.txt")

    def test_vbscript_scheme_blocked(self):
        with pytest.raises(URLValidationError, match="vbscript"):
            validate_url("vbscript:msgbox(1)")

    def test_blob_scheme_blocked(self):
        with pytest.raises(URLValidationError, match="blob"):
            validate_url("blob:http://example.com/abc")


class TestPrivateIPv4:
    def test_loopback_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://127.0.0.1/admin", resolve_dns=False)

    def test_private_10_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://10.0.0.1/internal", resolve_dns=False)

    def test_private_172_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://172.16.0.1/internal", resolve_dns=False)

    def test_private_192_168_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://192.168.1.1/router", resolve_dns=False)

    def test_link_local_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://169.254.1.1/", resolve_dns=False)

    def test_zero_network_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://0.0.0.0/", resolve_dns=False)


class TestPrivateIPv6:
    def test_ipv6_loopback_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://[::1]/", resolve_dns=False)

    def test_ipv6_link_local_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://[fe80::1]/", resolve_dns=False)

    def test_ipv6_ula_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://[fc00::1]/", resolve_dns=False)


class TestCloudMetadata:
    def test_aws_metadata_blocked(self):
        with pytest.raises(SSRFAttemptError):
            validate_url("http://169.254.169.254/latest/meta-data/", resolve_dns=False)

    def test_gcp_metadata_blocked(self):
        with pytest.raises((SSRFAttemptError, URLValidationError)):
            validate_url("http://metadata.google.internal/", resolve_dns=False)


class TestDomainAllowlist:
    def test_allowed_domain_passes(self):
        result = validate_url(
            "https://example.com/page",
            domain_allowlist=["example.com"],
            resolve_dns=False,
        )
        assert result["valid"] is True

    def test_subdomain_of_allowed_passes(self):
        result = validate_url(
            "https://sub.example.com/page",
            domain_allowlist=["example.com"],
            resolve_dns=False,
        )
        assert result["valid"] is True

    def test_non_allowlisted_domain_blocked(self):
        with pytest.raises(URLValidationError, match="allowlist"):
            validate_url(
                "https://evil.com/steal",
                domain_allowlist=["example.com"],
                resolve_dns=False,
            )


class TestDomainBlocklist:
    def test_blocklisted_domain_blocked(self):
        with pytest.raises(URLValidationError, match="blocklist"):
            validate_url(
                "https://evil.example.com/",
                domain_blocklist=["evil.example.com"],
                resolve_dns=False,
            )


class TestValidURLs:
    def test_https_allowed(self):
        result = validate_url("https://github.com/", resolve_dns=False)
        assert result["valid"] is True

    def test_http_allowed(self):
        result = validate_url("http://example.com/", resolve_dns=False)
        assert result["valid"] is True

    def test_url_with_path_allowed(self):
        result = validate_url("https://docs.python.org/3/library/", resolve_dns=False)
        assert result["valid"] is True


class TestEdgeCases:
    def test_empty_url_raises(self):
        with pytest.raises(URLValidationError):
            validate_url("")

    def test_url_too_long_raises(self):
        with pytest.raises(URLValidationError, match="length"):
            validate_url("https://example.com/" + "a" * 2048)

    def test_no_hostname_raises(self):
        with pytest.raises(URLValidationError):
            validate_url("https:///path")
