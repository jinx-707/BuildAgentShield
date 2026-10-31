"""Phase C: URL validation tests."""

from __future__ import annotations

import pytest

from app.downloads.exceptions import (
    AMBIGUOUS_HOST,
    EMBEDDED_CREDENTIALS,
    INVALID_PORT,
    INVALID_URL,
    UNSUPPORTED_SCHEME,
    InvalidURLError,
    SSRFBlockedError,
)
from app.downloads.url_validator import URLValidator, ValidatedURL


@pytest.fixture
def v() -> URLValidator:
    return URLValidator()


@pytest.fixture
def v_http() -> URLValidator:
    """Validator with HTTP allowed (dev-only)."""
    return URLValidator(allow_http=True)


# ── Valid URLs ─────────────────────────────────────────────────────────────────

class TestValidURLs:
    def test_simple_https(self, v):
        r = v.validate("https://files.example.com/report.pdf")
        assert r.scheme == "https"
        assert r.hostname == "files.example.com"
        assert r.port == 443
        assert not r.is_ip

    def test_https_with_explicit_port(self, v):
        r = v.validate("https://files.example.com:443/doc.pdf")
        assert r.port == 443

    def test_https_custom_allowed_port(self):
        v2 = URLValidator(allowed_ports=frozenset({8443}))
        r = v2.validate("https://files.example.com:8443/doc.pdf")
        assert r.port == 8443

    def test_preserves_path_and_query(self, v):
        r = v.validate("https://files.example.com/a/b?x=1&y=2")
        assert "/a/b" in r.normalized_url
        assert "x=1" in r.normalized_url

    def test_normalizes_hostname_to_lowercase(self, v):
        r = v.validate("https://Files.Example.COM/doc.pdf")
        assert r.hostname == "files.example.com"

    def test_returns_validated_url_dataclass(self, v):
        r = v.validate("https://files.example.com/f.pdf")
        assert isinstance(r, ValidatedURL)

    def test_http_allowed_when_configured(self, v_http):
        r = v_http.validate("http://files.example.com/f.pdf")
        assert r.scheme == "http"
        assert r.port == 80

    def test_subdomain_hostname(self, v):
        r = v.validate("https://cdn.downloads.example.com/file.pdf")
        assert r.hostname == "cdn.downloads.example.com"


# ── Scheme checks ──────────────────────────────────────────────────────────────

class TestSchemeValidation:
    def test_http_rejected_by_default(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("http://files.example.com/f.pdf")
        assert exc_info.value.code == UNSUPPORTED_SCHEME

    def test_ftp_rejected(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("ftp://files.example.com/f.pdf")
        assert exc_info.value.code == UNSUPPORTED_SCHEME

    def test_file_scheme_rejected(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("file:///etc/passwd")
        assert exc_info.value.code == UNSUPPORTED_SCHEME

    def test_javascript_rejected(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("javascript:alert(1)")

    def test_data_uri_rejected(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("data:text/plain,hello")


# ── Embedded credentials ───────────────────────────────────────────────────────

class TestEmbeddedCredentials:
    def test_username_only_rejected(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("https://user@files.example.com/f.pdf")
        assert exc_info.value.code == EMBEDDED_CREDENTIALS

    def test_username_password_rejected(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("https://user:secret@files.example.com/f.pdf")
        assert exc_info.value.code == EMBEDDED_CREDENTIALS

    def test_at_sign_in_netloc_rejected(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("https://attacker@files.example.com@other.com/f.pdf")
        assert exc_info.value.code in {EMBEDDED_CREDENTIALS, INVALID_URL}


# ── URL fragments ──────────────────────────────────────────────────────────────

class TestFragments:
    def test_fragment_rejected(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("https://files.example.com/f.pdf#section")
        assert exc_info.value.code == INVALID_URL


# ── Port validation ────────────────────────────────────────────────────────────

class TestPortValidation:
    def test_non_default_port_rejected_by_default(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("https://files.example.com:8080/f.pdf")
        assert exc_info.value.code == INVALID_PORT

    def test_port_0_rejected(self, v_http):
        with pytest.raises((InvalidURLError, Exception)):
            v_http.validate("https://files.example.com:0/f.pdf")

    def test_port_65536_rejected(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https://files.example.com:65536/f.pdf")

    def test_port_negative_rejected(self, v):
        with pytest.raises((InvalidURLError, Exception)):
            v.validate("https://files.example.com:-1/f.pdf")


# ── Malformed URLs ─────────────────────────────────────────────────────────────

class TestMalformedURLs:
    def test_empty_string(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("")

    def test_whitespace_only(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("   ")

    def test_no_host(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https:///path")

    def test_backslash_in_url(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https://files.example.com\\evil/f.pdf")

    def test_control_character_in_url(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https://files.example.com/f\x00.pdf")

    def test_newline_in_url(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https://files.example.com/f\n.pdf")

    def test_url_too_long(self, v):
        url = "https://files.example.com/" + "a" * 3000
        with pytest.raises(InvalidURLError):
            v.validate(url)


# ── Hostname validation ────────────────────────────────────────────────────────

class TestHostnameValidation:
    def test_reserved_localhost(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https://localhost/f.pdf")

    def test_reserved_dot_local(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https://myservice.local/f.pdf")

    def test_reserved_dot_internal(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https://api.internal/f.pdf")

    def test_reserved_metadata_google(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https://metadata.google.internal/f.pdf")

    def test_ambiguous_decimal_integer_host(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("https://2130706433/f.pdf")  # 127.0.0.1 as integer
        assert exc_info.value.code in {AMBIGUOUS_HOST, INVALID_URL}

    def test_ambiguous_hex_host(self, v):
        with pytest.raises(InvalidURLError) as exc_info:
            v.validate("https://0x7f000001/f.pdf")  # 127.0.0.1 as hex
        assert exc_info.value.code in {AMBIGUOUS_HOST, INVALID_URL}

    def test_label_too_long(self, v):
        label = "a" * 64
        with pytest.raises(InvalidURLError):
            v.validate(f"https://{label}.example.com/f.pdf")

    def test_hostname_too_long(self, v):
        # 254+ character hostname
        hostname = ".".join(["abcde"] * 52)
        with pytest.raises(InvalidURLError):
            v.validate(f"https://{hostname}/f.pdf")


# ── IP literal checks ──────────────────────────────────────────────────────────

class TestIPLiterals:
    def test_loopback_ipv4(self, v):
        with pytest.raises(SSRFBlockedError):
            v.validate("https://127.0.0.1/f.pdf")

    def test_loopback_ipv6(self, v):
        with pytest.raises(SSRFBlockedError):
            v.validate("https://[::1]/f.pdf")

    def test_private_172_16(self, v):
        with pytest.raises(SSRFBlockedError):
            v.validate("https://172.16.0.1/f.pdf")

    def test_private_192_168(self, v):
        with pytest.raises(SSRFBlockedError):
            v.validate("https://192.168.1.1/f.pdf")

    def test_private_10(self, v):
        with pytest.raises(SSRFBlockedError):
            v.validate("https://10.0.0.1/f.pdf")

    def test_link_local(self, v):
        with pytest.raises(SSRFBlockedError):
            v.validate("https://169.254.1.1/f.pdf")

    def test_cloud_metadata_aws(self, v):
        with pytest.raises(SSRFBlockedError):
            v.validate("https://169.254.169.254/latest/meta-data/")

    def test_ipv4_mapped_ipv6(self, v):
        # ::ffff:127.0.0.1 — IPv4-mapped loopback
        with pytest.raises(SSRFBlockedError):
            v.validate("https://[::ffff:127.0.0.1]/f.pdf")

    def test_scoped_ipv6_rejected(self, v):
        with pytest.raises(InvalidURLError):
            v.validate("https://[fe80::1%25eth0]/f.pdf")
