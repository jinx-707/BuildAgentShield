"""Phase C: IP address SSRF policy tests."""

from __future__ import annotations

import ipaddress

import pytest

from app.downloads.exceptions import (
    CLOUD_METADATA_BLOCKED,
    LINK_LOCAL_BLOCKED,
    LOOPBACK_BLOCKED,
    MULTICAST_BLOCKED,
    PRIVATE_RANGE_BLOCKED,
    SSRFBlockedError,
    UNSPECIFIED_ADDRESS_BLOCKED,
)
from app.downloads.ip_policy import assert_ip_allowed, check_address_string, is_ip_allowed, parse_ip


class TestParseIP:
    def test_valid_ipv4(self):
        assert parse_ip("1.2.3.4") == ipaddress.IPv4Address("1.2.3.4")

    def test_valid_ipv6(self):
        result = parse_ip("2001:db8::1")
        assert isinstance(result, ipaddress.IPv6Address)

    def test_ipv4_mapped_unwrapped(self):
        # ::ffff:127.0.0.1 → 127.0.0.1
        result = parse_ip("::ffff:127.0.0.1")
        assert result == ipaddress.IPv4Address("127.0.0.1")

    def test_invalid_string_returns_none(self):
        assert parse_ip("not-an-ip") is None
        assert parse_ip("") is None
        assert parse_ip("999.999.999.999") is None


class TestBlockedAddresses:
    # Loopback
    def test_loopback_ipv4(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("127.0.0.1"))
        assert exc.value.code == LOOPBACK_BLOCKED

    def test_loopback_127_0_0_2(self):
        with pytest.raises(SSRFBlockedError):
            assert_ip_allowed(ipaddress.ip_address("127.0.0.2"))

    def test_loopback_ipv6(self):
        with pytest.raises(SSRFBlockedError):
            assert_ip_allowed(ipaddress.ip_address("::1"))

    # Private IPv4
    def test_private_10(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("10.0.0.1"))
        assert exc.value.code == PRIVATE_RANGE_BLOCKED

    def test_private_172_16(self):
        with pytest.raises(SSRFBlockedError):
            assert_ip_allowed(ipaddress.ip_address("172.16.0.1"))

    def test_private_172_31(self):
        with pytest.raises(SSRFBlockedError):
            assert_ip_allowed(ipaddress.ip_address("172.31.255.255"))

    def test_private_192_168(self):
        with pytest.raises(SSRFBlockedError):
            assert_ip_allowed(ipaddress.ip_address("192.168.0.1"))

    # Link-local
    def test_link_local_ipv4(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("169.254.0.1"))
        assert exc.value.code == LINK_LOCAL_BLOCKED

    def test_link_local_ipv6(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("fe80::1"))
        assert exc.value.code == LINK_LOCAL_BLOCKED

    # Cloud metadata
    def test_aws_metadata(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("169.254.169.254"))
        assert exc.value.code == CLOUD_METADATA_BLOCKED

    def test_aws_ecs_metadata(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("169.254.170.2"))
        assert exc.value.code == CLOUD_METADATA_BLOCKED

    def test_alibaba_metadata(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("100.100.100.200"))
        assert exc.value.code == CLOUD_METADATA_BLOCKED

    # Multicast
    def test_multicast_ipv4(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("224.0.0.1"))
        assert exc.value.code == MULTICAST_BLOCKED

    def test_multicast_ipv6(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("ff02::1"))
        assert exc.value.code == MULTICAST_BLOCKED

    # Unspecified
    def test_unspecified_ipv4(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("0.0.0.0"))
        assert exc.value.code == UNSPECIFIED_ADDRESS_BLOCKED

    def test_unspecified_ipv6(self):
        with pytest.raises(SSRFBlockedError) as exc:
            assert_ip_allowed(ipaddress.ip_address("::"))
        assert exc.value.code == UNSPECIFIED_ADDRESS_BLOCKED

    # IPv4-mapped IPv6
    def test_ipv4_mapped_loopback(self):
        # ::ffff:127.0.0.1 unwraps to 127.0.0.1 which is loopback
        addr = parse_ip("::ffff:127.0.0.1")
        assert addr is not None
        with pytest.raises(SSRFBlockedError):
            assert_ip_allowed(addr)

    def test_ipv4_mapped_private(self):
        addr = parse_ip("::ffff:192.168.1.1")
        assert addr is not None
        with pytest.raises(SSRFBlockedError):
            assert_ip_allowed(addr)


class TestAllowedAddresses:
    def test_public_ipv4(self):
        # Should not raise
        assert_ip_allowed(ipaddress.ip_address("8.8.8.8"))

    def test_public_ipv4_cloudflare(self):
        assert_ip_allowed(ipaddress.ip_address("1.1.1.1"))

    def test_public_ipv6(self):
        assert_ip_allowed(ipaddress.ip_address("2606:4700:4700::1111"))

    def test_is_ip_allowed_public(self):
        assert is_ip_allowed("8.8.8.8") is True

    def test_is_ip_allowed_private(self):
        assert is_ip_allowed("192.168.0.1") is False

    def test_is_ip_allowed_invalid_string(self):
        assert is_ip_allowed("not-an-ip") is False


class TestCheckAddressString:
    def test_valid_string(self):
        check_address_string("8.8.8.8")  # no raise

    def test_blocked_string(self):
        with pytest.raises(SSRFBlockedError):
            check_address_string("127.0.0.1")

    def test_invalid_string(self):
        with pytest.raises(SSRFBlockedError):
            check_address_string("not-an-ip")
