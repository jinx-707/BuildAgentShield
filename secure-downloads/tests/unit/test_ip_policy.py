"""Tests for the IP policy (SSRF IP blocking logic)."""
from __future__ import annotations

import pytest

from security.ip_policy import is_blocked_ip, parse_ip


class TestAlwaysBlockedIps:
    def test_aws_metadata(self):
        assert is_blocked_ip("169.254.169.254") is True

    def test_ecs_metadata(self):
        assert is_blocked_ip("169.254.170.2") is True

    def test_alibaba_metadata(self):
        assert is_blocked_ip("100.100.100.200") is True

    def test_aws_ipv6_metadata(self):
        assert is_blocked_ip("fd00:ec2::254") is True

    def test_aws_metadata_not_bypassed_by_allow_private(self):
        """allow_private=True must never bypass the always-blocked list."""
        assert is_blocked_ip("169.254.169.254", allow_private=True) is True


class TestLoopback:
    def test_ipv4_loopback(self):
        assert is_blocked_ip("127.0.0.1") is True

    def test_ipv4_loopback_other(self):
        assert is_blocked_ip("127.0.0.2") is True

    def test_ipv6_loopback(self):
        assert is_blocked_ip("::1") is True

    def test_loopback_allowed_with_allow_private(self):
        assert is_blocked_ip("127.0.0.1", allow_private=True) is False


class TestPrivateRanges:
    def test_10_block(self):
        assert is_blocked_ip("10.0.0.1") is True

    def test_172_16_block(self):
        assert is_blocked_ip("172.16.0.1") is True

    def test_172_31_block(self):
        assert is_blocked_ip("172.31.255.255") is True

    def test_172_32_public(self):
        assert is_blocked_ip("172.32.0.0") is False

    def test_192_168_block(self):
        assert is_blocked_ip("192.168.1.100") is True

    def test_private_allowed_with_allow_private(self):
        assert is_blocked_ip("10.0.0.1", allow_private=True) is False


class TestLinkLocal:
    def test_link_local_ipv4(self):
        assert is_blocked_ip("169.254.1.1") is True

    def test_link_local_ipv6(self):
        assert is_blocked_ip("fe80::1") is True


class TestMulticast:
    def test_multicast_ipv4(self):
        assert is_blocked_ip("224.0.0.1") is True

    def test_multicast_ipv6(self):
        assert is_blocked_ip("ff02::1") is True


class TestPublicAddresses:
    def test_public_ip_allowed(self):
        assert is_blocked_ip("93.184.216.34") is False

    def test_8_8_8_8_allowed(self):
        assert is_blocked_ip("8.8.8.8") is False


class TestIpv6Variants:
    def test_ipv4_mapped_loopback_blocked(self):
        """::ffff:127.0.0.1 is IPv4-mapped; must be treated as loopback."""
        parsed = parse_ip("::ffff:127.0.0.1")
        assert parsed is not None
        assert str(parsed) == "127.0.0.1"
        assert is_blocked_ip("::ffff:127.0.0.1") is True

    def test_6to4_blocked(self):
        """2002::/16 is the 6to4 range; always blocked."""
        assert is_blocked_ip("2002:c000:0204::") is True

    def test_teredo_blocked(self):
        """2001::/32 is the Teredo range; always blocked."""
        assert is_blocked_ip("2001:0:0:0:0:0:0:1") is True


class TestUnspecified:
    def test_unspecified_ipv4(self):
        assert is_blocked_ip("0.0.0.0") is True

    def test_unspecified_ipv6(self):
        assert is_blocked_ip("::") is True


class TestParseIp:
    def test_returns_none_for_hostname(self):
        assert parse_ip("example.com") is None

    def test_parses_valid_ipv4(self):
        ip = parse_ip("93.184.216.34")
        assert str(ip) == "93.184.216.34"

    def test_parses_valid_ipv6(self):
        ip = parse_ip("2001:4860:4860::8888")
        assert ip is not None
