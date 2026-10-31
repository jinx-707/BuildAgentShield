"""Phase C: DNS resolution and SSRF protection tests.

All tests use injected fake resolvers — no real DNS queries are made.
"""

from __future__ import annotations

import pytest

from app.downloads.dns_resolver import ResolvedTarget, SecureDNSResolver
from app.downloads.exceptions import (
    DNS_EMPTY_RESPONSE,
    DNS_MIXED_RESPONSE,
    DNS_RESOLUTION_FAILED,
    DNSRebindingError,
    DNSResolutionError,
    SSRFBlockedError,
)
from app.downloads.url_validator import URLValidator, ValidatedURL


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validated(
    hostname: str = "files.example.com",
    scheme: str = "https",
    port: int = 443,
    is_ip: bool = False,
) -> ValidatedURL:
    url = f"{scheme}://{hostname}:{port}/file.pdf"
    return ValidatedURL(
        original_url=url,
        normalized_url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        is_ip=is_ip,
    )


class _FakeResolver:
    def __init__(self, answers: list[str] | Exception) -> None:
        self._answers = answers

    async def resolve(self, hostname: str) -> list[str]:
        if isinstance(self._answers, Exception):
            raise self._answers
        return self._answers


def _resolver(answers: list[str] | Exception) -> SecureDNSResolver:
    return SecureDNSResolver(resolver=_FakeResolver(answers))


# ── Happy path ────────────────────────────────────────────────────────────────

class TestSuccessfulResolution:
    @pytest.mark.asyncio
    async def test_public_ipv4_returns_resolved_target(self):
        r = _resolver(["8.8.8.8"])
        result = await r.resolve(_validated("files.example.com"))
        assert isinstance(result, ResolvedTarget)
        assert result.address == "8.8.8.8"
        assert result.hostname == "files.example.com"
        assert result.port == 443
        assert result.scheme == "https"

    @pytest.mark.asyncio
    async def test_public_ipv6_returns_resolved_target(self):
        r = _resolver(["2606:4700:4700::1111"])
        result = await r.resolve(_validated("files.example.com"))
        assert result.address == "2606:4700:4700::1111"

    @pytest.mark.asyncio
    async def test_multiple_public_ips_returns_first(self):
        r = _resolver(["8.8.8.8", "8.8.4.4"])
        result = await r.resolve(_validated("files.example.com"))
        assert result.address == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_ip_literal_skips_dns(self):
        # Fake resolver should never be called
        r = _resolver(Exception("should not be called"))
        result = await r.resolve(_validated("8.8.8.8", is_ip=True))
        assert result.address == "8.8.8.8"
        assert result.hostname == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_hostname_preserved_in_result(self):
        r = _resolver(["1.2.3.4"])
        result = await r.resolve(_validated("cdn.downloads.example.com"))
        assert result.hostname == "cdn.downloads.example.com"
        assert result.address == "1.2.3.4"
        assert result.hostname != result.address


# ── Blocked addresses ─────────────────────────────────────────────────────────

class TestBlockedResolution:
    @pytest.mark.asyncio
    async def test_loopback_blocked(self):
        r = _resolver(["127.0.0.1"])
        with pytest.raises(SSRFBlockedError):
            await r.resolve(_validated("evil.example.com"))

    @pytest.mark.asyncio
    async def test_private_10_blocked(self):
        r = _resolver(["10.0.0.1"])
        with pytest.raises(SSRFBlockedError):
            await r.resolve(_validated("internal.example.com"))

    @pytest.mark.asyncio
    async def test_private_192_168_blocked(self):
        r = _resolver(["192.168.1.100"])
        with pytest.raises(SSRFBlockedError):
            await r.resolve(_validated("router.example.com"))

    @pytest.mark.asyncio
    async def test_link_local_blocked(self):
        r = _resolver(["169.254.0.1"])
        with pytest.raises(SSRFBlockedError):
            await r.resolve(_validated("link.example.com"))

    @pytest.mark.asyncio
    async def test_cloud_metadata_blocked(self):
        r = _resolver(["169.254.169.254"])
        with pytest.raises(SSRFBlockedError):
            await r.resolve(_validated("metadata.example.com"))

    @pytest.mark.asyncio
    async def test_blocked_ip_literal_rejected(self):
        r = _resolver([])  # never called
        with pytest.raises(SSRFBlockedError):
            await r.resolve(_validated("127.0.0.1", is_ip=True))


# ── DNS errors ────────────────────────────────────────────────────────────────

class TestDNSErrors:
    @pytest.mark.asyncio
    async def test_resolution_failure_propagated(self):
        import socket
        r = _resolver(DNSResolutionError(DNS_RESOLUTION_FAILED, "nxdomain"))
        with pytest.raises(DNSResolutionError) as exc:
            await r.resolve(_validated("nxdomain.example.com"))
        assert exc.value.code == DNS_RESOLUTION_FAILED

    @pytest.mark.asyncio
    async def test_unexpected_exception_wrapped(self):
        r = _resolver(RuntimeError("network down"))
        with pytest.raises(DNSResolutionError) as exc:
            await r.resolve(_validated("broken.example.com"))
        assert exc.value.code == DNS_RESOLUTION_FAILED

    @pytest.mark.asyncio
    async def test_empty_answer_rejected(self):
        r = _resolver([])
        with pytest.raises(DNSResolutionError) as exc:
            await r.resolve(_validated("empty.example.com"))
        assert exc.value.code == DNS_EMPTY_RESPONSE


# ── DNS rebinding ─────────────────────────────────────────────────────────────

class TestDNSRebinding:
    @pytest.mark.asyncio
    async def test_mixed_public_private_rejected(self):
        # One public, one private — rebinding attack
        r = _resolver(["8.8.8.8", "192.168.1.1"])
        with pytest.raises(DNSRebindingError) as exc:
            await r.resolve(_validated("rebind.example.com"))
        assert exc.value.code == DNS_MIXED_RESPONSE

    @pytest.mark.asyncio
    async def test_mixed_public_loopback_rejected(self):
        r = _resolver(["8.8.8.8", "127.0.0.1"])
        with pytest.raises(DNSRebindingError):
            await r.resolve(_validated("rebind2.example.com"))

    @pytest.mark.asyncio
    async def test_mixed_public_metadata_rejected(self):
        r = _resolver(["1.1.1.1", "169.254.169.254"])
        with pytest.raises(DNSRebindingError):
            await r.resolve(_validated("tricky.example.com"))

    @pytest.mark.asyncio
    async def test_all_public_not_rejected(self):
        r = _resolver(["8.8.8.8", "8.8.4.4"])
        result = await r.resolve(_validated("cdn.example.com"))
        assert result.address == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_all_private_rejected_not_as_rebind(self):
        # All blocked — SSRFBlockedError, not DNSRebindingError
        r = _resolver(["10.0.0.1", "10.0.0.2"])
        with pytest.raises(SSRFBlockedError):
            await r.resolve(_validated("allprivate.example.com"))
