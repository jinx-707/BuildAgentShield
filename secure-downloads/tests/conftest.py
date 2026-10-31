"""Shared test fixtures for the secure-downloads test suite."""
from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

# Settings construction is fail-closed on ENVIRONMENT (see config/settings.py):
# missing/empty/unknown values raise ValidationError.  Tests operate as an
# explicitly non-production environment, set here (before test modules import
# api.app, whose module-level create_app() needs to build default settings).
os.environ.setdefault("ENVIRONMENT", "test")

# Make sure the project root is on sys.path.
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config.settings import Settings
from models.database import Base, get_async_engine, get_async_session
from models.download import Download, DownloadState
from security.mime_validator import MimeValidator
from security.preflight import DownloadPreflight
from security.ssrf import DnsResolverProtocol, ResolvedAddresses, SsrfGuard
from security.url_validator import DownloadUrlValidator
from services.repository import DownloadRepository
from services.scanner import ClamAvScanner, ScanResult, ScanVerdict
from storage.manager import StorageManager


# ── Settings helpers ──────────────────────────────────────────────────────────

def make_settings(**overrides) -> Settings:
    defaults = {
        "environment": "test",
        "log_level": "WARNING",
        "api_auth_token": "",
        "database_url": "sqlite+aiosqlite:///:memory:",
        "egress_proxy_url": "",
        "require_egress_proxy": False,
        "allowed_domains": "example.com,files.example.com",
        "blocked_domains": "",
        "default_domain_policy": "deny",
        "allowed_ports": "443",
        "allow_private_networks": False,
        "dns_preflight_enabled": False,   # disabled by default in tests
        "max_file_size_bytes": 10_000_000,
        "clamav_fail_closed": True,
        "storage_root": "/tmp/test-secure-downloads",
        "approved_file_ttl_seconds": 3600,
    }
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)


# ── Fake DNS resolver ─────────────────────────────────────────────────────────

class FakeDnsResolver(DnsResolverProtocol):
    """Returns pre-configured addresses instead of querying the OS resolver."""

    def __init__(self, mapping: dict[str, list[str]] | None = None) -> None:
        # hostname → list of IP addresses
        self._mapping: dict[str, list[str]] = mapping or {}
        self._default = ["93.184.216.34"]  # example.com

    def add(self, hostname: str, addresses: list[str]) -> None:
        self._mapping[hostname] = addresses

    async def resolve(self, hostname: str) -> list[str]:
        return self._mapping.get(hostname, self._default)


class SequenceDnsResolver(DnsResolverProtocol):
    """
    Returns a *different* answer for each successive lookup of a hostname.

    This is what a real DNS-rebinding attack does: the first (preflight)
    lookup returns a safe address and a later lookup returns a blocked one.
    FakeDnsResolver cannot model that because it answers every lookup
    identically — with it, preflight alone would already reject the target.
    """

    def __init__(self, mapping: dict[str, list[list[str]]]) -> None:
        self._answers = {host: list(seq) for host, seq in mapping.items()}
        self.lookup_counts: dict[str, int] = {}

    async def resolve(self, hostname: str) -> list[str]:
        seq = self._answers.get(hostname)
        if not seq:
            raise AssertionError(f"no scripted DNS answer for {hostname!r}")
        answer = seq.pop(0) if len(seq) > 1 else seq[0]
        self.lookup_counts[hostname] = self.lookup_counts.get(hostname, 0) + 1
        return answer


# ── Fake scanner ──────────────────────────────────────────────────────────────

class FakeScanner:
    def __init__(self, verdict: ScanVerdict = ScanVerdict.CLEAN, detail: str | None = None):
        self.verdict = verdict
        self.detail = detail
        self.calls: list[Path] = []

    async def scan(self, file_path: Path) -> ScanResult:
        self.calls.append(file_path)
        return ScanResult(verdict=self.verdict, detail=self.detail)

    async def is_available(self) -> bool:
        return True


# ── Security pipeline fixtures ────────────────────────────────────────────────

@pytest.fixture
def settings():
    return make_settings()


@pytest.fixture
def fake_dns():
    return FakeDnsResolver()


@pytest.fixture
def url_validator(settings):
    return DownloadUrlValidator(
        allowed_ports=settings.allowed_ports,
        allowed_domains=settings.allowed_domains,
        blocked_domains=settings.blocked_domains,
        default_domain_policy=settings.default_domain_policy,
        allow_private_networks=settings.allow_private_networks,
        https_only=True,
    )


@pytest.fixture
def ssrf_guard(fake_dns, settings):
    return SsrfGuard(
        resolver=fake_dns,
        allow_private_networks=settings.allow_private_networks,
    )


@pytest.fixture
def preflight(url_validator, ssrf_guard, settings):
    return DownloadPreflight(
        url_validator=url_validator,
        ssrf_guard=ssrf_guard,
        dns_enabled=False,
    )


@pytest.fixture
def mime_validator():
    return MimeValidator()


# ── Storage fixture ───────────────────────────────────────────────────────────

@pytest.fixture
def tmp_storage(tmp_path):
    sm = StorageManager(str(tmp_path / "storage"))
    sm.initialize()
    return sm


# ── Database fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
async def engine():
    eng = get_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
async def session_factory(engine):
    return get_async_session(engine)


@pytest.fixture
async def repo(session_factory):
    return DownloadRepository(session_factory)


# ── Scanner fixture ───────────────────────────────────────────────────────────

@pytest.fixture
def fake_scanner():
    return FakeScanner()
