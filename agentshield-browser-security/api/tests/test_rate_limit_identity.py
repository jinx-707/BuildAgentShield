"""Trusted-proxy identity and rate-limit isolation tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.security.rate_limit import (
    InMemoryRateLimitBackend,
    LimitPolicy,
    RateLimitBackendUnavailable,
    RateLimitConfigurationError,
    RateLimitExceeded,
    RateLimiter,
    build_rate_limiter,
)
from app.security.trusted_proxy import (
    InvalidForwardedAddress,
    parse_trusted_proxies,
    resolve_client_identity,
)
from tests.conftest import FakeSearchProvider, FakeWorkerClient, make_settings

TRUSTED = "10.0.0.1/32"
AGENT = {"X-Agent-ID": "agent-a"}


# ---------------------------------------------------------------------------
# Identity resolution
# ---------------------------------------------------------------------------


def test_parse_trusted_proxies_accepts_ips_and_cidrs():
    networks = parse_trusted_proxies("10.0.0.0/8, 2001:db8::/32, 192.0.2.7")

    assert len(networks) == 3
    assert str(networks[2]) == "192.0.2.7/32"


@pytest.mark.parametrize("value", ["not-an-ip", "10.0.0.0/99", "1.2.3.4, nope"])
def test_parse_trusted_proxies_rejects_invalid_entries(value):
    with pytest.raises(ValueError, match="trusted proxy"):
        parse_trusted_proxies(value)


def test_untrusted_peer_cannot_influence_identity_with_xff():
    identity = resolve_client_identity(
        "203.0.113.9",
        "198.51.100.1",
        trusted_proxies=parse_trusted_proxies(TRUSTED),
    )

    assert identity.address == "203.0.113.9"
    assert identity.source == "direct"
    assert identity.forwarded_chain == ()


def test_trusted_proxy_uses_rightmost_untrusted_address():
    identity = resolve_client_identity(
        "10.0.0.1",
        "198.51.100.1, 203.0.113.7",
        trusted_proxies=parse_trusted_proxies(TRUSTED),
    )

    assert identity.address == "203.0.113.7"
    assert identity.source == "forwarded"
    assert identity.trusted_proxy is True


def test_multi_hop_walks_past_trusted_proxies():
    identity = resolve_client_identity(
        "10.0.0.1",
        "198.51.100.1, 10.0.0.2, 10.0.0.3",
        trusted_proxies=parse_trusted_proxies("10.0.0.0/24"),
    )

    assert identity.address == "198.51.100.1"
    assert identity.forwarded_chain == (
        "198.51.100.1",
        "10.0.0.2",
        "10.0.0.3",
    )


def test_trusted_proxy_without_xff_uses_direct_peer():
    identity = resolve_client_identity(
        "10.0.0.1",
        None,
        trusted_proxies=parse_trusted_proxies(TRUSTED),
    )

    assert identity.address == "10.0.0.1"
    assert identity.source == "direct"


@pytest.mark.parametrize(
    "header",
    [
        "not-an-ip",
        "198.51.100.1,,203.0.113.7",
        "198.51.100.1, ",
        "198.51.100.1:1234",
        "[2001:db8::1]",
        "fe80::1%eth0",
    ],
)
def test_malformed_forwarded_chain_is_rejected(header):
    with pytest.raises(InvalidForwardedAddress):
        resolve_client_identity(
            "10.0.0.1",
            header,
            trusted_proxies=parse_trusted_proxies(TRUSTED),
        )


def test_forwarded_chain_length_is_capped():
    with pytest.raises(InvalidForwardedAddress, match="too long"):
        resolve_client_identity(
            "10.0.0.1",
            "198.51.100.1, 198.51.100.2",
            trusted_proxies=parse_trusted_proxies(TRUSTED),
            max_hops=1,
        )


def test_ipv4_mapped_peer_matches_ipv4_trusted_network():
    identity = resolve_client_identity(
        "::ffff:10.0.0.1",
        "198.51.100.9",
        trusted_proxies=parse_trusted_proxies(TRUSTED),
    )

    assert identity.address == "198.51.100.9"


# ---------------------------------------------------------------------------
# Backend / limiter unit behavior
# ---------------------------------------------------------------------------


async def test_memory_backend_allows_limit_then_denies_with_retry():
    backend = InMemoryRateLimitBackend()
    for _ in range(2):
        decision = await backend.increment("key", limit=2, window_seconds=60)
        assert decision.allowed is True

    denied = await backend.increment("key", limit=2, window_seconds=60)
    assert denied.allowed is False
    assert denied.retry_after >= 1
    await backend.aclose()


class RecordingBackend:
    def __init__(self, *, deny: bool = False, fail: bool = False) -> None:
        self.keys: list[str] = []
        self.deny = deny
        self.fail = fail

    async def increment(self, key, *, limit, window_seconds):
        self.keys.append(key)
        if self.fail:
            raise RateLimitBackendUnavailable()
        from app.security.rate_limit import RateLimitDecision

        return RateLimitDecision(
            allowed=not self.deny,
            limit=limit,
            remaining=0 if self.deny else limit - 1,
            retry_after=7 if self.deny else 0,
        )

    async def aclose(self):
        return None


async def test_limiter_checks_tenant_session_and_ip_without_raw_values():
    backend = RecordingBackend()
    limiter = RateLimiter(
        backend,
        policies={"action": LimitPolicy(5, 60)},
    )
    identity = resolve_client_identity("203.0.113.5", None)

    await limiter.check(
        "action",
        identity,
        agent_id="tenant-secret",
        session_id="session-secret",
    )

    assert len(backend.keys) == 3
    assert backend.keys[0].startswith("action:tenant:")
    assert backend.keys[1].startswith("action:session:")
    assert backend.keys[2].startswith("action:ip:")
    joined = " ".join(backend.keys)
    assert "tenant-secret" not in joined
    assert "session-secret" not in joined
    assert "203.0.113.5" not in joined


async def test_tenant_keys_differ_for_two_agents_on_the_same_ip():
    backend = RecordingBackend()
    limiter = RateLimiter(
        backend,
        policies={"api": LimitPolicy(5, 60)},
    )
    identity = resolve_client_identity("203.0.113.5", None)

    await limiter.check("api", identity, agent_id="tenant-a")
    await limiter.check("api", identity, agent_id="tenant-b")

    tenant_keys = [key for key in backend.keys if ":tenant:" in key]
    ip_keys = [key for key in backend.keys if ":ip:" in key]
    assert len(tenant_keys) == 2
    assert tenant_keys[0] != tenant_keys[1]
    assert ip_keys[0] == ip_keys[1]


async def test_limiter_reports_the_dimension_that_denied():
    limiter = RateLimiter(
        RecordingBackend(deny=True),
        policies={"action": LimitPolicy(5, 60)},
    )
    identity = resolve_client_identity("203.0.113.5", None)

    with pytest.raises(RateLimitExceeded) as caught:
        await limiter.check(
            "action",
            identity,
            agent_id="tenant-secret",
            session_id="session-secret",
        )

    assert caught.value.scope == "tenant"
    assert caught.value.retry_after == 7


async def test_backend_failure_is_fail_closed_by_default():
    limiter = RateLimiter(
        RecordingBackend(fail=True),
        policies={"api": LimitPolicy(5, 60)},
    )
    with pytest.raises(RateLimitBackendUnavailable):
        await limiter.check("api", resolve_client_identity("203.0.113.5", None))


async def test_backend_failure_can_be_explicitly_fail_open():
    limiter = RateLimiter(
        RecordingBackend(fail=True),
        policies={"api": LimitPolicy(5, 60)},
        fail_open=True,
    )
    await limiter.check("api", resolve_client_identity("203.0.113.5", None))


# ---------------------------------------------------------------------------
# API integration: spoofing and isolation
# ---------------------------------------------------------------------------


def _client_for(app, peer=("203.0.113.10", 50000)):
    return TestClient(app, client=peer, raise_server_exceptions=False)


def _get(client, *, ip=None, agent=None):
    headers = {}
    if ip is not None:
        headers["X-Forwarded-For"] = ip
    if agent is not None:
        headers["X-Agent-ID"] = agent
    return client.get("/health", headers=headers)


def test_untrusted_peer_cannot_spoof_xff_to_bypass_limit():
    app = create_app(
        make_settings(
            rate_limit_per_minute=2,
            rate_limit_trusted_proxies=TRUSTED,
        ),
        browser_client=FakeWorkerClient(),
    )

    with _client_for(app) as client:
        assert _get(client, ip="198.51.100.1").status_code == 200
        assert _get(client, ip="198.51.100.2").status_code == 200
        response = _get(client, ip="198.51.100.3")

    assert response.status_code == 429
    assert response.json()["code"] == "RATE_LIMIT_EXCEEDED"
    assert int(response.headers["retry-after"]) >= 1
    assert response.headers["x-ratelimit-scope"] == "ip"


def test_trusted_proxy_forwarded_addresses_get_independent_buckets():
    app = create_app(
        make_settings(
            rate_limit_per_minute=2,
            rate_limit_trusted_proxies=TRUSTED,
        ),
        browser_client=FakeWorkerClient(),
    )

    with _client_for(app, peer=("10.0.0.1", 50000)) as client:
        assert _get(client, ip="198.51.100.1").status_code == 200
        assert _get(client, ip="198.51.100.1").status_code == 200
        assert _get(client, ip="198.51.100.1").status_code == 429
        response = _get(client, ip="198.51.100.2")

    assert response.status_code == 200


def test_malformed_xff_from_trusted_proxy_returns_400():
    app = create_app(
        make_settings(rate_limit_trusted_proxies=TRUSTED),
        browser_client=FakeWorkerClient(),
    )

    with _client_for(app, peer=("10.0.0.1", 50000)) as client:
        response = _get(client, ip="198.51.100.1, not-an-ip")

    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_FORWARDED_FOR"


def test_untrusted_peer_malformed_xff_is_ignored():
    app = create_app(
        make_settings(rate_limit_trusted_proxies=TRUSTED),
        browser_client=FakeWorkerClient(),
    )

    with _client_for(app) as client:
        response = _get(client, ip="not-an-ip")

    assert response.status_code == 200


def test_tenant_limit_catches_ip_rotation_for_same_agent():
    app = create_app(
        make_settings(
            rate_limit_per_minute=2,
            rate_limit_trusted_proxies=TRUSTED,
        ),
        browser_client=FakeWorkerClient(),
    )

    with _client_for(app, peer=("10.0.0.1", 50000)) as client:
        assert _get(client, ip="198.51.100.1", agent="agent-a").status_code == 200
        assert _get(client, ip="198.51.100.2", agent="agent-a").status_code == 200
        response = _get(client, ip="198.51.100.3", agent="agent-a")

    assert response.status_code == 429
    assert response.json()["scope"] == "tenant"


def test_two_agents_behind_one_ip_share_the_ip_bucket():
    app = create_app(
        make_settings(
            rate_limit_per_minute=4,
            rate_limit_trusted_proxies=TRUSTED,
        ),
        browser_client=FakeWorkerClient(),
    )

    with _client_for(app, peer=("10.0.0.1", 50000)) as client:
        for _ in range(2):
            assert _get(client, ip="198.51.100.1", agent="agent-a").status_code == 200
        for _ in range(2):
            assert _get(client, ip="198.51.100.1", agent="agent-b").status_code == 200
        response = _get(client, ip="198.51.100.1", agent="agent-a")

    assert response.status_code == 429
    assert response.json()["scope"] == "ip"


def test_session_limit_is_shared_across_agents_and_ips():
    app = create_app(
        make_settings(
            rate_limit_per_minute=10,
            rate_limit_action_per_minute=2,
            rate_limit_trusted_proxies=TRUSTED,
        ),
        browser_client=FakeWorkerClient(),
    )
    payload = {
        "session_id": "session-123",
        "action": "click",
        "target": {"selector": "#go"},
    }

    with _client_for(app, peer=("10.0.0.1", 50000)) as client:
        for index, agent in enumerate(("agent-a", "agent-b")):
            response = client.post(
                "/v1/browser/action",
                headers={
                    "X-Agent-ID": agent,
                    "X-Forwarded-For": f"198.51.100.{index + 1}",
                },
                json=payload,
            )
            assert response.status_code == 200, response.text

        response = client.post(
            "/v1/browser/action",
            headers={
                "X-Agent-ID": "agent-c",
                "X-Forwarded-For": "198.51.100.3",
            },
            json=payload,
        )

    assert response.status_code == 429
    assert response.json()["scope"] == "session"


def test_search_has_a_separate_lower_limit():
    provider = FakeSearchProvider(hits=[])
    app = create_app(
        make_settings(
            rate_limit_per_minute=10,
            rate_limit_search_per_minute=1,
        ),
        browser_client=FakeWorkerClient(),
        search_provider=provider,
    )

    with _client_for(app) as client:
        first = client.post("/v1/browser/search", json={"query": "one"})
        second = client.post("/v1/browser/search", json={"query": "two"})

    assert first.status_code == 200, first.text
    assert second.status_code == 429
    assert second.json()["category"] == "search"
    assert len(provider.calls) == 1


def test_screenshot_has_a_separate_lower_limit():
    app = create_app(
        make_settings(
            rate_limit_per_minute=10,
            rate_limit_screenshot_per_minute=1,
        ),
        browser_client=FakeWorkerClient(),
    )
    payload = {"session_id": "session-123"}

    with _client_for(app) as client:
        first = client.post(
            "/v1/browser/screenshot", headers=AGENT, json=payload
        )
        second = client.post(
            "/v1/browser/screenshot", headers=AGENT, json=payload
        )

    assert first.status_code == 200, first.text
    assert second.status_code == 429
    assert second.json()["category"] == "screenshot"


def test_action_has_a_separate_lower_limit():
    app = create_app(
        make_settings(
            rate_limit_per_minute=10,
            rate_limit_action_per_minute=1,
        ),
        browser_client=FakeWorkerClient(),
    )
    payload = {
        "session_id": "session-123",
        "action": "click",
        "target": {"selector": "#go"},
    }

    with _client_for(app) as client:
        first = client.post("/v1/browser/action", headers=AGENT, json=payload)
        second = client.post("/v1/browser/action", headers=AGENT, json=payload)

    assert first.status_code == 200, first.text
    assert second.status_code == 429
    assert second.json()["category"] == "action"


# ---------------------------------------------------------------------------
# Startup configuration guards
# ---------------------------------------------------------------------------


def test_production_rejects_memory_rate_limit_backend():
    settings = make_settings(
        environment="production",
        api_auth_token="prod-token",
        policy_backend="egress-policy",
        inspection_backend="prompt-injection",
        rate_limit_enabled=True,
        rate_limit_backend="memory",
    )

    with pytest.raises(RateLimitConfigurationError, match="development-only"):
        build_rate_limiter(settings)


def test_production_requires_rate_limiting_enabled():
    settings = make_settings(
        environment="production",
        api_auth_token="prod-token",
        policy_backend="egress-policy",
        inspection_backend="prompt-injection",
        rate_limit_enabled=False,
        rate_limit_backend="redis",
        redis_url="redis://127.0.0.1:6379/0",
    )

    with pytest.raises(RateLimitConfigurationError, match="must be true"):
        build_rate_limiter(settings)


def test_redis_backend_requires_redis_url():
    settings = make_settings(
        rate_limit_backend="redis",
        redis_url="",
    )

    with pytest.raises(RateLimitConfigurationError, match="REDIS_URL"):
        build_rate_limiter(settings)


def test_invalid_trusted_proxy_fails_startup():
    settings = make_settings(rate_limit_trusted_proxies="not-a-network")

    with pytest.raises(ValueError, match="trusted proxy"):
        create_app(settings, browser_client=FakeWorkerClient())
