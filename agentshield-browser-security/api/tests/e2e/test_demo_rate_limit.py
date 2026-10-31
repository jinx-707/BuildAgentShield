"""DEMO 9: rate limiting is shared across replicas and cannot be spoofed."""

from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import httpx
import pytest
import redis

from .helpers import (
    API_TOKEN,
    ApiStack,
    Service,
    free_port,
    start_api,
)

pytestmark = pytest.mark.e2e

NAVIGATE_PAYLOAD = {
    "url": "https://example.com/",
    "wait_until": "domcontentloaded",
    "timeout_ms": 5000,
}


def _wait_for_redis(url: str, timeout: float = 15.0) -> None:
    client = redis.Redis.from_url(url)
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if client.ping():
                client.close()
                return
        except Exception as exc:  # noqa: BLE001 - surfaced below
            last_error = exc
        time.sleep(0.1)
    raise AssertionError(f"redis did not start: {last_error}")


@pytest.fixture(scope="module")
def redis_server():
    binary = shutil.which("redis-server")
    if not binary:
        pytest.skip("redis-server is not installed")
    port = free_port()
    log_dir = Path(tempfile.mkdtemp(prefix="agentshield-redis-"))
    log_path = log_dir / "redis.log"
    log_file = log_path.open("ab")
    process = subprocess.Popen(
        [
            binary,
            "--bind",
            "127.0.0.1",
            "--port",
            str(port),
            "--save",
            "",
            "--appendonly",
            "no",
            "--protected-mode",
            "no",
        ],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    service = Service(name="redis", process=process, log_path=log_path)
    url = f"redis://127.0.0.1:{port}/0"
    try:
        _wait_for_redis(url)
        yield url
    finally:
        service.stop()


def _limit_env(redis_url: str, *, trusted: bool) -> dict[str, str]:
    return {
        "RATE_LIMIT_BACKEND": "redis",
        "REDIS_URL": redis_url,
        "REDIS_TIMEOUT_SECONDS": "2",
        "RATE_LIMIT_PER_MINUTE": "1000",
        "RATE_LIMIT_NAVIGATION_PER_MINUTE": "2",
        "RATE_LIMIT_WINDOW_SECONDS": "60",
        "RATE_LIMIT_TRUSTED_PROXIES": "127.0.0.1/32" if trusted else "",
    }


@pytest.fixture(scope="module")
def replica_a(redis_server: str) -> ApiStack:
    return start_api(
        name="replica-a",
        log_dir=Path(tempfile.mkdtemp(prefix="agentshield-replica-a-")),
        worker_url="http://127.0.0.1:1",
        proxy=None,
        extra_env=_limit_env(redis_server, trusted=True),
        wait_ready=False,
    )


@pytest.fixture(scope="module")
def replica_b(redis_server: str) -> ApiStack:
    return start_api(
        name="replica-b",
        log_dir=Path(tempfile.mkdtemp(prefix="agentshield-replica-b-")),
        worker_url="http://127.0.0.1:1",
        proxy=None,
        extra_env=_limit_env(redis_server, trusted=True),
        wait_ready=False,
    )


@pytest.fixture(scope="module")
def untrusted_replica(redis_server: str) -> ApiStack:
    return start_api(
        name="replica-untrusted",
        log_dir=Path(tempfile.mkdtemp(prefix="agentshield-replica-untrusted-")),
        worker_url="http://127.0.0.1:1",
        proxy=None,
        extra_env=_limit_env(redis_server, trusted=False),
        wait_ready=False,
    )


def _navigate(url: str, forwarded_for: str | None = None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    if forwarded_for is not None:
        headers["X-Forwarded-For"] = forwarded_for
    return httpx.post(
        f"{url}/v1/browser/navigate",
        json=NAVIGATE_PAYLOAD,
        headers=headers,
        timeout=15.0,
    )


def _assert_limited(response: httpx.Response) -> None:
    assert response.status_code == 429, response.text
    body = response.json()
    assert body["code"] == "RATE_LIMIT_EXCEEDED"
    assert body["category"] == "navigation"
    assert body["scope"] == "ip"
    assert int(response.headers["retry-after"]) >= 1


def test_counter_is_shared_across_replicas(
    replica_a: ApiStack, replica_b: ApiStack
) -> None:
    client_ip = "203.0.113.10"
    first = _navigate(replica_a.url, client_ip)
    second = _navigate(replica_a.url, client_ip)
    assert first.status_code != 429, first.text
    assert second.status_code != 429, second.text

    third = _navigate(replica_b.url, client_ip)
    _assert_limited(third)


def test_trusted_forwarded_for_gets_its_own_bucket(replica_a: ApiStack) -> None:
    first = _navigate(replica_a.url, "203.0.113.20")
    second = _navigate(replica_a.url, "203.0.113.20")
    assert first.status_code != 429, first.text
    assert second.status_code != 429, second.text

    other = _navigate(replica_a.url, "203.0.113.21")
    assert other.status_code != 429, other.text


def test_forwarded_for_is_ignored_from_untrusted_peer(
    untrusted_replica: ApiStack,
) -> None:
    for index in range(2):
        response = _navigate(untrusted_replica.url, f"198.51.100.{index + 1}")
        assert response.status_code != 429, response.text

    limited = _navigate(untrusted_replica.url, "198.51.100.99")
    _assert_limited(limited)


def test_malformed_forwarded_for_is_rejected(replica_a: ApiStack) -> None:
    response = _navigate(replica_a.url, "not-an-ip")

    assert response.status_code == 400, response.text
    assert response.json()["code"] == "INVALID_FORWARDED_FOR"
