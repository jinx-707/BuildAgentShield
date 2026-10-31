"""Real Redis integration for shared and fail-closed rate limiting."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import FakeWorkerClient, make_settings

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def redis_url():
    binary = shutil.which("redis-server")
    if binary is None:
        pytest.skip("redis-server is not installed")

    port = _free_port()
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
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"redis://127.0.0.1:{port}/0"
    try:
        import redis

        client = redis.Redis.from_url(url, socket_connect_timeout=0.2)
        deadline = time.monotonic() + 5
        while True:
            try:
                client.ping()
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise RuntimeError("redis-server did not become ready")
                time.sleep(0.05)
        client.close()
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture(autouse=True)
def _clean_redis(redis_url):
    import redis

    client = redis.Redis.from_url(redis_url, socket_connect_timeout=0.5)
    client.flushdb()
    client.close()
    yield


def _settings(redis_url: str, **overrides):
    return make_settings(
        rate_limit_backend="redis",
        redis_url=redis_url,
        rate_limit_per_minute=2,
        redis_timeout_seconds=0.5,
        **overrides,
    )


def _get(client, path="/health"):
    return client.get(path)


def test_two_replicas_share_one_limit(redis_url):
    worker_a = FakeWorkerClient()
    worker_b = FakeWorkerClient()
    app_a = create_app(_settings(redis_url), browser_client=worker_a)
    app_b = create_app(_settings(redis_url), browser_client=worker_b)

    with TestClient(app_a, raise_server_exceptions=False) as client:
        assert _get(client).status_code == 200
        assert _get(client).status_code == 200

    with TestClient(app_b, raise_server_exceptions=False) as client:
        response = _get(client)

    assert response.status_code == 429
    assert response.json()["code"] == "RATE_LIMIT_EXCEEDED"


def test_redis_keys_expire(redis_url):
    app = create_app(_settings(redis_url), browser_client=FakeWorkerClient())

    with TestClient(app, raise_server_exceptions=False) as client:
        assert _get(client).status_code == 200

    import redis

    client = redis.Redis.from_url(redis_url, socket_connect_timeout=0.5)
    try:
        keys = list(client.scan_iter("agentshield:ratelimit:*"))
        assert keys
        assert all(client.pttl(key) > 0 for key in keys)
    finally:
        client.close()


def test_unavailable_redis_returns_503_by_default():
    app = create_app(
        _settings("redis://127.0.0.1:1/0"),
        browser_client=FakeWorkerClient(),
    )

    with TestClient(app, raise_server_exceptions=False) as client:
        response = _get(client)

    assert response.status_code == 503
    assert response.json()["code"] == "RATE_LIMIT_BACKEND_UNAVAILABLE"
    assert response.headers["retry-after"] == "1"


def test_unavailable_redis_can_be_explicitly_fail_open():
    app = create_app(
        _settings("redis://127.0.0.1:1/0", rate_limit_fail_open=True),
        browser_client=FakeWorkerClient(),
    )

    with TestClient(app, raise_server_exceptions=False) as client:
        response = _get(client)

    assert response.status_code == 200
