"""DEMO 10: dependency failures and hostile input fail safely."""

from __future__ import annotations

import socket
import tempfile
import threading
import time
from pathlib import Path
import httpx
import pytest

from .helpers import (
    API_TOKEN,
    ApiClient,
    ApiStack,
    FixtureSite,
    free_port,
    start_api,
    start_worker,
)

pytestmark = pytest.mark.e2e


def _api(name: str, **kwargs) -> ApiStack:
    return start_api(
        name=name,
        log_dir=Path(tempfile.mkdtemp(prefix=f"agentshield-{name}-")),
        wait_ready=False,
        **kwargs,
    )


@pytest.fixture(scope="module")
def dead_worker_api() -> ApiStack:
    return _api(
        "dead-worker",
        worker_url="http://127.0.0.1:1",
        proxy=None,
        extra_env={"ALLOWED_DOMAINS": "example.com"},
    )


@pytest.fixture(scope="module")
def rate_limit_closed_api() -> ApiStack:
    return _api(
        "rate-limit-closed",
        worker_url="http://127.0.0.1:1",
        proxy=None,
        extra_env={
            "ALLOWED_DOMAINS": "example.com",
            "RATE_LIMIT_BACKEND": "redis",
            "REDIS_URL": "redis://127.0.0.1:1/0",
            "REDIS_TIMEOUT_SECONDS": "0.5",
            "RATE_LIMIT_FAIL_OPEN": "false",
        },
    )


@pytest.fixture(scope="module")
def rate_limit_open_api() -> ApiStack:
    return _api(
        "rate-limit-open",
        worker_url="http://127.0.0.1:1",
        proxy=None,
        extra_env={
            "ALLOWED_DOMAINS": "example.com",
            "RATE_LIMIT_BACKEND": "redis",
            "REDIS_URL": "redis://127.0.0.1:1/0",
            "REDIS_TIMEOUT_SECONDS": "0.5",
            "RATE_LIMIT_FAIL_OPEN": "true",
        },
    )


class BlackholeProxy:
    """Accepts TCP connections and never answers, forcing a client timeout."""

    def __init__(self) -> None:
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(16)
        self.port = self.server.getsockname()[1]
        self.connections: list[socket.socket] = []
        self.thread = threading.Thread(target=self._accept, daemon=True)

    def _accept(self) -> None:
        while True:
            try:
                connection, _ = self.server.accept()
            except OSError:
                return
            self.connections.append(connection)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        for connection in self.connections:
            try:
                connection.close()
            except OSError:
                pass
        self.server.close()


@pytest.fixture(scope="module")
def blackhole_proxy():
    proxy = BlackholeProxy()
    proxy.start()
    try:
        yield proxy
    finally:
        proxy.stop()


@pytest.fixture(scope="module")
def search_timeout_api(blackhole_proxy) -> ApiStack:
    return _api(
        "search-timeout",
        worker_url="http://127.0.0.1:1",
        proxy=None,
        extra_env={
            "SEARCH_PROVIDER": "duckduckgo",
            "SEARCH_TIMEOUT_MS": "500",
            "HTTPS_PROXY": f"http://127.0.0.1:{blackhole_proxy.port}",
        },
    )


@pytest.fixture(scope="module")
def search_outage_api() -> ApiStack:
    dead_proxy_port = free_port()
    return _api(
        "search-outage",
        worker_url="http://127.0.0.1:1",
        proxy=None,
        extra_env={
            "SEARCH_PROVIDER": "duckduckgo",
            "SEARCH_TIMEOUT_MS": "1000",
            "HTTPS_PROXY": f"http://127.0.0.1:{dead_proxy_port}",
        },
    )


@pytest.fixture(scope="module")
def broken_browser_api(fixture_site: FixtureSite) -> ApiStack:
    worker = start_worker(
        log_dir=Path(tempfile.mkdtemp(prefix="agentshield-broken-browser-worker-")),
        proxy=None,
        allow_private=True,
        allowed_domains="127.0.0.1",
        extra_env={"BROWSER_EXECUTABLE_PATH": "/nonexistent/agentshield-chrome"},
    )
    api = _api(
        "broken-browser",
        worker_url=worker.url,
        proxy=None,
        extra_env={"ALLOWED_DOMAINS": "127.0.0.1"},
    )
    try:
        yield api
    finally:
        worker.service.stop()


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {API_TOKEN}"}


def _navigate(url: str, target: str) -> httpx.Response:
    return httpx.post(
        f"{url}/v1/browser/navigate",
        json={"url": target, "wait_until": "domcontentloaded", "timeout_ms": 5000},
        headers=_auth_headers(),
        timeout=20.0,
    )


def test_worker_unavailable_is_reported_not_hidden(dead_worker_api: ApiStack) -> None:
    response = _navigate(dead_worker_api.url, "https://example.com/")

    assert response.status_code == 502, response.text
    assert response.json()["detail"]["code"] == "browser_worker_failure"


def test_rate_limit_backend_failure_fails_closed(rate_limit_closed_api: ApiStack) -> None:
    response = _navigate(rate_limit_closed_api.url, "https://example.com/")

    assert response.status_code == 503, response.text
    assert response.json()["code"] == "RATE_LIMIT_BACKEND_UNAVAILABLE"
    assert response.headers["retry-after"] == "1"


def test_rate_limit_backend_failure_can_fail_open_only_when_configured(
    rate_limit_open_api: ApiStack,
) -> None:
    response = _navigate(rate_limit_open_api.url, "https://example.com/")

    assert response.status_code == 502, response.text
    assert response.json()["detail"]["code"] == "browser_worker_failure"


def test_search_provider_timeout_returns_504(search_timeout_api: ApiStack) -> None:
    response = httpx.post(
        f"{search_timeout_api.url}/v1/browser/search",
        json={"query": "python", "max_results": 3},
        headers=_auth_headers(),
        timeout=20.0,
    )

    assert response.status_code == 504, response.text
    assert response.json()["detail"]["code"] == "SEARCH_PROVIDER_TIMEOUT"


def test_search_provider_outage_returns_503(search_outage_api: ApiStack) -> None:
    response = httpx.post(
        f"{search_outage_api.url}/v1/browser/search",
        json={"query": "python", "max_results": 3},
        headers=_auth_headers(),
        timeout=20.0,
    )

    assert response.status_code == 503, response.text
    assert response.json()["detail"]["code"] == "SEARCH_PROVIDER_UNAVAILABLE"


def test_browser_launch_failure_is_reported(
    broken_browser_api: ApiStack, fixture_site: FixtureSite
) -> None:
    response = _navigate(broken_browser_api.url, fixture_site.url("/page"))

    assert response.status_code == 502, response.text
    assert response.json()["detail"]["code"] == "browser_worker_failure"


def test_session_expiration_during_action(
    api: ApiClient, fixture_site: FixtureSite
) -> None:
    created = api.create_session(agent_id="agent-expiring", timeout_ms=30000)
    assert created.status_code == 201, created.text
    session_id = created.json()["session_id"]

    time.sleep(32.5)

    response = api.action(
        session_id,
        {"action": "page_state"},
        agent_id="agent-expiring",
    )

    assert response.status_code == 404, response.text
    assert response.json()["detail"]["code"] == "SESSION_NOT_FOUND"


def test_invalid_url_and_action_are_rejected(api: ApiClient) -> None:
    bad_url = api.navigate("file:///etc/passwd")
    assert bad_url.status_code == 422, bad_url.text

    bad_action = api.action(
        "session-does-not-exist",
        {"action": "run_javascript", "script": "alert(1)"},
        agent_id="agent-input",
    )
    assert bad_action.status_code == 422, bad_action.text


def test_wrong_api_token_is_rejected(dead_worker_api: ApiStack) -> None:
    response = httpx.post(
        f"{dead_worker_api.url}/v1/browser/navigate",
        json={"url": "https://example.com/"},
        headers={"Authorization": "Bearer wrong-token"},
        timeout=10.0,
    )

    assert response.status_code == 401, response.text


def test_oversized_screenshot_clip_is_rejected(
    api: ApiClient, fixture_site: FixtureSite
) -> None:
    created = api.create_session(agent_id="agent-shot")
    assert created.status_code == 201, created.text
    session_id = created.json()["session_id"]
    try:
        navigation = api.navigate(
            fixture_site.url("/page"), session_id=session_id, agent_id="agent-shot"
        )
        assert navigation.status_code == 200, navigation.text

        response = api.screenshot(
            session_id,
            agent_id="agent-shot",
            clip={"x": 0, "y": 0, "width": 100000, "height": 100000},
        )
        assert response.status_code == 413, response.text
        assert response.json()["detail"]["code"] == "SCREENSHOT_DIMENSIONS_EXCEEDED"
    finally:
        api.close_session(session_id, agent_id="agent-shot")
