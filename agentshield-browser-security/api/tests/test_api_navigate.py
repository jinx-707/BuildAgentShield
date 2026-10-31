from fastapi.testclient import TestClient

from app.clients.browser_worker import (
    BrowserWorkerPolicyError,
    BrowserWorkerResponseError,
    BrowserWorkerTimeout,
    BrowserWorkerUnavailable,
)
from tests.conftest import FakeWorkerClient, make_settings, make_test_app


def test_navigate_orchestrates_worker_and_inspection(test_app, fake_worker):
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            headers={"X-Request-ID": "req-navigate"},
            json={
                "url": "https://example.com/",
                "wait_until": "load",
                "timeout_ms": 5000,
            },
        )

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "req-navigate"
    body = response.json()
    assert body["request_id"] == "req-navigate"
    assert body["final_url"] == "https://example.com/"
    assert body["policy"]["allowed"] is True
    assert body["inspection"]["inspector_name"] == "mock-content-inspector"
    assert {finding["rule_id"] for finding in body["inspection"]["findings"]} == {
        "script-tag"
    }
    assert fake_worker.navigate_calls[0]["request_id"] == "req-navigate"
    assert fake_worker.navigate_calls[0]["wait_until"] == "load"
    assert fake_worker.navigate_calls[0]["timeout_ms"] == 5000


def test_navigate_denies_urls_with_credentials(test_app):
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://user:password@example.com/"},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "INVALID_URL"


def test_navigate_returns_504_on_worker_timeout():
    worker = FakeWorkerClient()
    worker.navigate_error = BrowserWorkerTimeout("worker timed out")
    app = make_test_app(make_settings(), worker)

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )

    assert response.status_code == 504
    assert response.json()["detail"]["code"] == "browser_worker_timeout"


def test_navigate_maps_worker_navigation_timeout_to_504():
    worker = FakeWorkerClient()
    worker.navigate_error = BrowserWorkerPolicyError(
        "NAVIGATION_TIMEOUT", "Navigation timed out", status_code=504
    )
    app = make_test_app(make_settings(), worker)

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )

    assert response.status_code == 504
    assert response.json()["detail"]["code"] == "NAVIGATION_TIMEOUT"


def test_navigate_returns_502_on_worker_unavailable():
    worker = FakeWorkerClient()
    worker.navigate_error = BrowserWorkerUnavailable("connection refused")
    app = make_test_app(make_settings(), worker)

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )

    assert response.status_code == 502
    assert response.json()["detail"]["code"] == "browser_worker_failure"


def test_navigate_returns_502_on_worker_bad_response():
    worker = FakeWorkerClient()
    worker.navigate_error = BrowserWorkerResponseError("bad response")
    app = make_test_app(make_settings(), worker)

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "https://example.com/"},
        )

    assert response.status_code == 502
    assert response.json()["detail"]["code"] == "browser_worker_failure"


def test_navigate_validates_request_body(test_app):
    with TestClient(test_app) as client:
        response = client.post(
            "/v1/browser/navigate",
            json={"url": "ftp://example.com/"},
        )

    assert response.status_code == 422
