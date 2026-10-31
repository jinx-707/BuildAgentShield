from fastapi.testclient import TestClient

from app.clients.browser_worker import BrowserWorkerUnavailable
from app.schemas.health import WorkerHealthResponse
from tests.conftest import FakeWorkerClient, make_settings, make_test_app


def test_liveness_returns_ok_and_request_id(test_app):
    with TestClient(test_app) as client:
        response = client.get("/health/live", headers={"X-Request-ID": "req-123"})

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "req-123"
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"] == {"process": "ok"}
    assert body["service"] == "agentshield-browser-security-api"


def test_liveness_generates_request_id_when_missing(test_app):
    with TestClient(test_app) as client:
        response = client.get("/health/live")

    assert response.status_code == 200
    assert len(response.headers["x-request-id"]) == 32


def test_readiness_reports_worker_ok(test_app):
    with TestClient(test_app) as client:
        response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["checks"] == {"browser_worker": "ok"}


def test_health_alias_reports_worker_ok(test_app):
    with TestClient(test_app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["checks"] == {"browser_worker": "ok"}


def test_readiness_returns_503_when_worker_unavailable():
    worker = FakeWorkerClient()
    worker.health_error = BrowserWorkerUnavailable("connection refused")
    app = make_test_app(make_settings(), worker)

    with TestClient(app) as client:
        response = client.get("/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"] == {"browser_worker": "unavailable"}
    assert body["detail"] == "browser worker readiness check failed"


def test_readiness_returns_503_when_worker_degraded():
    worker = FakeWorkerClient()
    worker.health_response = WorkerHealthResponse(
        status="degraded",
        service="agentshield-browser-worker",
        version="0.1.0",
        checks={"browser": "unavailable"},
    )
    app = make_test_app(make_settings(), worker)

    with TestClient(app) as client:
        response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["checks"] == {"browser_worker": "degraded"}
