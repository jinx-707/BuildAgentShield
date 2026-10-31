"""API contract tests for D1 secure actions and D2 screenshots."""

import pytest
from fastapi.testclient import TestClient

from app.clients.browser_worker import BrowserWorkerPolicyError
from app.main import create_app
from tests.conftest import (
    FakeContentInspector,
    FakeWorkerClient,
    make_settings,
    make_test_app,
)

AGENT = {"X-Agent-ID": "agent-42"}


def app_with(worker=None, inspector=None):
    worker = worker or FakeWorkerClient()
    inspector = inspector or FakeContentInspector()
    app = create_app(
        make_settings(),
        browser_client=worker,
        content_inspector=inspector,
    )
    return app, worker, inspector


def test_action_requires_agent_identity():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/action",
            json={
                "session_id": "session-123",
                "action": "click",
                "target": {"selector": "#go"},
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_AGENT_ID"
    assert worker.action_calls == []


def test_action_forwards_identity_and_marks_page_text_untrusted():
    app, worker, inspector = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/action",
            headers=AGENT,
            json={
                "session_id": "session-123",
                "action": "click",
                "target": {"selector": "#go"},
                "timeout_ms": 5000,
            },
        )

    assert response.status_code == 200, response.text
    body = response.json()
    call = worker.action_calls[0]
    assert call["agent_id"] == "agent-42"
    assert call["session_id"] == "session-123"
    assert call["timeout_ms"] == 5000
    assert call["action"] == {
        "action": "click",
        "target": {"selector": "#go"},
    }
    assert body["action"] == "click"
    assert body["success"] is True
    assert body["content"]["text"] == "Visible page text"
    assert body["content"]["byte_length"] == len("Visible page text")
    assert body["security"]["trust_label"] == "untrusted"
    assert "UNTRUSTED_PAGE_CONTENT" in body["security"]["warnings"]
    assert body["inspection"]["inspector_name"] == "fake-inspector"
    assert inspector.calls[0].content == "Visible page text"
    assert inspector.calls[0].url == "https://example.com/"


def test_action_accepts_flat_selector_and_distance_aliases():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        click = client.post(
            "/v1/browser/action",
            headers=AGENT,
            json={
                "session_id": "session-123",
                "action": "click",
                "selector": "#go",
            },
        )
        scroll = client.post(
            "/v1/browser/action",
            headers=AGENT,
            json={
                "session_id": "session-123",
                "action": "scroll",
                "direction": "down",
                "distance": 250,
            },
        )

    assert click.status_code == 200, click.text
    assert scroll.status_code == 200, scroll.text
    assert worker.action_calls[0]["action"] == {
        "action": "click",
        "target": {"selector": "#go"},
    }
    assert worker.action_calls[1]["action"] == {
        "action": "scroll",
        "direction": "down",
        "amount": 250,
    }


def test_action_redacts_typed_values_again_at_the_api_boundary():
    worker = FakeWorkerClient()
    worker.action_response = worker.action_response.model_copy(
        update={
            "action": "type",
            "text": "value=hunter2-secret",
            "warnings": ["UNTRUSTED_PAGE_CONTENT"],
        }
    )
    inspector = FakeContentInspector()
    app, _, _ = app_with(worker=worker, inspector=inspector)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/action",
            headers=AGENT,
            json={
                "session_id": "session-123",
                "action": "type",
                "target": {"selector": "#secret"},
                "text": "hunter2-secret",
            },
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert "hunter2-secret" not in body["content"]["text"]
    assert "[REDACTED]" in body["content"]["text"]
    assert "TYPED_VALUE_REDACTED" in body["security"]["warnings"]
    assert "hunter2-secret" not in inspector.calls[0].content


def test_action_withholds_page_text_for_short_typed_values():
    worker = FakeWorkerClient()
    worker.action_response = worker.action_response.model_copy(
        update={"action": "type", "text": "abc appears here"}
    )
    app, _, _ = app_with(worker=worker)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/action",
            headers=AGENT,
            json={
                "session_id": "session-123",
                "action": "type",
                "target": {"selector": "#pin"},
                "text": "abc",
            },
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["content"]["text"] == ""
    assert body["content"]["text_truncated"] is True
    assert "TYPED_VALUE_TEXT_WITHHELD" in body["security"]["warnings"]
    assert "TEXT_TRUNCATED" in body["security"]["warnings"]


@pytest.mark.parametrize(
    ("worker_status", "worker_code", "api_status"),
    [
        (403, "FORM_SUBMIT_REQUIRES_GUARDED_OPERATION", 403),
        (409, "FORM_CONFIRMATION_REQUIRED", 409),
        (413, "INPUT_LENGTH_EXCEEDED", 413),
        (429, "SCREENSHOT_RATE_LIMITED", 429),
        (503, "BROWSER_CONTEXT_UNAVAILABLE", 503),
        (504, "ACTION_TIMEOUT", 504),
    ],
)
def test_action_worker_failures_preserve_security_status(
    worker_status, worker_code, api_status
):
    worker = FakeWorkerClient()
    worker.action_error = BrowserWorkerPolicyError(
        worker_code, "refused", status_code=worker_status
    )
    app, _, _ = app_with(worker=worker)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/action",
            headers=AGENT,
            json={
                "session_id": "session-123",
                "action": "click",
                "target": {"selector": "#go"},
            },
        )

    assert response.status_code == api_status
    assert response.json()["detail"]["code"] == worker_code


@pytest.mark.parametrize(
    "payload",
    [
        {"session_id": "session-123", "action": "click"},
        {"session_id": "session-123", "action": "type", "target": {"selector": "#x"}},
        {
            "session_id": "session-123",
            "action": "scroll",
            "direction": "down",
        },
        {
            "session_id": "session-123",
            "action": "click",
            "target": {"selector": "#x", "role": "button"},
        },
        {
            "session_id": "session-123",
            "action": "click",
            "target": {"selector": "aria/Submit"},
        },
        {"session_id": "bad id", "action": "page_state"},
    ],
)
def test_action_rejects_invalid_requests_before_the_worker(payload):
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post("/v1/browser/action", headers=AGENT, json=payload)

    assert response.status_code == 422
    assert worker.action_calls == []


def test_screenshot_requires_agent_identity():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/screenshot", json={"session_id": "session-123"}
        )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_AGENT_ID"
    assert worker.screenshot_calls == []


def test_screenshot_forwards_identity_and_returns_safe_binary_response():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/screenshot",
            headers=AGENT,
            json={
                "session_id": "session-123",
                "full_page": False,
                "clip": {"x": 1, "y": 2, "width": 100, "height": 50},
                "timeout_ms": 5000,
            },
        )

    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "image/png"
    assert response.content == worker.screenshot_content
    assert response.headers["content-disposition"] == 'inline; filename="screenshot.png"'
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-screenshot-width"] == "800"
    assert response.headers["x-screenshot-height"] == "600"
    assert response.headers["x-screenshot-bytes"] == str(len(worker.screenshot_content))
    assert response.headers["x-screenshot-full-page"] == "false"
    assert "/" not in response.headers["content-disposition"]

    call = worker.screenshot_calls[0]
    assert call["agent_id"] == "agent-42"
    assert call["session_id"] == "session-123"
    assert call["full_page"] is False
    assert call["clip"] == {"x": 1, "y": 2, "width": 100, "height": 50}
    assert call["timeout_ms"] == 5000


def test_screenshot_rejects_full_page_and_clip_before_the_worker():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/screenshot",
            headers=AGENT,
            json={
                "session_id": "session-123",
                "full_page": True,
                "clip": {"x": 0, "y": 0, "width": 10, "height": 10},
            },
        )

    assert response.status_code == 422
    assert worker.screenshot_calls == []


@pytest.mark.parametrize(
    ("worker_status", "worker_code", "api_status"),
    [
        (403, "SESSION_FORBIDDEN", 403),
        (404, "SESSION_NOT_FOUND", 404),
        (409, "SESSION_CHECKED_OUT", 409),
        (413, "SCREENSHOT_DIMENSIONS_EXCEEDED", 413),
        (429, "SCREENSHOT_RATE_LIMITED", 429),
        (503, "SCREENSHOT_CONCURRENCY_LIMIT", 503),
        (504, "SCREENSHOT_TIMEOUT", 504),
    ],
)
def test_screenshot_worker_failures_preserve_security_status(
    worker_status, worker_code, api_status
):
    worker = FakeWorkerClient()
    worker.screenshot_error = BrowserWorkerPolicyError(
        worker_code, "refused", status_code=worker_status
    )
    app, _, _ = app_with(worker=worker)
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/screenshot",
            headers=AGENT,
            json={"session_id": "session-123"},
        )

    assert response.status_code == api_status
    assert response.json()["detail"]["code"] == worker_code


def test_screenshot_rejects_malformed_session_id_before_the_worker():
    app, worker, _ = app_with()
    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/screenshot",
            headers=AGENT,
            json={"session_id": "bad id"},
        )

    assert response.status_code == 422
    assert worker.screenshot_calls == []
