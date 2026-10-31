import json

import httpx
import pytest

from app.clients.browser_worker import (
    BrowserWorkerClient,
    BrowserWorkerResponseError,
    BrowserWorkerTimeout,
    BrowserWorkerUnavailable,
)
from tests.conftest import make_settings


def build_client(handler) -> BrowserWorkerClient:
    return BrowserWorkerClient(
        make_settings(), transport=httpx.MockTransport(handler)
    )


async def test_health_live_parses_worker_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/health/live"
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "service": "agentshield-browser-worker",
                "version": "0.1.0",
                "checks": {"process": "ok"},
            },
        )

    client = build_client(handler)
    try:
        result = await client.health_live()
    finally:
        await client.aclose()

    assert result.status == "ok"
    assert result.checks == {"process": "ok"}


async def test_health_ready_accepts_degraded_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            json={
                "status": "degraded",
                "service": "agentshield-browser-worker",
                "version": "0.1.0",
                "checks": {"browser": "unavailable"},
            },
        )

    client = build_client(handler)
    try:
        result = await client.health_ready()
    finally:
        await client.aclose()

    assert result.status == "degraded"


async def test_navigate_forwards_payload_and_request_id():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["request_id"] = request.headers["x-request-id"]
        captured["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "request_id": "req-42",
                "requested_url": "https://example.com/",
                "final_url": "https://example.com/",
                "status_code": 200,
                "title": "Example",
                "content": "<html></html>",
                "content_truncated": False,
                "elapsed_ms": 12,
            },
        )

    client = build_client(handler)
    try:
        result = await client.navigate(
            url="https://example.com/",
            wait_until="load",
            timeout_ms=5000,
            request_id="req-42",
        )
    finally:
        await client.aclose()

    assert captured["path"] == "/v1/navigate"
    assert captured["request_id"] == "req-42"
    assert captured["payload"] == {
        "url": "https://example.com/",
        "wait_until": "load",
        "timeout_ms": 5000,
    }
    assert result.final_url == "https://example.com/"


async def test_navigate_maps_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client = build_client(handler)
    try:
        with pytest.raises(BrowserWorkerTimeout):
            await client.navigate(
                url="https://example.com/",
                wait_until="load",
                timeout_ms=5000,
                request_id="req-42",
            )
    finally:
        await client.aclose()


async def test_navigate_maps_connection_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = build_client(handler)
    try:
        with pytest.raises(BrowserWorkerUnavailable):
            await client.navigate(
                url="https://example.com/",
                wait_until="load",
                timeout_ms=5000,
                request_id="req-42",
            )
    finally:
        await client.aclose()


async def test_navigate_rejects_error_status():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "internal_error"})

    client = build_client(handler)
    try:
        with pytest.raises(BrowserWorkerResponseError):
            await client.navigate(
                url="https://example.com/",
                wait_until="load",
                timeout_ms=5000,
                request_id="req-42",
            )
    finally:
        await client.aclose()


async def test_navigate_rejects_invalid_response_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    client = build_client(handler)
    try:
        with pytest.raises(BrowserWorkerResponseError):
            await client.navigate(
                url="https://example.com/",
                wait_until="load",
                timeout_ms=5000,
                request_id="req-42",
            )
    finally:
        await client.aclose()


def session_payload(session_id="session-123"):
    return {
        "session_id": session_id,
        "state": "idle",
        "status": "idle",
        "created_at": "2026-01-01T00:00:00Z",
        "last_used_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:15:00Z",
        "idle_timeout_ms": 300000,
        "max_age_ms": 900000,
        "active_requests": 0,
        "closing_requested": False,
        "current_url": "https://example.com/",
    }


async def test_create_session_accepts_201_and_forwards_identity():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["headers"] = dict(request.headers)
        captured["payload"] = json.loads(request.content)
        return httpx.Response(201, json=session_payload())

    client = build_client(handler)
    try:
        result = await client.create_session(
            agent_id="agent-42",
            request_id="req-42",
            idle_timeout_ms=60000,
        )
    finally:
        await client.aclose()

    assert captured["path"] == "/v1/session"
    assert captured["headers"]["x-agent-id"] == "agent-42"
    assert captured["headers"]["x-request-id"] == "req-42"
    assert "x-agent-session" not in captured["headers"]
    assert captured["payload"] == {"idle_timeout_ms": 60000}
    assert result.session_id == "session-123"


async def test_get_close_and_extract_forward_identity_headers():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            {
                "method": request.method,
                "path": request.url.path,
                "headers": dict(request.headers),
                "payload": json.loads(request.content or b"{}"),
            }
        )
        if request.url.path == "/v1/extract":
            return httpx.Response(
                200,
                json={
                    "request_id": "req-42",
                    "session_id": "session-123",
                    "metadata": {"title": "Example", "url": "https://example.com/"},
                    "text": "Visible text",
                    "links": [],
                    "lists": [],
                    "tables": [],
                },
            )
        if request.method == "DELETE":
            return httpx.Response(
                200,
                json={
                    "session_id": "session-123",
                    "closed": True,
                    "closing": False,
                    "request_id": "req-42",
                },
            )
        return httpx.Response(200, json=session_payload())

    client = build_client(handler)
    try:
        await client.get_session(
            session_id="session-123", agent_id="agent-42", request_id="req-42"
        )
        await client.close_session(
            session_id="session-123", agent_id="agent-42", request_id="req-42"
        )
        extracted = await client.extract(
            session_id="session-123", agent_id="agent-42", request_id="req-42"
        )
    finally:
        await client.aclose()

    assert [(item["method"], item["path"]) for item in seen] == [
        ("GET", "/v1/session/session-123"),
        ("DELETE", "/v1/session/session-123"),
        ("POST", "/v1/extract"),
    ]
    for item in seen:
        assert item["headers"]["x-agent-id"] == "agent-42"
        assert item["headers"]["x-request-id"] == "req-42"
    assert seen[2]["headers"]["x-agent-session"] == "session-123"
    assert seen[2]["payload"] == {}
    assert extracted.text == "Visible text"


async def test_session_owner_error_maps_to_policy_error():
    from app.clients.browser_worker import BrowserWorkerPolicyError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "error": "forbidden",
                "code": "SESSION_FORBIDDEN",
                "message": "session is not owned by this agent",
                "request_id": "req-42",
            },
        )

    client = build_client(handler)
    try:
        with pytest.raises(BrowserWorkerPolicyError) as caught:
            await client.get_session(
                session_id="session-123", agent_id="agent-42", request_id="req-42"
            )
    finally:
        await client.aclose()

    assert caught.value.status_code == 403
    assert caught.value.code == "SESSION_FORBIDDEN"


async def test_action_forwards_payload_and_identity_headers():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["headers"] = dict(request.headers)
        captured["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "request_id": "req-42",
                "session_id": "session-123",
                "action": "click",
                "success": True,
                "target": {"tag": "button", "role": "button", "name": "Go"},
                "final_url": "https://example.com/next",
                "title": "Next",
                "text": "Visible text",
                "warnings": ["UNTRUSTED_PAGE_CONTENT"],
            },
        )

    client = build_client(handler)
    try:
        result = await client.action(
            session_id="session-123",
            agent_id="agent-42",
            request_id="req-42",
            action={"action": "click", "target": {"selector": "#go"}},
            timeout_ms=7000,
        )
    finally:
        await client.aclose()

    assert captured["path"] == "/v1/action"
    assert captured["headers"]["x-agent-id"] == "agent-42"
    assert captured["headers"]["x-agent-session"] == "session-123"
    assert captured["headers"]["x-request-id"] == "req-42"
    assert captured["payload"] == {
        "action": "click",
        "target": {"selector": "#go"},
        "timeout_ms": 7000,
    }
    assert result.final_url == "https://example.com/next"
    assert result.target["name"] == "Go"


async def test_action_maps_timeout_status_to_policy_error():
    from app.clients.browser_worker import BrowserWorkerPolicyError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            504,
            json={
                "error": "timeout",
                "code": "ACTION_TIMEOUT",
                "message": "browser action timed out",
                "request_id": "req-42",
            },
        )

    client = build_client(handler)
    try:
        with pytest.raises(BrowserWorkerPolicyError) as caught:
            await client.action(
                session_id="session-123",
                agent_id="agent-42",
                request_id="req-42",
                action={"action": "page_state"},
                timeout_ms=5000,
            )
    finally:
        await client.aclose()

    assert caught.value.status_code == 504
    assert caught.value.code == "ACTION_TIMEOUT"


def png_bytes(width: int = 800, height: int = 600) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00" * 8
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + b"\x00" * 8
    )


async def test_screenshot_parses_binary_png_and_metadata():
    content = png_bytes()
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["headers"] = dict(request.headers)
        captured["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            content=content,
            headers={
                "content-type": "image/png",
                "x-screenshot-width": "800",
                "x-screenshot-height": "600",
                "x-screenshot-bytes": str(len(content)),
                "x-screenshot-full-page": "false",
                "x-screenshot-elapsed-ms": "9",
            },
        )

    client = build_client(handler)
    try:
        result = await client.screenshot(
            session_id="session-123",
            agent_id="agent-42",
            request_id="req-42",
            full_page=False,
            clip={"x": 1, "y": 2, "width": 100, "height": 50},
            timeout_ms=7000,
        )
    finally:
        await client.aclose()

    assert captured["path"] == "/v1/screenshot"
    assert captured["headers"]["x-agent-id"] == "agent-42"
    assert captured["headers"]["x-agent-session"] == "session-123"
    assert captured["payload"] == {
        "full_page": False,
        "clip": {"x": 1, "y": 2, "width": 100, "height": 50},
        "timeout_ms": 7000,
    }
    assert result.content == content
    assert result.width == 800
    assert result.height == 600
    assert result.bytes == len(content)
    assert result.full_page is False
    assert result.elapsed_ms == 9


async def test_screenshot_rejects_invalid_png_and_metadata():
    from app.clients.browser_worker import BrowserWorkerResponseError

    content = png_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"not-a-png",
            headers={
                "content-type": "image/png",
                "x-screenshot-width": "800",
                "x-screenshot-height": "600",
                "x-screenshot-bytes": "9",
                "x-screenshot-full-page": "false",
                "x-screenshot-elapsed-ms": "9",
            },
        )

    client = build_client(handler)
    try:
        with pytest.raises(BrowserWorkerResponseError):
            await client.screenshot(
                session_id="session-123",
                agent_id="agent-42",
                request_id="req-42",
                full_page=False,
                clip=None,
                timeout_ms=5000,
            )
    finally:
        await client.aclose()

    def inconsistent_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=content,
            headers={
                "content-type": "image/png",
                "x-screenshot-width": "801",
                "x-screenshot-height": "600",
                "x-screenshot-bytes": str(len(content)),
                "x-screenshot-full-page": "false",
                "x-screenshot-elapsed-ms": "9",
            },
        )

    client = build_client(inconsistent_handler)
    try:
        with pytest.raises(BrowserWorkerResponseError):
            await client.screenshot(
                session_id="session-123",
                agent_id="agent-42",
                request_id="req-42",
                full_page=False,
                clip=None,
                timeout_ms=5000,
            )
    finally:
        await client.aclose()


async def test_screenshot_maps_limits_to_policy_error():
    from app.clients.browser_worker import BrowserWorkerPolicyError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            413,
            json={
                "error": "payload_too_large",
                "code": "SCREENSHOT_DIMENSIONS_EXCEEDED",
                "message": "too large",
                "request_id": "req-42",
            },
        )

    client = build_client(handler)
    try:
        with pytest.raises(BrowserWorkerPolicyError) as caught:
            await client.screenshot(
                session_id="session-123",
                agent_id="agent-42",
                request_id="req-42",
                full_page=True,
                clip=None,
                timeout_ms=5000,
            )
    finally:
        await client.aclose()

    assert caught.value.status_code == 413
    assert caught.value.code == "SCREENSHOT_DIMENSIONS_EXCEEDED"
