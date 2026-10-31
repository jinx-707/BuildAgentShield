"""DEMO 1, 3, 4, 5, 6, 7, 8 and the supported feature surface.

These tests drive the real API process, real worker, real egress proxy, and a
real Chromium instance. The only controlled component is the HTTP fixture
origin, which exists so the suite does not depend on a third-party site for
functional behaviour.
"""

from __future__ import annotations

import httpx
import pytest

from .helpers import ApiClient, FixtureSite, Stack

pytestmark = pytest.mark.e2e


def _assert_error(response: httpx.Response, status: int, code: str) -> dict:
    assert response.status_code == status, response.text
    detail = response.json().get("detail")
    assert isinstance(detail, dict), response.text
    assert detail.get("code") == code, response.text
    return detail


def test_demo1_allowed_https_site(api: ApiClient) -> None:
    try:
        httpx.get("https://example.com/", timeout=10.0)
    except httpx.HTTPError as exc:
        pytest.skip(f"external network unavailable: {exc}")

    response = api.navigate("https://example.com/")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["final_url"].startswith("https://example.com/")
    assert "Example Domain" in (body["title"] or "")
    assert "Example Domain" in body["content"]
    assert body["policy"]["allowed"] is True
    assert body["inspection"]["trust_label"] == "untrusted"
    assert body["blocked_request_count"] == 0


def test_demo3_destination_outside_allowlist_is_denied(api: ApiClient) -> None:
    response = api.navigate("https://example.org/")

    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["code"] in {
        "policy_denied",
        "DOMAIN_NOT_ALLOWED",
        "DOMAIN_BLOCKED",
    }, detail


def test_demo4_prompt_injection_page_is_flagged(
    api: ApiClient, fixture_site: FixtureSite
) -> None:
    response = api.navigate(fixture_site.url("/inject"))

    assert response.status_code == 200, response.text
    body = response.json()
    inspection = body["inspection"]
    assert inspection["trust_label"] == "untrusted"
    assert inspection["content_classification"] == "suspicious"
    assert inspection["findings"], inspection
    assert inspection["highest_severity"] in {"high", "critical"}
    assert any(
        "instruction" in finding["message"].lower()
        for finding in inspection["findings"]
    )


def test_demo5_real_search_provider_returns_normalized_results(api: ApiClient) -> None:
    response = api.search("Python (programming language)")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider"] == "duckduckgo-instant-answer"
    assert body["provider_mode"] == "limited_fallback"
    assert body["trust_label"] == "untrusted"
    assert body["results"], body
    first = body["results"][0]
    assert first["url"].startswith("https://")
    assert first["source"]
    assert first["trust_label"] == "untrusted"
    assert body["inspection"]["trust_label"] == "untrusted"


def test_demo6_redirect_chain_is_followed_within_policy(
    api: ApiClient, fixture_site: FixtureSite
) -> None:
    response = api.navigate(
        fixture_site.url("/redirect-chain?to=/page"),
        wait_until="networkidle2",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["final_url"].endswith("/page")
    assert body["redirect_count"] >= 1
    assert "Fixture Home" in body["content"]


def test_demo6_redirect_to_metadata_address_is_blocked(
    api: ApiClient, fixture_site: FixtureSite
) -> None:
    response = api.navigate(
        fixture_site.url(
            "/redirect?to=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
        )
    )

    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["code"] in {
        "REDIRECT_DESTINATION_BLOCKED",
        "URL_ADDRESS_BLOCKED",
        "PRIVATE_ADDRESS_BLOCKED",
        "EGRESS_DESTINATION_BLOCKED",
    }, detail


def test_demo7_disallowed_form_method_is_refused(
    api: ApiClient, fixture_site: FixtureSite
) -> None:
    created = api.create_session()
    assert created.status_code == 201, created.text
    session_id = created.json()["session_id"]
    try:
        navigation = api.navigate(
            fixture_site.url("/form-put"), session_id=session_id
        )
        assert navigation.status_code == 200, navigation.text

        response = api.action(
            session_id,
            {
                "action": "submit_form",
                "target": {"selector": "#danger"},
                "confirm": True,
            },
        )
        _assert_error(response, 403, "FORM_METHOD_NOT_ALLOWED")
    finally:
        api.close_session(session_id)


def test_demo8_oversized_action_payload_is_refused(
    api: ApiClient, fixture_site: FixtureSite
) -> None:
    created = api.create_session()
    assert created.status_code == 201, created.text
    session_id = created.json()["session_id"]
    try:
        navigation = api.navigate(
            fixture_site.url("/form-get"), session_id=session_id
        )
        assert navigation.status_code == 200, navigation.text

        response = api.action(
            session_id,
            {
                "action": "type",
                "target": {"selector": "#q"},
                "text": "A" * 5000,
            },
        )
        assert response.status_code in {400, 413}, response.text
        assert response.json()["detail"]["code"] in {
            "INPUT_LENGTH_EXCEEDED",
            "PAYLOAD_TOO_LARGE",
        }
    finally:
        api.close_session(session_id)


def test_persistent_session_extract_action_and_screenshot(
    api: ApiClient, fixture_site: FixtureSite
) -> None:
    created = api.create_session(agent_id="agent-session")
    assert created.status_code == 201, created.text
    session_id = created.json()["session_id"]
    try:
        navigation = api.navigate(
            fixture_site.url("/form-get"),
            session_id=session_id,
            agent_id="agent-session",
        )
        assert navigation.status_code == 200, navigation.text

        extracted = api.extract(session_id, agent_id="agent-session")
        assert extracted.status_code == 200, extracted.text
        body = extracted.json()
        assert "Form Fixture" in body["content"]["text"]
        assert body["security"]["trust_label"] == "untrusted"
        assert body["metadata"]["title"] == "Form Fixture"

        action = api.action(
            session_id,
            {
                "action": "type",
                "target": {"selector": "#q"},
                "text": "agentshield",
            },
            agent_id="agent-session",
        )
        assert action.status_code == 200, action.text
        assert action.json()["success"] is True
        assert action.json()["security"]["trust_label"] == "untrusted"

        page_navigation = api.navigate(
            fixture_site.url("/page"),
            session_id=session_id,
            agent_id="agent-session",
        )
        assert page_navigation.status_code == 200, page_navigation.text
        hidden = api.extract(session_id, agent_id="agent-session")
        assert hidden.status_code == 200, hidden.text
        assert "HIDDEN_E2E_SECRET" not in hidden.json()["content"]["text"]

        screenshot = api.screenshot(session_id, agent_id="agent-session")
        assert screenshot.status_code == 200, screenshot.text
        assert screenshot.headers["content-type"] == "image/png"
        assert screenshot.content.startswith(b"\x89PNG\r\n\x1a\n")
        assert screenshot.headers["cache-control"].startswith("no-store")
        assert screenshot.headers["x-screenshot-width"] == "1280"

        status = api.client.get(
            f"/v1/browser/session/{session_id}",
            headers=api.headers("agent-session"),
        )
        assert status.status_code == 200, status.text
        assert status.json()["session_id"] == session_id
    finally:
        api.close_session(session_id, agent_id="agent-session")


def test_session_is_owner_bound(
    api: ApiClient, fixture_site: FixtureSite
) -> None:
    created = api.create_session(agent_id="agent-owner")
    assert created.status_code == 201, created.text
    session_id = created.json()["session_id"]
    try:
        navigation = api.navigate(
            fixture_site.url("/page"),
            session_id=session_id,
            agent_id="agent-owner",
        )
        assert navigation.status_code == 200, navigation.text

        stolen = api.action(
            session_id,
            {"action": "page_state"},
            agent_id="agent-other",
        )
        _assert_error(stolen, 403, "SESSION_FORBIDDEN")

        unauthenticated = api.client.post(
            "/v1/browser/session",
            json={},
            headers={"X-Agent-ID": "agent-owner"},
        )
        assert unauthenticated.status_code == 401, unauthenticated.text
    finally:
        api.close_session(session_id, agent_id="agent-owner")


def test_health_readiness_reports_dependencies(functional_stack: Stack) -> None:
    response = httpx.get(f"{functional_stack.api_url}/health/ready", timeout=15.0)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"]["browser_worker"] == "ok"
    assert body["checks"]["egress_proxy"] == "ok"
