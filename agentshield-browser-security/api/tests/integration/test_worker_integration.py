import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

pytestmark = pytest.mark.integration

WORKER_DIR = Path(__file__).resolve().parents[3] / "worker"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_http(url: str, timeout_seconds: float = 45.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None

    with httpx.Client(timeout=2.0) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get(url)
                if response.status_code == 200:
                    return
            except httpx.HTTPError as exc:
                last_error = exc
            time.sleep(0.25)

    raise AssertionError(f"service did not become ready at {url}: {last_error}")


@pytest.fixture(scope="module")
def worker():
    if not (WORKER_DIR / "node_modules" / "puppeteer").exists():
        pytest.skip("worker dependencies missing; run npm install in worker/")

    port = free_port()
    env = os.environ.copy()
    env.update(
        {
            "WORKER_HOST": "127.0.0.1",
            "WORKER_PORT": str(port),
            "LOG_LEVEL": "info",
            "BROWSER_HEADLESS": "true",
            "BROWSER_ALLOW_PRIVATE_NETWORKS": "true",
            "BROWSER_NAVIGATION_TIMEOUT_MS": "20000",
            "ALLOWED_DOMAINS": "127.0.0.1",
            "ALLOWED_PORTS": "80,443,1024-65535",
            # Legacy direct-egress test fixture. Phase 2B proxy enforcement is
            # exercised by worker/test/egress_integration.test.js.
            "REQUIRE_EGRESS_PROXY": "false",
            "NODE_ENV": "test",
        }
    )

    process = subprocess.Popen(
        ["node", "src/index.js"],
        cwd=WORKER_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_for_http(f"http://127.0.0.1:{port}/health/live")
        yield {"port": port, "process": process}
    except Exception:
        process.terminate()
        output, _ = process.communicate(timeout=15)
        print(output)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate()
            if process.returncode not in (0, -15):
                print(output)


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = (
            "<!doctype html><html lang=\"en\"><head>"
            "<title>AgentShield Test Page</title>"
            '<meta name="description" content="Integration fixture">'
            "</head><body><h1>fixture</h1>"
            "<p>Visible paragraph with <a href=\"/next\">a link</a>.</p>"
            "<ul><li>Alpha</li><li>Beta</li></ul>"
            "<table><tr><th>Name</th></tr><tr><td>Alice</td></tr></table>"
            '<input id="name-input" aria-label="Full name" />'
            '<button id="plain-button" type="button">Plain button</button>'
            '<form id="search-form" action="/submitted" method="get">'
            '<input name="q" value="fixture" />'
            '<button type="submit">Submit</button></form>'
            '<div id="action-output"></div>'
            "<div hidden>HIDDEN_INTEGRATION_SECRET</div>"
            "<script>window.__agentshield_test = true;</script>"
            "</body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


@pytest.fixture(scope="module")
def local_site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_worker_liveness(worker):
    response = httpx.get(
        f"http://127.0.0.1:{worker['port']}/health/live", timeout=5.0
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["checks"] == {"process": "ok"}
    assert response.headers["x-request-id"]


def test_worker_health_alias(worker):
    response = httpx.get(
        f"http://127.0.0.1:{worker['port']}/health", timeout=5.0
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_worker_echoes_request_id(worker):
    response = httpx.get(
        f"http://127.0.0.1:{worker['port']}/health/live",
        headers={"X-Request-ID": "worker-request-1"},
        timeout=5.0,
    )

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "worker-request-1"


def test_worker_rejects_unsupported_url_scheme(worker):
    response = httpx.post(
        f"http://127.0.0.1:{worker['port']}/v1/navigate",
        json={"url": "file:///etc/passwd"},
        timeout=10.0,
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_worker_has_no_javascript_execution_route(worker):
    response = httpx.post(
        f"http://127.0.0.1:{worker['port']}/v1/evaluate",
        json={"script": "1 + 1"},
        timeout=10.0,
    )

    assert response.status_code == 404


def test_worker_readiness_launches_browser(worker):
    response = httpx.get(
        f"http://127.0.0.1:{worker['port']}/health/ready", timeout=60.0
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["checks"] == {"browser": "ok"}


def test_api_health_reaches_worker(worker):
    settings = Settings(
        _env_file=None,
        environment="test",
        log_level="WARNING",
        browser_worker_url=f"http://127.0.0.1:{worker['port']}",
        browser_worker_timeout_seconds=30.0,
        browser_worker_health_timeout_seconds=5.0,
    )
    app = create_app(settings)

    with TestClient(app) as client:
        response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["checks"] == {"browser_worker": "ok"}


def test_api_navigates_through_worker(worker, local_site):
    fixture_port = httpx.URL(local_site).port
    settings = Settings(
        _env_file=None,
        environment="test",
        log_level="WARNING",
        browser_worker_url=f"http://127.0.0.1:{worker['port']}",
        browser_worker_timeout_seconds=30.0,
        browser_worker_health_timeout_seconds=5.0,
        allowed_domains="127.0.0.1",
        allowed_ports=f"80,443,{fixture_port}",
        allow_private_networks=True,
        dns_preflight_enabled=False,
    )
    app = create_app(settings)

    with TestClient(app) as client:
        response = client.post(
            "/v1/browser/navigate",
            headers={"X-Request-ID": "integration-navigate"},
            json={
                "url": local_site,
                "wait_until": "load",
                "timeout_ms": 15000,
            },
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert response.headers["x-request-id"] == "integration-navigate"
    assert body["request_id"] == "integration-navigate"
    assert body["final_url"].startswith(local_site)
    assert body["title"] == "AgentShield Test Page"
    assert "fixture" in body["content"]
    assert body["policy"]["policy_name"] == "mock-policy"
    assert body["inspection"]["inspector_name"] == "mock-content-inspector"
    assert {finding["rule_id"] for finding in body["inspection"]["findings"]} == {
        "script-tag"
    }


def test_api_session_navigate_and_extract_through_worker(worker, local_site):
    fixture_port = httpx.URL(local_site).port
    settings = Settings(
        _env_file=None,
        environment="test",
        log_level="WARNING",
        browser_worker_url=f"http://127.0.0.1:{worker['port']}",
        browser_worker_timeout_seconds=30.0,
        browser_worker_health_timeout_seconds=5.0,
        allowed_domains="127.0.0.1",
        allowed_ports=f"80,443,{fixture_port}",
        allow_private_networks=True,
        dns_preflight_enabled=False,
    )
    app = create_app(settings)

    with TestClient(app) as client:
        created = client.post(
            "/v1/browser/session", headers={"X-Agent-ID": "integration-agent"}
        )
        assert created.status_code == 201, created.text
        session_id = created.json()["session_id"]

        navigated = client.post(
            "/v1/browser/navigate",
            headers={
                "X-Agent-ID": "integration-agent",
                "X-Request-ID": "integration-session-navigate",
            },
            json={
                "url": local_site,
                "wait_until": "load",
                "timeout_ms": 15000,
                "session_id": session_id,
            },
        )
        assert navigated.status_code == 200, navigated.text

        extracted = client.post(
            "/v1/browser/extract",
            headers={"X-Agent-ID": "integration-agent"},
            json={"session_id": session_id},
        )
        assert extracted.status_code == 200, extracted.text
        body = extracted.json()
        assert body["session_id"] == session_id
        assert body["metadata"]["title"] == "AgentShield Test Page"
        assert body["metadata"]["language"] == "en"
        assert "Visible paragraph" in body["content"]["text"]
        assert "HIDDEN_INTEGRATION_SECRET" not in body["content"]["text"]
        assert body["security"]["trust_label"] == "untrusted"
        assert body["security"]["hidden_content_excluded"] is True
        assert body["links"][0]["url"].startswith(local_site)
        assert body["lists"][0]["items"] == ["Alpha", "Beta"]
        assert body["tables"][0]["rows"] == [["Alice"]]

        status = client.get(
            f"/v1/browser/session/{session_id}",
            headers={"X-Agent-ID": "integration-agent"},
        )
        assert status.status_code == 200
        assert status.json()["current_url"].startswith(local_site)
        assert status.json()["active_requests"] == 0

        closed = client.delete(
            f"/v1/browser/session/{session_id}",
            headers={"X-Agent-ID": "integration-agent"},
        )
        assert closed.status_code == 200
        assert closed.json()["closed"] is True


def test_api_actions_and_screenshot_through_worker(worker, local_site):
    fixture_port = httpx.URL(local_site).port
    settings = Settings(
        _env_file=None,
        environment="test",
        log_level="WARNING",
        browser_worker_url=f"http://127.0.0.1:{worker['port']}",
        browser_worker_timeout_seconds=30.0,
        browser_worker_health_timeout_seconds=5.0,
        allowed_domains="127.0.0.1",
        allowed_ports=f"80,443,{fixture_port}",
        allow_private_networks=True,
        dns_preflight_enabled=False,
    )
    app = create_app(settings)
    headers = {"X-Agent-ID": "integration-action-agent"}

    with TestClient(app) as client:
        created = client.post("/v1/browser/session", headers=headers)
        assert created.status_code == 201, created.text
        session_id = created.json()["session_id"]

        try:
            navigated = client.post(
                "/v1/browser/navigate",
                headers=headers,
                json={
                    "url": local_site,
                    "wait_until": "load",
                    "timeout_ms": 15000,
                    "session_id": session_id,
                },
            )
            assert navigated.status_code == 200, navigated.text

            clicked = client.post(
                "/v1/browser/action",
                headers=headers,
                json={
                    "session_id": session_id,
                    "action": "click",
                    "target": {"selector": "a"},
                },
            )
            assert clicked.status_code == 200, clicked.text
            clicked_body = clicked.json()
            assert clicked_body["action"] == "click"
            assert clicked_body["success"] is True
            assert clicked_body["final_url"].startswith(local_site)
            assert "NAVIGATION_OCCURRED" in clicked_body["security"]["warnings"]
            assert clicked_body["security"]["trust_label"] == "untrusted"

            typed = client.post(
                "/v1/browser/action",
                headers=headers,
                json={
                    "session_id": session_id,
                    "action": "type",
                    "target": {"selector": "#name-input"},
                    "text": "api-integration-secret",
                },
            )
            assert typed.status_code == 200, typed.text
            typed_body = typed.json()
            assert "api-integration-secret" not in typed_body["content"]["text"]
            assert "TYPED_VALUE_REDACTED" in typed_body["security"]["warnings"]

            scrolled = client.post(
                "/v1/browser/action",
                headers=headers,
                json={
                    "session_id": session_id,
                    "action": "scroll",
                    "direction": "down",
                    "amount": 100,
                },
            )
            assert scrolled.status_code == 200, scrolled.text
            assert scrolled.json()["scroll"]["y"] >= 0

            state = client.post(
                "/v1/browser/action",
                headers=headers,
                json={"session_id": session_id, "action": "page_state"},
            )
            assert state.status_code == 200, state.text
            assert state.json()["action"] == "page_state"
            assert "Visible paragraph" in state.json()["content"]["text"]

            submitted = client.post(
                "/v1/browser/action",
                headers=headers,
                json={
                    "session_id": session_id,
                    "action": "submit_form",
                    "target": {"selector": "#search-form"},
                },
            )
            assert submitted.status_code == 200, submitted.text
            submitted_body = submitted.json()
            assert submitted_body["action"] == "submit_form"
            assert submitted_body["form"]["method"] == "get"
            assert submitted_body["form"]["cross_origin"] is False
            assert "NAVIGATION_OCCURRED" in submitted_body["security"]["warnings"]

            shot = client.post(
                "/v1/browser/screenshot",
                headers=headers,
                json={"session_id": session_id},
            )
            assert shot.status_code == 200, shot.text
            assert shot.headers["content-type"] == "image/png"
            assert shot.content.startswith(b"\x89PNG\r\n\x1a\n")
            assert int(shot.headers["x-screenshot-width"]) > 0
            assert int(shot.headers["x-screenshot-height"]) > 0
            assert int(shot.headers["x-screenshot-bytes"]) == len(shot.content)
            assert shot.headers["x-screenshot-full-page"] == "false"
            assert "filename=" in shot.headers["content-disposition"]
            assert local_site not in shot.headers["content-disposition"]
        finally:
            closed = client.delete(
                f"/v1/browser/session/{session_id}", headers=headers
            )
            assert closed.status_code == 200, closed.text
