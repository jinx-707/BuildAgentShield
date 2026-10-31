from __future__ import annotations

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import admin_headers, build_settings, create_agent, execute


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_stub(
    payload: dict[str, Any] | None = None,
    *,
    delay: float = 0.0,
    status: int = 200,
) -> tuple[ThreadingHTTPServer, str]:
    response_body = payload if payload is not None else {
        "result": {
            "decision": "DENY",
            "reason": "Default deny: no OPA rule matched.",
            "policy_id": "opa.default_deny",
        }
    }

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                if delay:
                    time.sleep(delay)
                body = json.dumps(response_body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _stop_stub(server: ThreadingHTTPServer) -> None:
    server.shutdown()
    server.server_close()


def _opa_component(body: dict[str, Any]) -> dict[str, Any]:
    return next(item for item in body["components"] if item["name"] == "opa")


def test_opa_health_reports_mock_when_not_configured(tmp_path: Path):
    settings = build_settings(tmp_path / "mock.db", opa_url=None)
    with TestClient(create_app(settings)) as client:
        body = client.get("/ready").json()

    component = _opa_component(body)
    assert component["status"] == "MOCK"
    assert "AGENTSHIELD_OPA_URL" in component["detail"]
    assert body["status"] == "ok"


def test_opa_health_reports_real_for_valid_response(tmp_path: Path):
    server, url = _start_stub()
    try:
        settings = build_settings(
            tmp_path / "reachable.db", opa_url=url, opa_timeout_seconds=1.0
        )
        with TestClient(create_app(settings)) as client:
            body = client.get("/ready").json()
    finally:
        _stop_stub(server)

    component = _opa_component(body)
    assert component["status"] == "REAL"
    assert component["detail"] == "opa policy evaluation succeeded"
    assert body["status"] == "ok"


def test_opa_health_reports_unavailable_when_unreachable(tmp_path: Path):
    port = _free_port()
    settings = build_settings(
        tmp_path / "unreachable.db",
        opa_url=f"http://127.0.0.1:{port}",
        opa_timeout_seconds=0.2,
    )
    with TestClient(create_app(settings)) as client:
        body = client.get("/ready").json()
        headers = admin_headers(client)
        _, agent_key = create_agent(client, headers, permissions=["documents.read"])
        response = execute(client, agent_key, "read_document", {"document": "report.pdf"})

    component = _opa_component(body)
    assert component["status"] == "UNAVAILABLE"
    assert "probe failed" in component["detail"]
    assert body["status"] == "unhealthy"
    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"
    assert "failed closed" in response.json()["reason"]


def test_opa_health_reports_unavailable_for_invalid_response(tmp_path: Path):
    server, url = _start_stub({"result": {"decision": "UNKNOWN"}})
    try:
        settings = build_settings(
            tmp_path / "invalid.db", opa_url=url, opa_timeout_seconds=1.0
        )
        with TestClient(create_app(settings)) as client:
            body = client.get("/ready").json()
    finally:
        _stop_stub(server)

    component = _opa_component(body)
    assert component["status"] == "UNAVAILABLE"
    assert "unknown decision" in component["detail"]
    assert body["status"] == "unhealthy"


def test_opa_health_reports_unavailable_on_timeout(tmp_path: Path):
    server, url = _start_stub(delay=0.3)
    try:
        settings = build_settings(
            tmp_path / "timeout.db", opa_url=url, opa_timeout_seconds=0.05
        )
        with TestClient(create_app(settings)) as client:
            body = client.get("/ready").json()
    finally:
        _stop_stub(server)

    component = _opa_component(body)
    assert component["status"] == "UNAVAILABLE"
    assert "probe failed" in component["detail"]
    assert body["status"] == "unhealthy"


@pytest.mark.skipif(
    not os.environ.get("AGENTSHIELD_OPA_URL"),
    reason="requires a running real OPA instance",
)
def test_opa_health_reports_real_for_running_opa(tmp_path: Path):
    settings = build_settings(
        tmp_path / "real-opa.db",
        opa_url=os.environ["AGENTSHIELD_OPA_URL"],
        opa_timeout_seconds=2.0,
    )
    with TestClient(create_app(settings)) as client:
        body = client.get("/ready").json()

    component = _opa_component(body)
    assert component["status"] == "REAL"
    assert body["status"] == "ok"
