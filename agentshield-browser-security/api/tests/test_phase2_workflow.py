from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import FakeWorkerClient, make_settings, make_test_app


def test_workflow():
    worker = FakeWorkerClient()
    app = make_test_app(make_settings(), worker)
    with TestClient(app) as client:
        r = client.post("/v1/browser/session", json={}, headers={"X-Agent-Id": "agent-a"})
        assert r.status_code == 201, r.text
        sid = r.json()["session_id"]
        nav = client.post("/v1/browser/navigate", json={"session_id": sid, "url": "https://example.com"}, headers={"X-Agent-Id": "agent-a"})
        assert nav.status_code in (200, 403, 502), nav.text
        client.delete(f"/v1/browser/session/{sid}", headers={"X-Agent-Id": "agent-a"})
