from fastapi.testclient import TestClient

from tests.conftest import FakeWorkerClient, make_settings, make_test_app


def _make_client():
    worker = FakeWorkerClient()
    app = make_test_app(make_settings(), worker)
    return TestClient(app), worker


def _create_session(client: TestClient, agent_id: str):
    response = client.post(
        "/v1/browser/session", json={}, headers={"X-Agent-Id": agent_id}
    )
    assert response.status_code == 201, response.text
    return response.json()["session_id"]


def _get_session(client: TestClient, agent_id: str, session_id: str):
    return client.get(
        f"/v1/browser/session/{session_id}",
        headers={"X-Agent-Id": agent_id},
    )


def _navigate(client: TestClient, agent_id: str, session_id: str):
    return client.post(
        "/v1/browser/navigate",
        json={"session_id": session_id, "url": "https://example.com"},
        headers={"X-Agent-Id": agent_id},
    )


def _delete_session(client: TestClient, agent_id: str, session_id: str):
    return client.delete(
        f"/v1/browser/session/{session_id}",
        headers={"X-Agent-Id": agent_id},
    )


def _infer_ok_or_forbidden(status_code: int) -> str:
    return "ok" if status_code == 200 else ("forbidden" if status_code == 403 else f"status={status_code}")


def test_agent_can_access_own_session():
    client, _ = _make_client()
    with client:
        sid = _create_session(client, "agent-a")
        response = _get_session(client, "agent-a", sid)
        assert response.status_code == 200
        assert response.json()["session_id"] == sid


def test_other_agent_cannot_access_session():
    client, _ = _make_client()
    with client:
        sid = _create_session(client, "agent-a")
        for operation, response in (
            ("navigate", _navigate(client, "agent-b", sid)),
            ("inspect", _get_session(client, "agent-b", sid)),
            ("delete", _delete_session(client, "agent-b", sid)),
        ):
            assert response.status_code in {403, 404}, (operation, response.text)
        assert _get_session(client, "agent-a", sid).status_code == 200


def test_other_agent_cannot_reuse_session_id():
    client, _ = _make_client()
    with client:
        sid = _create_session(client, "agent-a")
        _delete_session(client, "agent-a", sid)
        response = client.post(
            "/v1/browser/navigate",
            json={"session_id": sid, "url": "https://example.com"},
            headers={"X-Agent-Id": "agent-b"},
        )
        assert response.status_code in {403, 404}, response.text


def test_missing_agent_identity_rejected():
    client, _ = _make_client()
    with client:
        response = client.post("/v1/browser/session", json={})
        assert response.status_code == 400, response.text


def test_invalid_agent_identity_rejected():
    client, _ = _make_client()
    with client:
        response = client.post("/v1/browser/session", json={}, headers={"X-Agent-Id": ""})
        assert response.status_code == 400, response.text
