from __future__ import annotations

import json

import httpx
import pytest

from agentshield_sdk import (
    AgentShieldClient,
    AgentShieldError,
    AsyncAgentShieldClient,
    SecureAgent,
)


def _ok_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "request_id": "sdk_test_request",
            "decision": "ALLOW",
            "risk_level": "low",
            "risk_score": 8,
            "executed": True,
            "reason": "Allowed by policy",
            "status": "completed",
            "tool": "read_document",
        },
    )


def test_execute_sends_agent_identity_and_strict_provenance() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["agent_key"] = request.headers.get("X-Agent-Key")
        seen["idempotency"] = request.headers.get("Idempotency-Key")
        seen["body"] = json.loads(request.content)
        return _ok_response()

    client = AgentShieldClient(
        "http://gateway.test",
        agent_key="as_test_key",
        transport=httpx.MockTransport(handler),
    )
    result = client.execute_once(
        "read_document",
        {"document": "quarterly-report.pdf"},
        source="email-inbox",
        trust="untrusted",
        data_classification="sensitive",
        user_intent="Summarize the attached report",
    )

    assert result["decision"] == "ALLOW"
    assert seen["path"] == "/v1/tools/execute"
    assert seen["agent_key"] == "as_test_key"
    assert isinstance(seen["idempotency"], str)
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["tool_name"] == "read_document"
    assert body["provenance"] == {
        "source": "email-inbox",
        "trust": "untrusted",
        "data_classification": "sensitive",
        "tainted": True,
        "origin": "email-inbox",
        "taint_labels": ["untrusted"],
    }


def test_execute_raises_structured_error_for_denied_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Invalid agent key"})

    client = AgentShieldClient(
        "http://gateway.test",
        agent_key="bad-key",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(AgentShieldError) as error:
        client.execute("read_document", {"document": "report.pdf"})

    assert error.value.status_code == 401
    assert error.value.payload == {"detail": "Invalid agent key"}


def test_sync_approval_flow_uses_dashboard_token_and_returns_signed_token() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["authorization"] = request.headers.get("Authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "apr_test",
                "status": "Approved",
                "token": "signed-single-use-token",
            },
        )

    client = AgentShieldClient(
        "http://gateway.test",
        dashboard_token="dashboard-jwt",
        transport=httpx.MockTransport(handler),
    )
    approval = client.approve("apr_test", comment="Reviewed in test")

    assert seen["path"] == "/v1/approvals/apr_test/approve"
    assert seen["authorization"] == "Bearer dashboard-jwt"
    assert seen["body"] == {"comment": "Reviewed in test"}
    assert approval["token"] == "signed-single-use-token"


def test_wait_for_approval_stops_when_reviewed() -> None:
    statuses = iter(["Pending", "Approved"])

    class StubClient(AgentShieldClient):
        def get_approval(self, approval_id: str) -> dict:
            return {"id": approval_id, "status": next(statuses)}

    client = StubClient("http://gateway.test")
    approval = client.wait_for_approval("apr_test", timeout=1, interval=0)

    assert approval["status"] == "Approved"


def test_secure_agent_requires_sync_client_for_run() -> None:
    async_client = AsyncAgentShieldClient("http://gateway.test")

    with pytest.raises(TypeError):
        SecureAgent(async_client).run("read_document", {"document": "report.pdf"})


async def test_secure_agent_requires_async_client_for_arun() -> None:
    sync_client = AgentShieldClient("http://gateway.test")

    with pytest.raises(TypeError):
        await SecureAgent(sync_client).arun(
            "read_document", {"document": "report.pdf"}
        )


def test_health_checks_readiness_endpoint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/ready"
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "version": "1.0.0",
                "mode": "mock",
                "components": [],
                "timestamp": "2026-01-01T00:00:00Z",
            },
        )

    client = AgentShieldClient(
        "http://gateway.test", transport=httpx.MockTransport(handler)
    )
    assert client.health()["status"] == "ok"


async def test_async_propose_and_simulator_paths() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/tools/propose"):
            return httpx.Response(
                200,
                json={
                    "request_id": "sdk_test_request",
                    "decision": "REQUIRE_APPROVAL",
                    "risk_level": "medium",
                    "risk_score": 60,
                    "executed": False,
                    "reason": "Human approval required",
                    "approval": {"id": "apr_test", "status": "Pending"},
                },
            )
        return httpx.Response(200, json={"items": [], "passed": 0, "total": 0})

    async with AsyncAgentShieldClient(
        "http://gateway.test",
        agent_key="as_test_key",
        dashboard_token="dashboard-jwt",
        transport=httpx.MockTransport(handler),
    ) as client:
        proposal = await client.propose(
            "initiate_payment",
            {"amount": 120, "currency": "USD", "merchant": "Acme Software"},
            user_intent="Buy a team license",
        )
        simulation = await client.run_simulator()

    assert proposal["decision"] == "REQUIRE_APPROVAL"
    assert simulation["total"] == 0
    assert paths == ["/v1/tools/propose", "/v1/simulator/run"]
