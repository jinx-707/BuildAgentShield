import pytest

from app.schemas.browser import BrowserNavigateRequest
from app.services.orchestrator import BrowserSecurityOrchestrator, PolicyDeniedError
from tests.conftest import (
    FakeContentInspector,
    FakePolicyEngine,
    FakeWorkerClient,
    make_network_preflight,
)


def build_orchestrator(policy=None, inspector=None, worker=None):
    return BrowserSecurityOrchestrator(
        policy_engine=policy or FakePolicyEngine(),
        content_inspector=inspector or FakeContentInspector(),
        worker_client=worker or FakeWorkerClient(),
        network_preflight=make_network_preflight(),
    )


async def test_navigation_authorizes_executes_and_inspects():
    policy = FakePolicyEngine()
    inspector = FakeContentInspector()
    worker = FakeWorkerClient()
    orchestrator = build_orchestrator(policy, inspector, worker)

    result = await orchestrator.navigate(
        BrowserNavigateRequest(url="https://example.com/"),
        request_id="req-1",
    )

    assert policy.calls[0].request_id == "req-1"
    assert worker.navigate_calls[0]["request_id"] == "req-1"
    assert worker.navigate_calls[0]["url"] == "https://example.com/"
    assert inspector.calls[0].url == "https://example.com/"
    assert result.request_id == "req-1"
    assert result.policy.allowed is True
    assert result.inspection.inspector_name == "fake-inspector"


async def test_policy_denial_stops_worker_execution():
    policy = FakePolicyEngine(allowed=False, reason="blocked for test")
    worker = FakeWorkerClient()
    orchestrator = build_orchestrator(policy=policy, worker=worker)

    with pytest.raises(PolicyDeniedError) as exc_info:
        await orchestrator.navigate(
            BrowserNavigateRequest(url="https://example.com/"),
            request_id="req-2",
        )

    assert exc_info.value.reason == "blocked for test"
    assert worker.navigate_calls == []
