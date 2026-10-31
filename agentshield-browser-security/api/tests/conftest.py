from dataclasses import dataclass, field

import pytest

from app.clients.browser_worker import ScreenshotResult
from app.config import Settings
from app.factories import build_network_preflight
from app.main import create_app
from app.schemas.action import WorkerActionResponse
from app.schemas.browser import WorkerNavigateResponse
from app.schemas.extract import (
    ExtractedLink,
    ExtractedList,
    ExtractedTable,
    PageMetadata,
    WorkerExtractResponse,
)
from app.schemas.health import WorkerHealthResponse
from app.schemas.session import SessionCloseResponse, SessionStatus


class FakeWorkerClient:
    def __init__(self) -> None:
        self.health_response = WorkerHealthResponse(
            status="ok",
            service="agentshield-browser-worker",
            version="0.1.0",
            checks={"browser": "ok"},
        )
        self.health_error: Exception | None = None
        self.navigate_response = WorkerNavigateResponse(
            request_id="test-request",
            requested_url="https://example.com/",
            final_url="https://example.com/",
            status_code=200,
            title="Example",
            content="<html><body><script>alert(1)</script></body></html>",
            content_truncated=False,
            elapsed_ms=25,
        )
        self.navigate_error: Exception | None = None
        self.navigate_calls: list[dict] = []
        self.session_status = SessionStatus(
            session_id="session-123",
            state="idle",
            status="idle",
            created_at="2026-01-01T00:00:00Z",
            last_used_at="2026-01-01T00:00:00Z",
            expires_at="2026-01-01T00:15:00Z",
            idle_timeout_ms=300000,
            max_age_ms=900000,
            active_requests=0,
            closing_requested=False,
            current_url="https://example.com/",
        )
        self.session_error: Exception | None = None
        self.create_session_calls: list[dict] = []
        self.get_session_calls: list[dict] = []
        self.close_session_calls: list[dict] = []
        self.close_session_response = SessionCloseResponse(
            session_id="session-123",
            closed=True,
            closing=False,
            request_id="test-request",
        )
        self.extract_response = WorkerExtractResponse(
            request_id="test-request",
            session_id="session-123",
            metadata=PageMetadata(
                title="Example",
                url="https://example.com/",
                description="An example page",
                canonical_url="https://example.com/",
                site_name="Example",
                language="en",
            ),
            text="Visible page text",
            links=[ExtractedLink(text="More", url="https://example.com/more")],
            lists=[ExtractedList(ordered=False, items=["One", "Two"])],
            tables=[
                ExtractedTable(
                    caption="Data",
                    headers=["Name"],
                    rows=[["Alice"]],
                )
            ],
            hidden_content_excluded=True,
            hidden_element_count=1,
        )
        self.extract_error: Exception | None = None
        self.extract_calls: list[dict] = []
        self.action_response = WorkerActionResponse(
            request_id="test-request",
            session_id="session-123",
            action="click",
            success=True,
            target={"tag": "button", "role": "button", "name": "Continue"},
            final_url="https://example.com/",
            title="Example",
            text="Visible page text",
            warnings=["UNTRUSTED_PAGE_CONTENT"],
            elapsed_ms=5,
        )
        self.action_error: Exception | None = None
        self.action_calls: list[dict] = []
        self.screenshot_content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
        self.screenshot_result = ScreenshotResult(
            content=self.screenshot_content,
            content_type="image/png",
            width=800,
            height=600,
            bytes=len(self.screenshot_content),
            full_page=False,
            elapsed_ms=7,
        )
        self.screenshot_error: Exception | None = None
        self.screenshot_calls: list[dict] = []
        self.closed = False

    async def health_live(self) -> WorkerHealthResponse:
        if self.health_error:
            raise self.health_error
        return self.health_response

    async def health_ready(self) -> WorkerHealthResponse:
        if self.health_error:
            raise self.health_error
        return self.health_response

    async def navigate(self, **kwargs) -> WorkerNavigateResponse:
        self.navigate_calls.append(kwargs)
        if self.navigate_error:
            raise self.navigate_error
        return self.navigate_response.model_copy(
            update={"request_id": kwargs["request_id"]}
        )

    async def create_session(self, **kwargs) -> SessionStatus:
        self.create_session_calls.append(kwargs)
        if self.session_error:
            raise self.session_error
        return self.session_status

    async def get_session(self, **kwargs) -> SessionStatus:
        self.get_session_calls.append(kwargs)
        if self.session_error:
            raise self.session_error
        return self.session_status

    async def close_session(self, **kwargs) -> SessionCloseResponse:
        self.close_session_calls.append(kwargs)
        if self.session_error:
            raise self.session_error
        return self.close_session_response.model_copy(
            update={"request_id": kwargs["request_id"]}
        )

    async def extract(self, **kwargs) -> WorkerExtractResponse:
        self.extract_calls.append(kwargs)
        if self.extract_error:
            raise self.extract_error
        return self.extract_response.model_copy(
            update={
                "request_id": kwargs["request_id"],
                "session_id": kwargs["session_id"],
            }
        )

    async def action(self, **kwargs) -> WorkerActionResponse:
        self.action_calls.append(kwargs)
        if self.action_error:
            raise self.action_error
        return self.action_response.model_copy(
            update={
                "request_id": kwargs["request_id"],
                "session_id": kwargs["session_id"],
                "action": kwargs["action"]["action"],
            }
        )

    async def screenshot(self, **kwargs) -> ScreenshotResult:
        self.screenshot_calls.append(kwargs)
        if self.screenshot_error:
            raise self.screenshot_error
        return self.screenshot_result

    async def aclose(self) -> None:
        self.closed = True


@dataclass
class FakePolicyEngine:
    allowed: bool = True
    reason: str = "allowed by test policy"
    name: str = "fake-policy"
    calls: list = field(default_factory=list)

    async def authorize(self, request):
        self.calls.append(request)
        from app.schemas.browser import PolicyDecision

        return PolicyDecision(
            allowed=self.allowed,
            policy_name=self.name,
            reason=self.reason,
        )


@dataclass
class FakeSearchProvider:
    name: str = "fake-search"
    mode: str = "full"
    notice: str | None = None
    endpoint: str = "https://search.test/"
    hits: list = field(default_factory=list)
    error: Exception | None = None
    calls: list = field(default_factory=list)
    closed: bool = False

    async def search(self, *, query, max_results, safe_search):
        self.calls.append(
            {
                "query": query,
                "max_results": max_results,
                "safe_search": safe_search,
            }
        )
        if self.error:
            raise self.error
        return list(self.hits)

    async def aclose(self) -> None:
        self.closed = True


@dataclass
class FakeContentInspector:
    name: str = "fake-inspector"
    calls: list = field(default_factory=list)

    async def inspect(self, request):
        from app.schemas.browser import InspectionResult

        self.calls.append(request)
        return InspectionResult(inspector_name=self.name)


def make_settings(**overrides) -> Settings:
    values = {
        "app_name": "agentshield-browser-security-api",
        "environment": "test",
        "log_level": "WARNING",
        "browser_worker_url": "http://browser-worker.test:8080",
        "browser_worker_timeout_seconds": 5.0,
        "browser_worker_health_timeout_seconds": 1.0,
        "policy_backend": "mock",
        "inspection_backend": "mock",
        "allowed_domains": "example.com",
        "dns_preflight_enabled": False,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def make_network_preflight(**overrides):
    return build_network_preflight(make_settings(**overrides))


def make_test_app(settings: Settings, worker_client, *, search_provider=None):
    return create_app(
        settings,
        browser_client=worker_client,
        search_provider=search_provider,
    )


@pytest.fixture
def fake_worker() -> FakeWorkerClient:
    return FakeWorkerClient()


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def test_app(settings, fake_worker):
    return make_test_app(settings, fake_worker)
