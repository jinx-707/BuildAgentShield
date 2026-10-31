"""
Real-HTTP integration tests for the provider adapter.

A local ThreadingHTTPServer implements provider contract v1 over a real
socket.  The adapter's genuine transport chain (DNS/IP re-validation,
destination pinning, proxy policy when configured, trust_env=False, no
redirects, bounded reads) is exercised end to end.  These tests prove the
local fake-provider path; they do not contact any production provider.
"""
from __future__ import annotations

import base64
import json

import pytest

from config.settings import Settings
from integrations.analysis_adapter import HttpDocumentAnalysisAdapter
from integrations.handoff import (
    AnalysisDocument,
    DocumentHandoffPayload,
    HandoffError,
)
from integrations.analysis_models import ANALYSIS_SCHEMA_VERSION
from security.errors import (
    ANALYSIS_AUTH_FAILED,
    ANALYSIS_INVALID_RESPONSE,
    ANALYSIS_PAYLOAD_TOO_LARGE,
    ANALYSIS_PROVIDER_ERROR,
    ANALYSIS_PROVIDER_RATE_LIMITED,
    ANALYSIS_REDIRECT_BLOCKED,
    ANALYSIS_RESPONSE_TOO_LARGE,
    ANALYSIS_TIMEOUT,
    ANALYSIS_UNAVAILABLE,
)
from tests.integration.analysis_test_server import (
    ANALYSIS_PATH,
    endpoint_for,
    json_responder,
    raw_responder,
    serve_analysis,
)
from tests.integration.raw_http import closed_port
from tests.pdf_fixtures import make_pdf

pytestmark = pytest.mark.integration

TOKEN = "analysis-bearer-token-value"
PDF_BYTES = make_pdf(("Confidential quarterly report",))
EXTRACTED_TEXT = "Confidential quarterly report"


def make_settings(endpoint: str, **overrides) -> Settings:
    base = {
        "environment": "test",
        "api_auth_token": "api-token",
        "database_url": "sqlite+aiosqlite:///:memory:",
        "egress_proxy_url": "",
        "egress_proxy_health_url": "",
        "require_egress_proxy": False,
        "allowed_domains": "analysis.example.com",
        "default_domain_policy": "deny",
        "dns_preflight_enabled": True,
        "allow_private_networks": False,
        "analysis_provider": "http",
        "analysis_endpoint_url": endpoint,
        "analysis_api_token": TOKEN,
        "analysis_allow_insecure_local": True,
        "analysis_allow_private_endpoints": True,
        "analysis_max_attempts": 1,
        "analysis_retry_base_delay_seconds": 0.0,
        "analysis_connect_timeout_seconds": 2.0,
        "analysis_read_timeout_seconds": 2.0,
        "analysis_total_timeout_seconds": 10.0,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def make_document() -> AnalysisDocument:
    return AnalysisDocument(
        payload=DocumentHandoffPayload(
            download_id="dl-1",
            tenant_id="tenant-1",
            agent_id="agent-1",
            file_ref="approved/uuid-1",
            mime_type="application/pdf",
            file_size=len(PDF_BYTES),
            sha256="f" * 64,
        ),
        content=PDF_BYTES,
        document_type="pdf",
        page_count=1,
        extracted_text=EXTRACTED_TEXT,
        text_truncated=False,
        warnings=("NO_EXTRACTABLE_TEXT",),
    )


def provider_payload(**overrides) -> dict:
    payload = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "analysis_id": "provider-1",
        "correlation_id": "corr-1",
        "status": "completed",
        "document": {"document_type": "pdf", "page_count": 1},
        "summary": "Looks like a report.",
        "findings": [],
        "confidence": {"overall": 0.9},
        "metadata": {"pages": 1},
        "warnings": [],
        "processed_at": "2026-01-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def provider_server():
    servers = []
    shutdowns = []

    def start(responder):
        server, shutdown = serve_analysis(responder)
        servers.append(server)
        shutdowns.append(shutdown)
        return server

    yield start
    for shutdown in shutdowns:
        shutdown()


class TestSuccessfulAnalysis:
    async def test_valid_request_and_response(self, provider_server, caplog):
        server = provider_server(json_responder(provider_payload()))
        adapter = HttpDocumentAnalysisAdapter(settings=make_settings(endpoint_for(server)))
        caplog.set_level("DEBUG")

        result = await adapter.analyze(make_document(), correlation_id="corr-client")

        assert result.status == "completed"
        assert result.analysis_id == "provider-1"
        assert result.confidence == {"overall": 0.9}

        assert len(server.state["requests"]) == 1
        request = server.state["requests"][0]
        assert request["path"] == ANALYSIS_PATH
        assert request["headers"]["authorization"] == f"Bearer {TOKEN}"
        assert request["headers"]["x-correlation-id"] == "corr-client"
        assert request["headers"]["idempotency-key"] == f"dl-1:{'f' * 64}"
        assert request["headers"]["accept"] == "application/json"
        assert request["headers"]["content-type"] == "application/json"

        body = json.loads(request["body"])
        assert body["schema_version"] == ANALYSIS_SCHEMA_VERSION
        assert body["correlation_id"] == "corr-client"
        assert body["document"]["download_id"] == "dl-1"
        assert body["document"]["extracted_text"] == EXTRACTED_TEXT
        assert body["document"]["page_count"] == 1
        assert base64.b64decode(body["content_base64"]) == PDF_BYTES

        # Secrets and document content never reach the log stream.
        assert TOKEN not in caplog.text
        assert EXTRACTED_TEXT not in caplog.text
        assert "Looks like a report." not in caplog.text


class TestHttpFailures:
    async def test_auth_failure_is_not_retried(self, provider_server):
        server = provider_server(
            json_responder(provider_payload(), status="401 Unauthorized")
        )
        settings = make_settings(endpoint_for(server), analysis_max_attempts=3)
        adapter = HttpDocumentAnalysisAdapter(settings=settings)

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_AUTH_FAILED
        assert exc.value.retriable is False
        assert len(server.state["requests"]) == 1

    async def test_non_json_content_type_rejected(self, provider_server):
        server = provider_server(
            raw_responder(
                "200 OK",
                [("Content-Type", "text/plain"), ("Content-Length", "11")],
                b"hello world",
            )
        )
        adapter = HttpDocumentAnalysisAdapter(settings=make_settings(endpoint_for(server)))

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_INVALID_RESPONSE

    async def test_invalid_json_rejected(self, provider_server):
        body = b"{not json"
        server = provider_server(
            raw_responder(
                "200 OK",
                [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
                body,
            )
        )
        adapter = HttpDocumentAnalysisAdapter(settings=make_settings(endpoint_for(server)))

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_INVALID_RESPONSE

    async def test_schema_mismatch_rejected(self, provider_server):
        server = provider_server(json_responder({"analysis_id": ""}))
        adapter = HttpDocumentAnalysisAdapter(settings=make_settings(endpoint_for(server)))

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_INVALID_RESPONSE

    async def test_provider_failure_status_maps_to_provider_error(self, provider_server):
        payload = provider_payload(
            status="failed",
            error={"code": "ANALYSIS_OVERLOADED", "message": "busy", "retryable": True},
        )
        server = provider_server(json_responder(payload))
        adapter = HttpDocumentAnalysisAdapter(settings=make_settings(endpoint_for(server)))

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_PROVIDER_ERROR
        assert exc.value.retriable is True

    async def test_redirect_is_not_followed(self, provider_server):
        server = provider_server(
            raw_responder(
                "302 Found",
                [("Location", "http://127.0.0.1:1/elsewhere"), ("Content-Length", "0")],
                b"",
            )
        )
        adapter = HttpDocumentAnalysisAdapter(settings=make_settings(endpoint_for(server)))

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_REDIRECT_BLOCKED
        assert exc.value.retriable is False
        # Only the original request reached the wire.
        assert len(server.state["requests"]) == 1


class TestTimeoutsAndOutages:
    async def test_read_timeout_maps_to_analysis_timeout(self, provider_server):
        server = provider_server(json_responder(provider_payload(), delay=0.5))
        settings = make_settings(
            endpoint_for(server),
            analysis_read_timeout_seconds=0.1,
            analysis_total_timeout_seconds=5.0,
        )
        adapter = HttpDocumentAnalysisAdapter(settings=settings)

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_TIMEOUT
        assert exc.value.retriable is True

    async def test_connection_refused_maps_to_unavailable(self):
        endpoint = f"http://127.0.0.1:{closed_port()}{ANALYSIS_PATH}"
        adapter = HttpDocumentAnalysisAdapter(settings=make_settings(endpoint=endpoint))

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_UNAVAILABLE
        assert exc.value.retriable is True


class TestRetries:
    async def test_rate_limit_is_retried_then_succeeds(self, provider_server):
        calls = {"count": 0}

        def respond(handler):
            calls["count"] += 1
            if calls["count"] == 1:
                body = b'{"error": "slow down"}'
                handler.write_response(
                    "429 Too Many Requests",
                    [("Content-Type", "application/json"),
                     ("Content-Length", str(len(body))),
                     ("Retry-After", "0")],
                    body,
                )
            else:
                body = json.dumps(provider_payload()).encode()
                handler.write_response(
                    "200 OK",
                    [("Content-Type", "application/json"),
                     ("Content-Length", str(len(body)))],
                    body,
                )

        server = provider_server(respond)
        settings = make_settings(endpoint_for(server), analysis_max_attempts=3)
        adapter = HttpDocumentAnalysisAdapter(settings=settings)

        result = await adapter.analyze(make_document(), correlation_id="corr")

        assert result.status == "completed"
        assert len(server.state["requests"]) == 2

    async def test_persistent_rate_limit_exhausts_attempts(self, provider_server):
        server = provider_server(
            json_responder({"error": "slow down"}, status="429 Too Many Requests")
        )
        settings = make_settings(endpoint_for(server), analysis_max_attempts=2)
        adapter = HttpDocumentAnalysisAdapter(settings=settings)

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_PROVIDER_RATE_LIMITED
        assert len(server.state["requests"]) == 2

    async def test_server_error_is_retried(self, provider_server):
        server = provider_server(
            json_responder({"error": "down"}, status="503 Service Unavailable")
        )
        settings = make_settings(endpoint_for(server), analysis_max_attempts=2)
        adapter = HttpDocumentAnalysisAdapter(settings=settings)

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_PROVIDER_ERROR
        assert exc.value.retriable is True
        assert len(server.state["requests"]) == 2


class TestSizeLimits:
    async def test_request_over_payload_cap_never_sent(self, provider_server):
        server = provider_server(json_responder(provider_payload()))
        settings = make_settings(endpoint_for(server), analysis_max_payload_bytes=64)
        adapter = HttpDocumentAnalysisAdapter(settings=settings)

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_PAYLOAD_TOO_LARGE
        assert exc.value.retriable is False
        assert server.state["requests"] == []

    async def test_declared_oversized_response_rejected(self, provider_server):
        huge = provider_payload(summary="s" * 5_000)
        server = provider_server(json_responder(huge))
        settings = make_settings(endpoint_for(server), analysis_max_response_bytes=256)
        adapter = HttpDocumentAnalysisAdapter(settings=settings)

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_RESPONSE_TOO_LARGE

    async def test_undeclared_oversized_response_is_bounded(self, provider_server):
        body = b'{"x": "' + b"a" * 5_000 + b'"}'
        server = provider_server(
            raw_responder(
                "200 OK",
                [
                    ("Content-Type", "application/json"),
                    ("Connection", "close"),
                ],
                body,
            )
        )
        settings = make_settings(endpoint_for(server), analysis_max_response_bytes=256)
        adapter = HttpDocumentAnalysisAdapter(settings=settings)

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert exc.value.code == ANALYSIS_RESPONSE_TOO_LARGE


class TestCredentialRedaction:
    async def test_error_messages_never_contain_token(self, provider_server):
        server = provider_server(
            json_responder(provider_payload(), status="500 Internal Server Error")
        )
        settings = make_settings(endpoint_for(server), analysis_max_attempts=1)
        adapter = HttpDocumentAnalysisAdapter(settings=settings)

        with pytest.raises(HandoffError) as exc:
            await adapter.analyze(make_document(), correlation_id="corr")
        assert TOKEN not in exc.value.message
        assert TOKEN not in str(exc.value)
