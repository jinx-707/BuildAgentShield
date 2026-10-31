"""
HTTP document-analysis adapter (provider contract v1).

Security properties
-------------------
* The endpoint is fixed by configuration and validated at construction
  (HTTPS, standard port, no embedded credentials, IP policy).
* Every request uses a fresh, explicitly built transport
  (security/analysis_egress.py): proxy policy applied and attested exactly as
  for downloads, per-request DNS/IP re-validation, ``trust_env=False`` so no
  HTTP(S)_PROXY environment variable is honoured, redirects disabled, and a
  final check that the target is still the configured endpoint.
* Request bodies are built from approved bytes only and are refused before
  sending when they exceed ANALYSIS_MAX_PAYLOAD_BYTES.
* Response bodies are read incrementally and aborted past
  ANALYSIS_MAX_RESPONSE_BYTES; only ``application/json`` responses are parsed.
* Retries are bounded (attempts, retry delay, total deadline) and applied only
  to transient outcomes: timeouts, connection failures, 429 and 5xx.
* The bearer token, document text, document bytes and raw provider responses
  are never logged.  Errors carry fixed messages plus structural fields
  (status code, error code).
* A 3xx response is rejected rather than followed, so the Authorization header
  can never be replayed to an unexpected destination.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from typing import Callable

import httpx
from pydantic import ValidationError

from config.settings import Settings
from integrations.analysis_models import (
    ANALYSIS_SCHEMA_VERSION,
    AnalysisRequest,
    AnalysisRequestDocument,
    ProviderAnalysisResponse,
)
from integrations.handoff import (
    AnalysisDocument,
    DisabledAnalysisAdapter,
    DocumentAnalysisAdapter,
    HandoffError,
    MockDocumentAnalysisAdapter,
)
from security.analysis_egress import (
    AnalysisEndpoint,
    build_analysis_transport,
    validate_analysis_endpoint,
)
from security.errors import (
    ANALYSIS_AUTH_FAILED,
    ANALYSIS_ENDPOINT_BLOCKED,
    ANALYSIS_INVALID_RESPONSE,
    ANALYSIS_PAYLOAD_TOO_LARGE,
    ANALYSIS_PROVIDER_ERROR,
    ANALYSIS_PROVIDER_RATE_LIMITED,
    ANALYSIS_REDIRECT_BLOCKED,
    ANALYSIS_REQUEST_REJECTED,
    ANALYSIS_RESPONSE_TOO_LARGE,
    ANALYSIS_TIMEOUT,
    ANALYSIS_UNAVAILABLE,
    DownloadSecurityError,
)

logger = logging.getLogger(__name__)

_MAX_RETRY_DELAY_SECONDS = 5.0
_MAX_RETRY_AFTER_SECONDS = 5.0
_WRITE_TIMEOUT_SECONDS = 10.0
_POOL_TIMEOUT_SECONDS = 5.0


class HttpDocumentAnalysisAdapter:
    """Provider-contract-v1 adapter over hardened httpx transports."""

    provider_name = "http"

    def __init__(
        self,
        *,
        settings: Settings,
        transport_factory: Callable[..., httpx.AsyncBaseTransport]
        | None = None,
    ) -> None:
        self._settings = settings
        self._endpoint = validate_analysis_endpoint(
            settings.analysis_endpoint_url,
            allow_insecure_local=settings.analysis_allow_insecure_local,
            allow_private_endpoints=settings.analysis_allow_private_endpoints,
        )
        self._token = settings.analysis_api_token
        self._max_payload = settings.analysis_max_payload_bytes
        self._max_response = settings.analysis_max_response_bytes
        self._max_attempts = settings.analysis_max_attempts
        self._base_delay = settings.analysis_retry_base_delay_seconds
        self._total_timeout = settings.analysis_total_timeout_seconds
        self._timeout = httpx.Timeout(
            connect=settings.analysis_connect_timeout_seconds,
            read=settings.analysis_read_timeout_seconds,
            write=_WRITE_TIMEOUT_SECONDS,
            pool=_POOL_TIMEOUT_SECONDS,
        )
        self._transport_factory = transport_factory or build_analysis_transport

    # ── Public ───────────────────────────────────────────────────────────────

    async def analyze(
        self,
        document: AnalysisDocument,
        *,
        correlation_id: str,
    ) -> ProviderAnalysisResponse:
        body = self._build_body(document, correlation_id)
        idempotency_key = (
            f"{document.payload.download_id}:{document.payload.sha256}"
        )

        last_error: HandoffError | None = None
        try:
            async with asyncio.timeout(self._total_timeout):
                for attempt in range(1, self._max_attempts + 1):
                    try:
                        return await self._attempt(
                            body=body,
                            correlation_id=correlation_id,
                            idempotency_key=idempotency_key,
                        )
                    except HandoffError as exc:
                        last_error = exc
                        if not exc.retriable or attempt >= self._max_attempts:
                            raise
                        delay = min(
                            self._base_delay * (2 ** (attempt - 1)),
                            _MAX_RETRY_DELAY_SECONDS,
                        )
                        if exc.retry_after is not None:
                            delay = min(exc.retry_after, _MAX_RETRY_AFTER_SECONDS)
                        logger.warning(
                            "analysis_provider_retry",
                            extra={
                                "provider": self.provider_name,
                                "attempt": attempt,
                                "code": exc.code,
                            },
                        )
                        await asyncio.sleep(delay)
        except TimeoutError as exc:
            raise HandoffError(
                f"Analysis provider call exceeded the total deadline of "
                f"{self._total_timeout:g}s.",
                code=ANALYSIS_TIMEOUT,
                retriable=True,
            ) from exc

        # The loop only exits through return/raise; this is defensive.
        raise last_error or HandoffError(
            "Analysis provider call failed.", code=ANALYSIS_PROVIDER_ERROR
        )

    # ── Request building ─────────────────────────────────────────────────────

    def _build_body(self, document: AnalysisDocument, correlation_id: str) -> bytes:
        payload = document.payload
        request = AnalysisRequest(
            correlation_id=correlation_id,
            document=AnalysisRequestDocument(
                download_id=payload.download_id,
                tenant_id=payload.tenant_id,
                agent_id=payload.agent_id,
                sha256=payload.sha256,
                mime_type=payload.mime_type,
                size_bytes=payload.file_size,
                page_count=document.page_count,
                text_truncated=document.text_truncated,
                extracted_text=document.extracted_text,
                warnings=list(document.warnings),
            ),
            content_base64=base64.b64encode(document.content).decode("ascii"),
        )
        body = request.model_dump_json().encode("utf-8")
        if len(body) > self._max_payload:
            raise HandoffError(
                f"Analysis request is {len(body)} bytes; the configured limit "
                f"is {self._max_payload}.",
                code=ANALYSIS_PAYLOAD_TOO_LARGE,
                retriable=False,
            )
        return body

    # ── One HTTP attempt ─────────────────────────────────────────────────────

    async def _attempt(
        self,
        *,
        body: bytes,
        correlation_id: str,
        idempotency_key: str,
    ) -> ProviderAnalysisResponse:
        transport = self._transport_factory(
            settings=self._settings, endpoint=self._endpoint
        )
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "POST",
                    self._endpoint.url,
                    headers={
                        "Authorization": f"Bearer {self._token}",
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "X-Correlation-ID": correlation_id,
                        "Idempotency-Key": idempotency_key,
                    },
                    content=body,
                ) as response:
                    result = await self._handle_response(
                        response, correlation_id=correlation_id
                    )
        except HandoffError:
            raise
        except httpx.TimeoutException as exc:
            raise HandoffError(
                "The analysis provider timed out.",
                code=ANALYSIS_TIMEOUT,
                retriable=True,
            ) from exc
        except httpx.ProxyError as exc:
            raise HandoffError(
                "The egress proxy rejected the analysis connection.",
                code=ANALYSIS_UNAVAILABLE,
                retriable=True,
            ) from exc
        except DownloadSecurityError as exc:
            logger.warning(
                "analysis_destination_rejected",
                extra={"provider": self.provider_name, "code": exc.code},
            )
            raise HandoffError(
                "The analysis destination failed the egress security policy.",
                code=ANALYSIS_ENDPOINT_BLOCKED,
                retriable=False,
            ) from None
        except httpx.HTTPError as exc:
            raise HandoffError(
                "The analysis provider could not be reached.",
                code=ANALYSIS_UNAVAILABLE,
                retriable=True,
            ) from exc
        finally:
            await transport.aclose()

        logger.info(
            "analysis_provider_response",
            extra={
                "provider": self.provider_name,
                "status": 200,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            },
        )
        return result

    async def _handle_response(
        self,
        response: httpx.Response,
        *,
        correlation_id: str,
    ) -> ProviderAnalysisResponse:
        status = response.status_code

        if 300 <= status < 400:
            raise HandoffError(
                "The analysis provider responded with a redirect; redirects "
                "are not followed.",
                code=ANALYSIS_REDIRECT_BLOCKED,
                retriable=False,
            )
        if status in (401, 403):
            raise HandoffError(
                "The analysis provider rejected the credentials.",
                code=ANALYSIS_AUTH_FAILED,
                retriable=False,
            )
        if status == 429:
            raise HandoffError(
                "The analysis provider is rate limiting requests.",
                code=ANALYSIS_PROVIDER_RATE_LIMITED,
                retriable=True,
                retry_after=_parse_retry_after(response.headers.get("retry-after")),
            )
        if status >= 500:
            raise HandoffError(
                f"The analysis provider is unavailable (HTTP {status}).",
                code=ANALYSIS_PROVIDER_ERROR,
                retriable=True,
            )
        if status != 200:
            raise HandoffError(
                f"The analysis provider rejected the request (HTTP {status}).",
                code=ANALYSIS_REQUEST_REJECTED,
                retriable=False,
            )

        content_type = response.headers.get("content-type", "")
        if not content_type.lower().startswith("application/json"):
            raise HandoffError(
                "The analysis provider returned a non-JSON response.",
                code=ANALYSIS_INVALID_RESPONSE,
                retriable=False,
            )

        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > self._max_response:
                    raise HandoffError(
                        "The analysis provider response exceeds the configured "
                        "size limit.",
                        code=ANALYSIS_RESPONSE_TOO_LARGE,
                        retriable=False,
                    )
            except ValueError:
                raise HandoffError(
                    "The analysis provider returned an invalid Content-Length.",
                    code=ANALYSIS_INVALID_RESPONSE,
                    retriable=False,
                ) from None

        raw = await self._read_bounded(response)

        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise HandoffError(
                "The analysis provider returned invalid JSON.",
                code=ANALYSIS_INVALID_RESPONSE,
                retriable=False,
            ) from exc

        try:
            parsed = ProviderAnalysisResponse.model_validate(payload)
        except ValidationError as exc:
            logger.warning(
                "analysis_provider_schema_invalid",
                extra={
                    "provider": self.provider_name,
                    "error_count": exc.error_count(),
                },
            )
            raise HandoffError(
                "The analysis provider response did not match the expected "
                "schema.",
                code=ANALYSIS_INVALID_RESPONSE,
                retriable=False,
            ) from None

        if parsed.schema_version != ANALYSIS_SCHEMA_VERSION:
            raise HandoffError(
                "The analysis provider used an unsupported schema version.",
                code=ANALYSIS_INVALID_RESPONSE,
                retriable=False,
            )

        if parsed.status == "failed":
            provider_code = parsed.error.code if parsed.error else ""
            raise HandoffError(
                "The analysis provider reported a failed analysis"
                + (f" (code {provider_code})." if provider_code else "."),
                code=ANALYSIS_PROVIDER_ERROR,
                retriable=bool(parsed.error and parsed.error.retryable),
            )

        return parsed

    async def _read_bounded(self, response: httpx.Response) -> bytes:
        buffer = bytearray()
        async for chunk in response.aiter_bytes():
            buffer.extend(chunk)
            if len(buffer) > self._max_response:
                raise HandoffError(
                    "The analysis provider response exceeds the configured "
                    "size limit.",
                    code=ANALYSIS_RESPONSE_TOO_LARGE,
                    retriable=False,
                )
        return bytes(buffer)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return max(seconds, 0.0)


def build_analysis_adapter(settings: Settings) -> DocumentAnalysisAdapter:
    """
    Select the adapter for the configured provider mode.

    Selection is explicit and config-driven; there is no fallback.  A failed
    HTTP adapter construction (bad endpoint) raises and startup fails — it
    never silently degrades to the mock.
    """
    if settings.analysis_provider == "http":
        return HttpDocumentAnalysisAdapter(settings=settings)
    if settings.analysis_provider == "local_mock":
        return MockDocumentAnalysisAdapter()
    return DisabledAnalysisAdapter()
