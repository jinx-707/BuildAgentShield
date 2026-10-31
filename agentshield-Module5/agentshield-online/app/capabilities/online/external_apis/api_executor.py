"""
API Executor — executes authenticated, validated HTTP requests to approved connectors.
Credentials are injected here — never from agent input.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.capabilities.online.external_apis.connector_registry import ConnectorConfig
from app.capabilities.online.external_apis.credential_manager import CredentialManager
from app.capabilities.online.external_apis.schema_validator import (
    sanitize_response,
    validate_request_schema,
)
from app.core.exceptions import APIError, APISchemaValidationError, RateLimitError
from app.core.result_models import APICallResult

logger = logging.getLogger(__name__)


class APIExecutor:
    """
    Executes HTTP requests through approved connectors.
    Injects credentials, validates schemas, sanitizes responses.
    """

    def __init__(self, credential_manager: CredentialManager) -> None:
        self._cred_manager = credential_manager
        # Simple in-memory rate limit counters (replace with Redis in production)
        self._call_counts: dict[str, list[float]] = {}

    async def execute(
        self,
        connector: ConnectorConfig,
        method: str,
        path: str,
        query_params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> APICallResult:
        """
        Execute the request through the connector.
        Returns sanitized APICallResult.
        """
        # Rate limit check
        self._check_rate_limit(connector)

        # Validate request schema
        if connector.request_schema and body:
            valid, reason = validate_request_schema(body, connector.request_schema)
            if not valid:
                raise APISchemaValidationError(
                    f"Request schema validation failed for {connector.id}: {reason}"
                )

        # Build headers (agent cannot inject auth)
        headers: dict[str, str] = {}
        if extra_headers:
            # Only allow safe extra headers from agent
            safe_headers = {
                k: v for k, v in extra_headers.items()
                if k.lower() not in {"authorization", "x-api-key", "cookie", "x-forwarded-for"}
            }
            headers.update(safe_headers)

        # Inject credentials from SecretProvider
        headers = await self._cred_manager.inject_auth_headers(
            connector=connector,
            headers=headers,
        )

        # Build full URL
        from app.capabilities.online.external_apis.request_policy import RequestPolicy
        url = connector.base_url.rstrip("/") + (path if path.startswith("/") else f"/{path}")

        # Execute request
        timeout = httpx.Timeout(float(connector.timeout_seconds))
        start = time.monotonic()

        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                verify=True,
                follow_redirects=False,  # don't follow redirects automatically
            ) as client:
                resp = await client.request(
                    method=method.upper(),
                    url=url,
                    params=query_params,
                    json=body if method.upper() in ("POST", "PUT", "PATCH") else None,
                    headers=headers,
                )
                duration_ms = (time.monotonic() - start) * 1000

                # Response size limit
                content_length = len(resp.content)
                if content_length > connector.response_size_limit_bytes:
                    raise APIError(
                        f"Response size {content_length} exceeds limit "
                        f"{connector.response_size_limit_bytes} for connector {connector.id}"
                    )

                # Parse response
                try:
                    response_body = resp.json()
                except Exception:
                    response_body = resp.text

                # Sanitize — remove internal error details
                response_body = sanitize_response(
                    response_body,
                    max_size=connector.response_size_limit_bytes,
                )

                # Record the call
                self._record_call(connector.id)

                return APICallResult(
                    connector=connector.id,
                    method=method.upper(),
                    path=path,
                    status_code=resp.status_code,
                    response_body=response_body,
                    duration_ms=round(duration_ms, 2),
                )

        except httpx.ConnectError as e:
            raise APIError(f"Cannot connect to {connector.name}: connection refused")
        except httpx.TimeoutException:
            raise APIError(f"Request to {connector.name} timed out after {connector.timeout_seconds}s")
        except (APIError, APISchemaValidationError):
            raise
        except Exception as e:
            # Sanitize error — don't leak internal details
            raise APIError(f"API call to {connector.name} failed: {type(e).__name__}")

    def _check_rate_limit(self, connector: ConnectorConfig) -> None:
        now = time.monotonic()
        window = 60.0
        key = connector.id
        calls = self._call_counts.get(key, [])
        # Purge calls outside the window
        calls = [t for t in calls if now - t < window]
        if len(calls) >= connector.rate_limit_per_minute:
            raise RateLimitError(
                f"Rate limit exceeded for connector '{connector.id}': "
                f"{connector.rate_limit_per_minute} requests/minute"
            )
        self._call_counts[key] = calls

    def _record_call(self, connector_id: str) -> None:
        now = time.monotonic()
        calls = self._call_counts.get(connector_id, [])
        calls.append(now)
        self._call_counts[connector_id] = calls
