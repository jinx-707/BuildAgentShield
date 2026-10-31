"""
API Gateway — enforced entry point for all external API calls.
LLM never receives unrestricted network access or credentials.
"""
from __future__ import annotations

import logging
from typing import Any

from app.capabilities.online.external_apis.api_executor import APIExecutor
from app.capabilities.online.external_apis.connector_registry import ConnectorRegistry
from app.capabilities.online.external_apis.credential_manager import CredentialManager
from app.capabilities.online.external_apis.request_policy import RequestPolicy
from app.core.contracts import GatewayResponse, SecurityContext
from app.core.decisions import SecurityDecision
from app.core.exceptions import (
    APIError,
    APISchemaValidationError,
    RateLimitError,
    UnknownConnectorError,
)
from app.integrations.ports import (
    AuditEvent,
    AuditPort,
    DataInspectionPort,
    PolicyContext,
    PolicyPort,
    SecretProviderPort,
)

logger = logging.getLogger(__name__)


class APIGateway:
    """
    Enforces all security rules for external API calls.
    Every call passes through: registry check → method/path validation →
    credential injection → execution → response inspection → audit.
    """

    def __init__(
        self,
        policy: PolicyPort,
        audit: AuditPort,
        data_inspector: DataInspectionPort,
        registry: ConnectorRegistry,
        secret_provider: SecretProviderPort,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._data_inspector = data_inspector
        self._registry = registry
        cred_manager = CredentialManager(secret_provider)
        self._executor = APIExecutor(cred_manager)
        self._request_policy = RequestPolicy(registry)

    async def execute(
        self,
        ctx: SecurityContext,
        connector_id: str,
        method: str,
        path: str,
        query_params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> GatewayResponse:
        # Policy check
        policy_decision = await self._policy.authorize(
            PolicyContext(
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                capability="apis",
                operation="execute",
                resource=connector_id,
            )
        )
        if not policy_decision.allowed:
            await self._record_audit(ctx, "DENY", "BLOCKED", policy_decision.reason, connector_id)
            return GatewayResponse.deny(ctx, policy_decision.reason, policy_decision.policy_id)

        try:
            # Validate connector, method, path
            connector = self._request_policy.validate_request(
                connector_id=connector_id,
                method=method,
                path=path,
                headers=extra_headers,
            )

            # Execute through connector
            result = await self._executor.execute(
                connector=connector,
                method=method,
                path=path,
                query_params=query_params,
                body=body,
                extra_headers=extra_headers,
            )

            # Inspect response for sensitive data leakage
            import json as _json
            response_str = _json.dumps(result.response_body) if not isinstance(
                result.response_body, str
            ) else result.response_body

            dlp_result = await self._data_inspector.inspect(
                content=response_str[:10000],  # limit for inspection
                metadata={"connector": connector_id, "path": path},
            )

            await self._record_audit(ctx, "ALLOW", "EXECUTED", resource=connector_id)

            result_dict = result.model_dump()
            if not dlp_result.safe_to_use:
                result_dict["dlp_warning"] = (
                    "Response contained potentially sensitive data. "
                    "Review before using."
                )
                logger.warning(
                    "API response DLP warning: connector=%s findings=%d",
                    connector_id, len(dlp_result.findings)
                )

            return GatewayResponse.allow(ctx, result=result_dict)

        except UnknownConnectorError as e:
            await self._record_audit(ctx, "DENY", "BLOCKED", str(e), connector_id)
            return GatewayResponse.deny(ctx, str(e), "API-CONNECTOR-001")

        except APISchemaValidationError as e:
            await self._record_audit(ctx, "DENY", "BLOCKED", str(e), connector_id)
            return GatewayResponse.deny(ctx, str(e), "API-SCHEMA-001")

        except RateLimitError as e:
            await self._record_audit(ctx, "DENY", "BLOCKED", str(e), connector_id)
            return GatewayResponse.deny(ctx, str(e), "API-RATELIMIT-001")

        except APIError as e:
            await self._record_audit(ctx, "ALLOW", "FAILED", str(e), connector_id)
            return GatewayResponse(
                request_id=ctx.request_id,
                status="FAILED",
                decision=SecurityDecision.ALLOW,
                capability="apis",
                operation="execute",
                reason=str(e),
            )

    async def _record_audit(
        self,
        ctx: SecurityContext,
        decision: str,
        status: str,
        reason: str | None = None,
        resource: str | None = None,
    ) -> None:
        await self._audit.record(
            AuditEvent(
                event_type="API_EXECUTE",
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                capability="apis",
                operation="execute",
                decision=decision,
                status=status,
                request_id=ctx.request_id,
                resource=resource,
                reason=reason,
            )
        )
