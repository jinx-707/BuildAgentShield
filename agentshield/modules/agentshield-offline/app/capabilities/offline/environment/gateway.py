"""
AgentShield Offline — Environment Protection Gateway.
"""

from __future__ import annotations

import structlog

from app.capabilities.offline.environment.environment_guard import EnvironmentGuard
from app.capabilities.offline.environment.environment_policy import EnvironmentPolicy
from app.capabilities.offline.environment.secret_broker import SecretBroker
from app.core.contracts import (
    BaseOfflineResponse,
    EnvironmentInspectRequest,
    OfflineModule,
    RiskLevel,
    SecretAccessRequest,
)
from app.core.decisions import allow_response, deny_response
from app.core.exceptions import SecretAccessDeniedError

log = structlog.get_logger(__name__)
_MODULE = OfflineModule.ENVIRONMENT_PROTECTION


class EnvironmentGateway:
    """
    Single enforcement point for all environment and secret access.
    """

    def __init__(
        self,
        policy: EnvironmentPolicy,
        guard: EnvironmentGuard,
        secret_broker: SecretBroker,
    ) -> None:
        self._policy = policy
        self._guard = guard
        self._broker = secret_broker

    async def inspect(
        self, request: EnvironmentInspectRequest
    ) -> BaseOfflineResponse:
        """
        Inspect whether a set of environment variables is accessible.
        Returns per-variable decisions but NEVER their values.
        """
        results = self._guard.inspect_requested_vars(
            request.variable_names, request.agent_id
        )
        allowed = {k: v for k, v in results.items() if v[0]}
        denied = {k: v[1] for k, v in results.items() if not v[0]}

        if denied:
            log.warning(
                "environment_inspect_denied_vars",
                agent_id=request.agent_id,
                denied_count=len(denied),
            )

        return allow_response(
            request_id=request.request_id,
            module=_MODULE,
            tool=request.tool_name,
            result={
                "allowed_variables": list(allowed.keys()),
                "denied_variables": {k: v for k, v in denied.items()},
                # Values are intentionally NOT included
            },
            risk_level=RiskLevel.LOW if not denied else RiskLevel.MEDIUM,
        )

    async def access_secret(
        self, request: SecretAccessRequest
    ) -> BaseOfflineResponse:
        """
        Retrieve a secret through the broker.
        The response NEVER includes the secret value in plaintext fields.
        The value must be used internally only.
        """
        try:
            value = await self._broker.retrieve(
                request.secret_id,
                agent_id=request.agent_id,
                purpose=request.purpose,
            )
            # Return a token/reference — never the raw value in the response
            return allow_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                result={
                    "secret_id": request.secret_id,
                    "retrieved": True,
                    # secret value not exposed here
                },
                risk_level=RiskLevel.MEDIUM,
            )
        except SecretAccessDeniedError as exc:
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason=exc.message,
                risk_level=RiskLevel.HIGH,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("secret_access_error", error=str(exc))
            return deny_response(
                request_id=request.request_id,
                module=_MODULE,
                tool=request.tool_name,
                reason="Secret retrieval failed",
                risk_level=RiskLevel.HIGH,
            )
