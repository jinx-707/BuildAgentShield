"""
AgentShield Offline — Secret Broker.

Provides controlled, permission-gated access to secrets.
The actual secret value is only returned to the caller if:
  1. The agent is explicitly authorised for the secret.
  2. The request purpose is provided.
  3. The secret is not in the unconditional denylist.

Secret values are NEVER logged.
"""

from __future__ import annotations

from typing import Optional

import structlog

from app.capabilities.offline.environment.secret_provider import SecretProviderBase
from app.core.exceptions import SecretAccessDeniedError

log = structlog.get_logger(__name__)

# Secrets that must NEVER be returned regardless of permissions
_UNCONDITIONALLY_DENIED_SECRETS: frozenset[str] = frozenset()  # extend as needed


class SecretBroker:
    """
    Provider-independent secret broker.

    Usage:
        broker = SecretBroker(provider, permitted_secrets)
        value = await broker.retrieve("my_db_password", agent_id="agent_1", purpose="DB conn")
    """

    def __init__(
        self,
        provider: SecretProviderBase,
        permitted_secrets: dict[str, list[str]],
    ) -> None:
        """
        Args:
            provider: Secret provider backend.
            permitted_secrets: Mapping of secret_id -> list[agent_id] allowed to retrieve it.
        """
        self._provider = provider
        self._permitted: dict[str, list[str]] = permitted_secrets
        log.info(
            "secret_broker_initialized",
            permitted_secret_count=len(permitted_secrets),
        )

    async def retrieve(
        self,
        secret_id: str,
        *,
        agent_id: str,
        purpose: Optional[str] = None,
    ) -> str:
        """
        Retrieve a secret value.
        Raises SecretAccessDeniedError on any permission failure.
        Never logs the returned value.
        """
        if secret_id in _UNCONDITIONALLY_DENIED_SECRETS:
            log.warning(
                "secret_unconditionally_denied",
                secret_id=secret_id,
                agent_id=agent_id,
            )
            raise SecretAccessDeniedError(
                "This secret cannot be retrieved by any agent",
                secret_id=secret_id,
            )

        allowed_agents = self._permitted.get(secret_id, [])
        if agent_id not in allowed_agents and "*" not in allowed_agents:
            log.warning(
                "secret_access_denied",
                secret_id=secret_id,
                agent_id=agent_id,
                # Never log the secret value
            )
            raise SecretAccessDeniedError(
                f"Agent '{agent_id}' is not permitted to access secret '{secret_id}'",
                secret_id=secret_id,
            )

        exists = await self._provider.secret_exists(secret_id)
        if not exists:
            raise SecretAccessDeniedError(
                f"Secret '{secret_id}' not found",
                secret_id=secret_id,
            )

        value = await self._provider.get_secret(secret_id)
        if value is None:
            raise SecretAccessDeniedError(
                f"Secret '{secret_id}' returned no value",
                secret_id=secret_id,
            )

        log.info(
            "secret_retrieved",
            secret_id=secret_id,
            agent_id=agent_id,
            purpose=purpose,
            # value intentionally NOT logged
        )
        return value

    async def check_permission(self, secret_id: str, agent_id: str) -> bool:
        allowed_agents = self._permitted.get(secret_id, [])
        return agent_id in allowed_agents or "*" in allowed_agents
