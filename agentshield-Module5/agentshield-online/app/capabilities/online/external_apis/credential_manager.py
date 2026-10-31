"""
Credential manager for external API connectors.
Credentials are injected server-side only.
NEVER exposed to LLM contexts or returned in API responses.
"""
from __future__ import annotations

import logging
from typing import Any

from app.capabilities.online.external_apis.connector_registry import ConnectorConfig
from app.integrations.ports import SecretProviderPort

logger = logging.getLogger(__name__)


class CredentialManager:
    """
    Retrieves and injects credentials for API connectors.
    All credential access goes through SecretProviderPort.
    """

    def __init__(self, secret_provider: SecretProviderPort) -> None:
        self._secrets = secret_provider

    async def inject_auth_headers(
        self,
        connector: ConnectorConfig,
        headers: dict[str, str],
        context: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """
        Inject authentication headers based on connector auth_type.
        Returns headers dict with auth added.
        Raises CredentialError if credentials cannot be retrieved.
        """
        if connector.auth_type == "none":
            return headers

        if not connector.credential_id:
            logger.warning(
                "Connector %s requires auth but has no credential_id", connector.id
            )
            return headers

        credential_value = await self._secrets.get_credential(
            credential_id=connector.credential_id,
            context=context,
        )

        if connector.auth_type == "api_key":
            headers["X-API-Key"] = credential_value
        elif connector.auth_type == "bearer":
            headers["Authorization"] = f"Bearer {credential_value}"
        elif connector.auth_type == "basic":
            import base64
            encoded = base64.b64encode(credential_value.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        # Never log or return the credential value
        return headers
