"""
AgentShield Offline — Secret Provider Interface and Mock.

⚠️  DEVELOPMENT COMPONENT ⚠️

Provides a provider-independent interface for secret retrieval.
The mock provider is for development and testing ONLY — it stores
secrets in memory and must never be used in production.

In production, replace with a Vault adapter or cloud secrets manager.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Optional

import structlog

log = structlog.get_logger(__name__)

_MOCK_NOTE = (
    "MOCK_SECRET_PROVIDER — development only. "
    "Replace with HashiCorp Vault or cloud secrets manager in production."
)


class SecretProviderBase(ABC):
    """Abstract base for secret providers."""

    @abstractmethod
    async def get_secret(self, secret_id: str) -> Optional[str]:
        """Return the secret value or None if not found. NEVER log the value."""
        ...

    @abstractmethod
    async def secret_exists(self, secret_id: str) -> bool:
        ...


class MockSecretProvider(SecretProviderBase):
    """
    In-memory mock provider for development and testing.
    Secrets are loaded from environment variables with a MOCK_SECRET_ prefix
    or from a provided dictionary.

    ⚠️  NOT FOR PRODUCTION USE ⚠️
    """

    def __init__(self, secrets: Optional[dict[str, str]] = None) -> None:
        # Load from environment variables prefixed with MOCK_SECRET_
        self._secrets: dict[str, str] = {}
        for k, v in os.environ.items():
            if k.startswith("MOCK_SECRET_"):
                sid = k[len("MOCK_SECRET_"):]
                self._secrets[sid] = v

        # Layer in programmatically provided secrets (for tests)
        if secrets:
            self._secrets.update(secrets)

        log.warning(
            "mock_secret_provider_active",
            note=_MOCK_NOTE,
            secret_count=len(self._secrets),
        )

    async def get_secret(self, secret_id: str) -> Optional[str]:
        value = self._secrets.get(secret_id)
        # Never log the value
        log.debug("mock_secret_get", secret_id=secret_id, found=value is not None)
        return value

    async def secret_exists(self, secret_id: str) -> bool:
        return secret_id in self._secrets


class VaultSecretProviderAdapter(SecretProviderBase):
    """
    Placeholder adapter for HashiCorp Vault.
    Complete the implementation when the Vault SDK is available.

    Replace MockSecretProvider with this in production via dependency injection.
    """

    def __init__(self, vault_url: str, vault_token: str, mount_point: str = "secret") -> None:
        self._url = vault_url
        self._token = vault_token  # treat as opaque — never log
        self._mount = mount_point
        log.info("vault_adapter_initialized", url=vault_url, mount=mount_point)

    async def get_secret(self, secret_id: str) -> Optional[str]:
        # Implementation would use hvac or httpx to call Vault
        # Example:
        # response = await self._client.get(
        #     f"{self._url}/v1/{self._mount}/data/{secret_id}",
        #     headers={"X-Vault-Token": self._token},
        # )
        # return response.json()["data"]["data"].get("value")
        raise NotImplementedError("VaultSecretProviderAdapter is not yet fully implemented")

    async def secret_exists(self, secret_id: str) -> bool:
        raise NotImplementedError("VaultSecretProviderAdapter is not yet fully implemented")
