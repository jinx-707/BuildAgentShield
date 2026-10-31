"""
Secret providers — environment-based (local dev) and Vault adapter stub.

Credentials are NEVER exposed to LLM contexts or returned in API responses.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from app.core.exceptions import CredentialError
from app.integrations.ports import SecretProviderPort

logger = logging.getLogger(__name__)


class LocalEnvSecretProvider(SecretProviderPort):
    """
    Reads credentials from environment variables.
    For local development only.

    Credential IDs map to environment variable names.
    Example: "RAZORPAY_KEY_SECRET" -> os.environ["RAZORPAY_KEY_SECRET"]
    """

    async def get_credential(
        self,
        credential_id: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        value = os.environ.get(credential_id)
        if not value:
            raise CredentialError(
                f"Credential '{credential_id}' not found in environment. "
                f"Set {credential_id} in your .env file."
            )
        return value


class VaultSecretProvider(SecretProviderPort):
    """
    HashiCorp Vault secret provider.
    Connects to Vault using VAULT_URL and VAULT_TOKEN from environment.

    This is a stub — install hvac and configure Vault to activate.
    """

    def __init__(self, vault_url: str, vault_token: str, mount: str = "secret") -> None:
        self._vault_url = vault_url
        self._vault_token = vault_token
        self._mount = mount
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import hvac  # type: ignore
                self._client = hvac.Client(
                    url=self._vault_url,
                    token=self._vault_token,
                )
                if not self._client.is_authenticated():
                    raise CredentialError("Vault authentication failed")
            except ImportError:
                raise CredentialError(
                    "hvac package not installed. Run: pip install hvac"
                )
        return self._client

    async def get_credential(
        self,
        credential_id: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        try:
            client = self._get_client()
            # credential_id format: "path/to/secret:field"
            if ":" in credential_id:
                path, field = credential_id.rsplit(":", 1)
            else:
                path = credential_id
                field = "value"

            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self._mount,
            )
            data = response["data"]["data"]
            if field not in data:
                raise CredentialError(
                    f"Field '{field}' not found in Vault secret '{path}'"
                )
            return str(data[field])
        except CredentialError:
            raise
        except Exception as e:
            raise CredentialError(f"Vault error for '{credential_id}': {e}") from e
