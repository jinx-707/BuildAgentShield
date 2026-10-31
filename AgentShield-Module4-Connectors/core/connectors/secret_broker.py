"""
AgentShield Secret Broker.
Secure credential store and injection gateway.
Guarantees:
  - Raw API keys, bearer tokens, and credentials are NEVER exposed to AI models or agents.
  - Credentials are never stored in tool descriptions, schemas, or LLM-visible outputs.
  - Credentials are automatically scrubbed from headers, logs, error messages, and audit trails.
"""

from __future__ import annotations

import base64
import os
import threading
from typing import Any

from core.config import setup_logger
from core.connectors.models import AuthenticationConfig, AuthType
from core.secret_scanner import SecretScanner

logger = setup_logger("agentshield.connectors.secret_broker")


class SecretBroker:
    """
    Secure Broker for external API keys and authentication tokens.
    Coordinates secure storage, injection into outbound requests,
    and automatic scrubbing from inbound/outbound payloads.
    """

    def __init__(self, secret_scanner: SecretScanner | None = None) -> None:
        self._lock = threading.RLock()
        self._secrets: dict[str, str] = {}
        self._secret_scanner = secret_scanner or SecretScanner()

    def store_secret(self, secret_id: str, secret_value: str) -> None:
        """Stores a secret credential securely in memory."""
        with self._lock:
            key = secret_id.strip()
            val = secret_value.strip()
            self._secrets[key] = val
            logger.info("Secret stored for ID '%s' (masked: %s)", key, self.mask_secret(val))

    def get_secret(self, secret_id: str) -> str | None:
        """
        Retrieves a secret by ID.
        Checks internal vault first, then environment variables (AGENTSHIELD_SECRET_<ID> or <ID>).
        NOTE: This must only be invoked by internal gateway transport, never returned to agent!
        """
        with self._lock:
            if secret_id in self._secrets:
                return self._secrets[secret_id]

            # Fall back to environment variable
            env_key_1 = f"AGENTSHIELD_SECRET_{secret_id.upper()}"
            env_key_2 = secret_id.upper()
            if env_key_1 in os.environ:
                return os.environ[env_key_1]
            if env_key_2 in os.environ:
                return os.environ[env_key_2]

            return None

    def delete_secret(self, secret_id: str) -> bool:
        """Removes a secret from the vault."""
        with self._lock:
            if secret_id in self._secrets:
                del self._secrets[secret_id]
                logger.info("Deleted secret ID '%s'", secret_id)
                return True
            return False

    def inject_auth(
        self,
        auth_config: AuthenticationConfig,
        headers: dict[str, str],
        query_params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, str], dict[str, Any]]:
        """
        Injects authentication credentials directly into outbound HTTP headers or query params.
        Operates on shallow copies to preserve immutability of the caller's request.
        """
        out_headers = dict(headers)
        out_params = dict(query_params or {})

        # Include any configured static custom headers
        if auth_config.custom_headers:
            out_headers.update(auth_config.custom_headers)

        if auth_config.auth_type == AuthType.NONE or not auth_config.secret_id:
            return out_headers, out_params

        secret = self.get_secret(auth_config.secret_id)
        if not secret:
            logger.warning("Secret ID '%s' requested by auth_config was not found in vault", auth_config.secret_id)
            return out_headers, out_params

        if auth_config.auth_type == AuthType.BEARER_TOKEN or auth_config.auth_type == AuthType.OAUTH2:
            prefix = auth_config.token_prefix or "Bearer "
            out_headers[auth_config.header_name] = f"{prefix}{secret}"

        elif auth_config.auth_type == AuthType.API_KEY:
            if auth_config.query_param_name:
                out_params[auth_config.query_param_name] = secret
            else:
                out_headers[auth_config.header_name] = secret

        elif auth_config.auth_type == AuthType.CUSTOM_HEADER:
            out_headers[auth_config.header_name] = secret

        elif auth_config.auth_type == AuthType.BASIC:
            # If secret contains username:password or already base64
            if ":" in secret:
                b64 = base64.b64encode(secret.encode("utf-8")).decode("ascii")
                out_headers[auth_config.header_name] = f"Basic {b64}"
            else:
                out_headers[auth_config.header_name] = f"Basic {secret}"

        return out_headers, out_params

    def scrub_text(self, text: str) -> str:
        """
        Scans text and scrubs any known secret values or high-entropy patterns.
        Replaces matched secrets with '[REDACTED_CREDENTIAL]'.
        """
        if not text:
            return text

        scrubbed = text

        # 1. Scrub all known stored secrets directly
        with self._lock:
            for sec_val in self._secrets.values():
                if sec_val and len(sec_val) >= 4 and sec_val in scrubbed:
                    scrubbed = scrubbed.replace(sec_val, "[REDACTED_CREDENTIAL]")

        # 2. Run through existing SecretScanner to catch standard patterns (API keys, tokens, entropy)
        try:
            scan_res = self._secret_scanner.scan(scrubbed)
            if scan_res.has_secrets:
                scrubbed = scan_res.sanitized_text
        except Exception as exc:
            logger.error("Error running SecretScanner in SecretBroker.scrub_text: %s", exc)

        return scrubbed

    def scrub_data(self, data: Any) -> Any:
        """Recursively scrubs strings within dicts, lists, or primitive values."""
        if isinstance(data, str):
            return self.scrub_text(data)
        elif isinstance(data, dict):
            return {k: self.scrub_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.scrub_data(item) for item in data]
        return data

    def contains_secret(self, text: str) -> bool:
        """Returns True if any known vault secret or scanned credential is in text."""
        if not text:
            return False
        with self._lock:
            for sec_val in self._secrets.values():
                if sec_val and len(sec_val) >= 6 and sec_val in text:
                    return True
        scan_res = self._secret_scanner.scan(text)
        return scan_res.has_secrets

    @staticmethod
    def mask_secret(secret_val: str) -> str:
        """Produces a safe preview string (e.g. sk-****1234 or ****)."""
        if not secret_val:
            return ""
        if len(secret_val) <= 6:
            return "****"
        prefix = secret_val[:3]
        suffix = secret_val[-4:]
        return f"{prefix}****{suffix}"

    def clear(self) -> None:
        """Clears vault (for test teardowns)."""
        with self._lock:
            self._secrets.clear()
