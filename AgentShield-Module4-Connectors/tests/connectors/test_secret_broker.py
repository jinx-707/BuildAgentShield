"""
Unit & Security Tests for AgentShield Secret Broker.
Tests:
  - Secure credential storage and retrieval
  - Header and query parameter authentication injection
  - Zero-leakage guarantees (scrubbing secrets from text & structures)
  - Safe preview masking
  - Environment variable fallback
"""

import os
import pytest

from core.connectors.models import AuthenticationConfig, AuthType
from core.connectors.secret_broker import SecretBroker
from core.secret_scanner import SecretScanner


@pytest.fixture
def broker():
    return SecretBroker(secret_scanner=SecretScanner())


def test_secret_store_and_retrieve(broker):
    """Stored secrets can be retrieved by internal transport only."""
    broker.store_secret("prod_github_pat", "ghp_111122223333444455556666777788889999")
    val = broker.get_secret("prod_github_pat")
    assert val == "ghp_111122223333444455556666777788889999"


def test_env_fallback(broker, monkeypatch):
    """Fallback to environment variables when secret not in vault."""
    monkeypatch.setenv("AGENTSHIELD_SECRET_STRIPE_KEY", "sk_live_abcdef1234567890")
    val = broker.get_secret("stripe_key")
    assert val == "sk_live_abcdef1234567890"


def test_inject_bearer_auth(broker):
    """Bearer token correctly injected into Authorization header."""
    broker.store_secret("jwt_sec", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token.sig")
    auth_cfg = AuthenticationConfig(
        auth_type=AuthType.BEARER_TOKEN,
        secret_id="jwt_sec",
    )
    headers, params = broker.inject_auth(auth_cfg, headers={"Accept": "application/json"})
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Bearer eyJ")
    assert params == {}


def test_inject_api_key_query_param(broker):
    """API key correctly injected into query parameters."""
    broker.store_secret("weather_key", "secret_weather_token_999")
    auth_cfg = AuthenticationConfig(
        auth_type=AuthType.API_KEY,
        secret_id="weather_key",
        query_param_name="api_key",
    )
    headers, params = broker.inject_auth(auth_cfg, headers={}, query_params={"city": "NYC"})
    assert params["api_key"] == "secret_weather_token_999"
    assert params["city"] == "NYC"


def test_inject_basic_auth(broker):
    """Basic auth encodes username:password to base64."""
    broker.store_secret("basic_sec", "admin:SecretPass!")
    auth_cfg = AuthenticationConfig(
        auth_type=AuthType.BASIC,
        secret_id="basic_sec",
    )
    headers, _ = broker.inject_auth(auth_cfg, headers={})
    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Basic ")


def test_scrub_stored_secret_from_text(broker):
    """Any occurrence of a stored secret in text is strictly redacted."""
    raw_secret = "super_classified_api_token_456"
    broker.store_secret("my_token", raw_secret)

    leak_text = f"Warning: Connection established using {raw_secret} for session."
    clean = broker.scrub_text(leak_text)

    assert raw_secret not in clean
    assert "[REDACTED_CREDENTIAL]" in clean


def test_scrub_nested_data(broker):
    """Recursively scrubs secret strings within nested dictionaries and lists."""
    secret = "ghp_999988887777666655554444333322221111"
    broker.store_secret("gh_token", secret)

    payload = {
        "status": "success",
        "debug_info": {
            "auth_used": secret,
            "tokens": [secret, "public_user"],
        },
    }
    cleaned = broker.scrub_data(payload)

    assert secret not in str(cleaned)
    assert cleaned["debug_info"]["tokens"][1] == "public_user"


def test_mask_preview():
    """Safe previews display prefix and suffix with masked core."""
    preview = SecretBroker.mask_secret("sk-1234567890abcdef")
    assert preview == "sk-****cdef"
    assert "1234567890" not in preview
