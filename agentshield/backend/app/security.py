from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timezone
from typing import Any

import bcrypt
import jwt

from .config import Settings

SECRET_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential)"
)
EMAIL_PATTERN = re.compile(r"([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
PHONE_PATTERN = re.compile(r"(?<!\d)(\+?\d[\d -]{7,}\d)(?!\d)")


def hash_password(password: str) -> str:
    if len(password.encode("utf-8")) > 72:
        raise ValueError("password exceeds bcrypt limit")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_user_token(
    settings: Settings,
    *,
    user_id: str,
    tenant_id: str,
    role: str,
    email: str,
) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    expires = int(settings.jwt_ttl_minutes * 60)
    payload = {
        "sub": user_id,
        "tid": tenant_id,
        "role": role,
        "email": email,
        "type": "dashboard",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + expires,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")
    return token, expires


def decode_user_token(settings: Settings, token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=["HS256"],
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        options={"require": ["exp", "sub", "tid", "role", "type"]},
    )


def generate_agent_key(settings: Settings) -> tuple[str, str, str]:
    prefix = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    full_key = f"ash_{prefix}_{secret}"
    return full_key, prefix, hash_api_key(settings, full_key)


def hash_api_key(settings: Settings, key: str) -> str:
    return hashlib.sha256(f"{settings.api_key_pepper}:{key}".encode("utf-8")).hexdigest()


def verify_api_key(settings: Settings, key: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(settings, key), expected_hash)


def parse_agent_key(key: str) -> str | None:
    parts = key.split("_", 2)
    if len(parts) != 3 or parts[0] != "ash" or len(parts[1]) != 12:
        return None
    return parts[1]


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign_approval_token(
    settings: Settings,
    *,
    approval_id: str,
    action_hash: str,
    nonce: str,
    expires_at: datetime,
) -> str:
    payload = {
        "approval_id": approval_id,
        "action_hash": action_hash,
        "nonce": nonce,
        "exp": int(expires_at.timestamp()),
    }
    encoded = _b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature = hmac.new(
        settings.approval_signing_secret.encode("utf-8"),
        encoded.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{encoded}.{_b64encode(signature)}"


def verify_approval_token(settings: Settings, token: str) -> dict[str, Any]:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(
            settings.approval_signing_secret.encode("utf-8"),
            encoded.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(_b64decode(signature), expected):
            raise ValueError("invalid approval signature")
        payload = json.loads(_b64decode(encoded))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid approval token") from exc
    required = {"approval_id", "action_hash", "nonce", "exp"}
    if not isinstance(payload, dict) or not required.issubset(payload):
        raise ValueError("invalid approval token payload")
    if datetime.now(timezone.utc).timestamp() > int(payload["exp"]):
        raise ValueError("approval token expired")
    return payload


def sanitize_value(key: str, value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "[TRUNCATED]"
    if SECRET_KEY_PATTERN.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): sanitize_value(str(k), v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(str(key), item, depth + 1) for item in value[:50]]
    if isinstance(value, str):
        masked = EMAIL_PATTERN.sub(r"\1***\2", value)
        masked = PHONE_PATTERN.sub("[PHONE]", masked)
        if len(masked) > 500:
            masked = f"{masked[:497]}..."
        return masked
    return value


def sanitize_dict(value: dict[str, Any]) -> dict[str, Any]:
    return sanitize_value("root", value)


def hash_event(prev_hash: str, payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{prev_hash}:{body}".encode("utf-8")).hexdigest()


def preview(value: Any, limit: int = 500) -> str:
    sanitized = sanitize_value("preview", value)
    text = json.dumps(sanitized, sort_keys=True, default=str)
    return text[:limit]
