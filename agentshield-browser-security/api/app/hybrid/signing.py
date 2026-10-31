"""Policy package signing and verification.

Every policy package is HMAC-SHA256 signed using the deployment-specific
secret.  Data planes MUST verify the signature before applying any policy
update.  Packages with invalid signatures are rejected and the last known-good
policy is retained.

Canonical payload format (UTF-8):
    {version_id}|{deployment_id}|{created_at_iso}|{sequence_number}|{spec_json}

where:
    - created_at_iso is ISO-8601 UTC with millisecond precision
    - spec_json is canonical JSON (keys sorted, no extra whitespace)
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timezone

from app.hybrid.models import PolicyPackage, PolicySpec


_SEPARATOR = "|"


def _canonical_spec_json(spec: PolicySpec) -> str:
    """Return deterministic JSON for the policy spec."""
    return json.dumps(spec.model_dump(), sort_keys=True, separators=(",", ":"))


def _canonical_payload(package: PolicyPackage) -> bytes:
    """Return the byte string that is signed."""
    created_iso = package.created_at.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    ) + "Z"
    parts = [
        package.version_id,
        package.deployment_id,
        created_iso,
        str(package.sequence_number),
        _canonical_spec_json(package.spec),
    ]
    return _SEPARATOR.join(parts).encode("utf-8")


def sign_package(package: PolicyPackage, deployment_secret: str) -> str:
    """Compute and return the hex HMAC-SHA256 signature for a policy package."""
    payload = _canonical_payload(package)
    return hmac.new(
        deployment_secret.encode("utf-8"),
        payload,
        digestmod=hashlib.sha256,
    ).hexdigest()


def verify_package(package: PolicyPackage, deployment_secret: str) -> bool:
    """Return True if the package signature is valid.

    Uses a constant-time comparison to prevent timing attacks.
    Returns False for any invalid or malformed signature — never raises.
    """
    try:
        expected = sign_package(package, deployment_secret)
        return hmac.compare_digest(expected, package.signature)
    except Exception:
        return False
