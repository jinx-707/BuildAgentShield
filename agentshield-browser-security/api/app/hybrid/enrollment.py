"""Control-plane enrollment service.

Handles data-plane registration and enrollment token lifecycle.
Each customer data plane registers once, receiving a long-lived deployment
credential used for all subsequent control-channel communication.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.db.models import Deployment
from app.hybrid.models import (
    DeploymentProfile,
    DeploymentStatus,
    EnrollmentRequest,
    EnrollmentResponse,
    PolicyPackage,
    PolicySpec,
)
from app.hybrid.signing import sign_package

# Enrollment tokens expire after 24 hours if unused.
ENROLLMENT_TOKEN_TTL_HOURS = 24
# Deployment secret length: 32 random bytes → 64 hex chars.
DEPLOYMENT_SECRET_BYTES = 32


def generate_enrollment_token() -> str:
    """Return a secure enrollment token suitable for distributing to operators."""
    return secrets.token_urlsafe(48)  # 64-char URL-safe string


def enroll_deployment(
    db: Session,
    org_id: str,
    req: EnrollmentRequest,
) -> EnrollmentResponse:
    """Register a new data-plane deployment and return its credentials.

    Raises ValueError for invalid/expired/already-used tokens.
    """
    # Verify the enrollment token against the org's pending deployments.
    deployment = (
        db.query(Deployment)
        .filter(
            Deployment.organization_id == org_id,
            Deployment.enrollment_token_hash == _hash_token(req.enrollment_token),
            Deployment.status == DeploymentStatus.PENDING_ENROLLMENT.value,
        )
        .first()
    )
    if not deployment:
        raise ValueError("invalid or already-used enrollment token")

    if deployment.enrollment_token_expires_at:
        if datetime.now(timezone.utc) > deployment.enrollment_token_expires_at:
            raise ValueError("enrollment token has expired")

    # Issue a long-lived deployment secret.
    raw_secret = secrets.token_hex(DEPLOYMENT_SECRET_BYTES)
    secret_hash = _hash_token(raw_secret)

    deployment.status = DeploymentStatus.ACTIVE.value
    deployment.deployment_secret_hash = secret_hash
    deployment.name = req.deployment_name
    deployment.profile = req.profile.value
    deployment.location_label = req.location_label
    deployment.data_plane_version = req.data_plane_version
    deployment.enrolled_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(deployment)

    # Build a bootstrap policy package for the data plane.
    initial_policy = _build_initial_policy(
        deployment_id=deployment.deployment_id,
        deployment_secret=raw_secret,
    )

    return EnrollmentResponse(
        deployment_id=deployment.deployment_id,
        deployment_secret=raw_secret,
        initial_policy=initial_policy,
        control_plane_url=deployment.control_plane_url or "",
    )


def create_pending_deployment(
    db: Session,
    org_id: str,
    *,
    name: str,
    profile: DeploymentProfile = DeploymentProfile.HYBRID,
    control_plane_url: str,
) -> tuple[Deployment, str]:
    """Create a pending deployment record and return it with a one-time token.

    Call this from the control-plane UI when an operator provisions a new
    customer data plane.  The enrollment token is returned once and never
    stored in plain text.
    """
    token = generate_enrollment_token()
    token_hash = _hash_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=ENROLLMENT_TOKEN_TTL_HOURS)

    deployment = Deployment(
        organization_id=org_id,
        deployment_id=f"dp-{uuid.uuid4().hex[:16]}",
        name=name,
        profile=profile.value,
        status=DeploymentStatus.PENDING_ENROLLMENT.value,
        enrollment_token_hash=token_hash,
        enrollment_token_expires_at=expires_at,
        control_plane_url=control_plane_url,
    )
    db.add(deployment)
    db.commit()
    db.refresh(deployment)
    return deployment, token


def verify_deployment_request(
    deployment_id: str,
    deployment_secret_hash: str,
    request_timestamp_ms: int,
    request_path: str,
    signature_header: str,
    raw_secret: str,
) -> bool:
    """Verify a signed data-plane request.

    Returns True only when:
    1. The secret hash matches the stored hash.
    2. The HMAC signature is valid.
    3. The request timestamp is within 5 minutes (replay protection).
    """
    import time

    # Time window: ±5 minutes to tolerate clock skew.
    now_ms = int(time.time() * 1000)
    if abs(now_ms - request_timestamp_ms) > 5 * 60 * 1000:
        return False

    # Verify secret hash
    if not hmac.compare_digest(
        _hash_token(raw_secret), deployment_secret_hash
    ):
        return False

    # Verify HMAC
    expected_prefix = "hmac-sha256="
    if not signature_header.startswith(expected_prefix):
        return False
    received_sig = signature_header[len(expected_prefix):]
    payload = f"{deployment_id}|{request_timestamp_ms}|{request_path}".encode("utf-8")
    expected_sig = hmac.new(
        raw_secret.encode("utf-8"),
        payload,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)


def _hash_token(token: str) -> str:
    """Return SHA-256 hex digest of a token (safe to store in the database)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _build_initial_policy(
    deployment_id: str,
    deployment_secret: str,
) -> PolicyPackage:
    """Return a minimal bootstrap policy package for a freshly enrolled data plane."""
    import time

    spec = PolicySpec(
        allowed_domains=[],
        blocked_domains=[],
        default_domain_policy="deny",
        allow_private_networks=False,
        dlp_enabled=True,
        threat_detection_enabled=True,
    )
    pkg = PolicyPackage(
        version_id=f"bootstrap-{int(time.time())}",
        deployment_id=deployment_id,
        spec=spec,
        signature="",  # will be replaced below
        sequence_number=1,
        valid_until=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    pkg.signature = sign_package(pkg, deployment_secret)
    return pkg
