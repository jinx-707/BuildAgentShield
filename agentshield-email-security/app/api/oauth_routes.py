"""OAuth 2.0 routes for Google authentication and account lifecycle management."""

from datetime import datetime, timedelta, timezone
import logging
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import get_settings
from app.database.repository import AuditRepository, OAuthAccountRepository, OAuthStateRepository
from app.database.session import get_db
from app.middleware.authentication import get_security_context
from app.providers.gmail.oauth import GoogleOAuthHandler
from app.schemas.security import SecurityContext

logger = logging.getLogger("agentshield.api.oauth")

router = APIRouter(prefix="/online/email/oauth", tags=["OAuth"])


@router.get(
    "/google/start",
    status_code=status.HTTP_200_OK,
    summary="Initiate Google OAuth Flow",
    description="Generates CSRF state token and Google consent URL with least-privilege scopes.",
)
async def google_oauth_start(
    scopes: Optional[str] = Query(
        default=None,
        description="Comma-separated OAuth scopes to request (defaults to read-only)",
    ),
    context: SecurityContext = Depends(get_security_context),
    db: AsyncSession = Depends(get_db),
):
    settings = get_settings()
    oauth_handler = GoogleOAuthHandler()

    # Determine requested scopes
    requested_scopes: List[str]
    if scopes:
        requested_scopes = [s.strip() for s in scopes.split(",") if s.strip()]
    else:
        requested_scopes = list(settings.DEFAULT_OAUTH_SCOPES)

    # Validate against allowed scopes list
    allowed_set = set(settings.ALLOWED_OAUTH_SCOPES)
    disallowed = [s for s in requested_scopes if s not in allowed_set]
    if disallowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Requested scopes not allowed by security policy: {disallowed}",
        )

    # Generate cryptographically secure state token
    state_token = oauth_handler.generate_state_token(context.tenant_id, context.agent_id)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Persist state token
    state_repo = OAuthStateRepository(db)
    await state_repo.create_state(
        state_token=state_token,
        tenant_id=context.tenant_id,
        agent_id=context.agent_id,
        provider="google",
        requested_scopes=requested_scopes,
        redirect_uri=settings.GOOGLE_REDIRECT_URI,
        expires_at=expires_at,
    )

    auth_url = oauth_handler.get_authorization_url(
        state_token=state_token, scopes=requested_scopes
    )

    audit_repo = AuditRepository(db)
    await audit_repo.record_audit_event(
        tenant_id=context.tenant_id,
        agent_id=context.agent_id,
        event_type="OAUTH_INITIATED",
        status="ALLOWED",
        metadata={"scopes": requested_scopes, "provider": "google"},
    )

    return {
        "authorization_url": auth_url,
        "state": state_token,
        "expires_in_seconds": 600,
        "scopes": requested_scopes,
    }


@router.get(
    "/google/callback",
    status_code=status.HTTP_200_OK,
    summary="Google OAuth Callback Handler",
    description="Validates CSRF state, exchanges authorization code, encrypts tokens, and registers account.",
)
async def google_oauth_callback(
    code: Optional[str] = Query(default=None, description="Google OAuth authorization code"),
    state: Optional[str] = Query(default=None, description="CSRF state token"),
    error: Optional[str] = Query(default=None, description="Error reported by provider"),
    db: AsyncSession = Depends(get_db),
):
    if error:
        logger.error(f"OAuth authorization failed at provider: {error}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth authorization failed with provider: {error}",
        )

    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required 'code' or 'state' query parameters",
        )

    # 1. Validate and consume CSRF state token
    state_repo = OAuthStateRepository(db)
    state_record = await state_repo.validate_and_consume_state(state)
    if not state_record:
        logger.warning(f"Invalid, expired, or reused OAuth state token: {state}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid, expired, or reused CSRF state token. Authorization aborted.",
        )

    oauth_handler = GoogleOAuthHandler()

    # 2. Exchange code for access & refresh tokens
    try:
        token_data = await oauth_handler.exchange_code_for_tokens(code)
    except Exception as e:
        logger.error(f"Google token exchange failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Provider token exchange error: {str(e)}",
        )

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in", 3600)
    token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    granted_scopes_raw = token_data.get("scope", "")
    granted_scopes = [s for s in granted_scopes_raw.split() if s] or state_record.requested_scopes

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Provider response did not contain access_token",
        )

    # 3. Fetch user email identity
    try:
        user_info = await oauth_handler.get_user_profile(access_token)
        account_email = user_info.get("email")
        if not account_email:
            raise ValueError("No email found in user profile")
    except Exception as e:
        logger.error(f"Failed to retrieve user profile for token: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to retrieve user identity from provider",
        )

    # 4. Securely store account with encrypted tokens
    account_repo = OAuthAccountRepository(db)
    account = await account_repo.create_or_update_account(
        tenant_id=state_record.tenant_id,
        agent_id=state_record.agent_id,
        provider="google",
        account_email=account_email,
        access_token=access_token,
        refresh_token=refresh_token,
        token_expiry=token_expiry,
        granted_scopes=granted_scopes,
    )

    audit_repo = AuditRepository(db)
    await audit_repo.record_audit_event(
        tenant_id=state_record.tenant_id,
        agent_id=state_record.agent_id,
        event_type="OAUTH_CONNECTED",
        status="ALLOWED",
        metadata={
            "account_id": str(account.id),
            "account_email": account_email,
            "provider": "google",
            "granted_scopes": granted_scopes,
        },
        account_id=account.id,
    )

    # Return safe metadata only: Never expose raw tokens to caller
    return {
        "status": "success",
        "account_id": account.id,
        "email": account.account_email,
        "provider": "google",
        "granted_scopes": granted_scopes,
        "created_at": account.created_at,
    }


@router.post(
    "/accounts/{account_id}/revoke",
    status_code=status.HTTP_200_OK,
    summary="Revoke OAuth Account",
    description="Revokes credentials with Google and disables local account integration.",
)
async def revoke_account_access(
    account_id: UUID,
    context: SecurityContext = Depends(get_security_context),
    db: AsyncSession = Depends(get_db),
):
    account_repo = OAuthAccountRepository(db)
    account = await account_repo.get_account(account_id, context.tenant_id, context.agent_id)
    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found or inaccessible",
        )

    access_token, _ = account_repo.get_decrypted_tokens(account)
    oauth_handler = GoogleOAuthHandler()
    await oauth_handler.revoke_token(access_token)

    await account_repo.revoke_account(account_id, context.tenant_id, context.agent_id)

    audit_repo = AuditRepository(db)
    await audit_repo.record_audit_event(
        tenant_id=context.tenant_id,
        agent_id=context.agent_id,
        event_type="OAUTH_REVOKED",
        status="ALLOWED",
        metadata={"account_id": str(account_id), "email": account.account_email},
        account_id=account_id,
    )

    return {"status": "revoked", "account_id": account_id}

