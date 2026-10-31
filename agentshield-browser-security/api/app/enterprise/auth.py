"""Enterprise authentication service for AgentShield.

Handles password hashing, JWT token issuance, login/logout, and API key
management. Organization-scoped: every authenticated principal is bound to
one or more organizations through membership records.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.db.models import (
    User,
    OrganizationUser,
    Organization,
    Agent,
    APIKey,
)
from app.db.base import get_db_session

JWT_SECRET = "agentshield-dev-secret-change-in-production"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def create_access_token(
    subject: str,
    *,
    organization_id: Optional[str] = None,
    roles: Optional[list[str]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    to_encode = {"sub": subject}
    if organization_id:
        to_encode["org"] = organization_id
    if roles:
        to_encode["roles"] = roles
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None


def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.password_hash:
        return None
    if not verify_password(password, user.password_hash):
        return None
    if not user.is_active:
        return None
    return user


def create_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: Optional[str] = None,
) -> User:
    if db.query(User).filter(User.email == email).first():
        raise ValueError("user with this email already exists")
    user = User(
        email=email,
        password_hash=hash_password(password),
        full_name=full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_organization(
    db: Session, *, name: str, slug: str, owner_user_id: str
) -> Organization:
    if db.query(Organization).filter(Organization.slug == slug).first():
        raise ValueError("organization with this slug already exists")
    org = Organization(name=name, slug=slug)
    db.add(org)
    db.commit()
    db.refresh(org)

    membership = OrganizationUser(
        organization_id=org.id,
        user_id=owner_user_id,
        role="owner",
    )
    db.add(membership)
    db.commit()
    return org


def get_user_organizations(db: Session, user_id: str) -> list[OrganizationUser]:
    return (
        db.query(OrganizationUser)
        .filter(OrganizationUser.user_id == user_id, OrganizationUser.is_active == True)  # noqa: E712
        .all()
    )


def create_agent(
    db: Session,
    *,
    organization_id: str,
    name: str,
    created_by_user_id: Optional[str] = None,
) -> Agent:
    agent_id = f"agent-{uuid.uuid4().hex[:16]}"
    raw_secret = f"ash_{uuid.uuid4().hex}"
    credentials_hash = hash_password(raw_secret)

    agent = Agent(
        organization_id=organization_id,
        name=name,
        agent_id=agent_id,
        credentials_hash=credentials_hash,
        created_by_user_id=created_by_user_id,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    # Return the raw secret once - it is never stored plaintext
    agent._raw_secret = raw_secret  # type: ignore[attr-defined]
    return agent


def verify_agent_credentials(db: Session, agent_id: str, secret: str) -> Optional[Agent]:
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent or not agent.credentials_hash:
        return None
    if not verify_password(secret, agent.credentials_hash):
        return None
    if agent.status != "active":
        return None
    return agent


def create_api_key(
    db: Session,
    *,
    organization_id: str,
    user_id: str,
    name: str,
    expires_in_days: Optional[int] = None,
) -> tuple[APIKey, str]:
    raw_key = f"ash_sk_{uuid.uuid4().hex}"
    key_hash = hash_password(raw_key)
    key_prefix = raw_key[:12]

    expires_at = None
    if expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

    api_key = APIKey(
        organization_id=organization_id,
        user_id=user_id,
        name=name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        expires_at=expires_at,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    return api_key, raw_key


def verify_api_key(db: Session, key: str) -> Optional[APIKey]:
    prefix = key[:12]
    api_key = (
        db.query(APIKey)
        .filter(APIKey.key_prefix == prefix, APIKey.is_active == True)  # noqa: E712
        .first()
    )
    if not api_key:
        return None
    if not verify_password(key, api_key.key_hash):
        return None
    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        return None
    return api_key
