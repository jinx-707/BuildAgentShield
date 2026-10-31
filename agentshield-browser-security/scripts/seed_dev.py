"""Idempotent development seed for the AgentShield dashboard.

Creates an owner account, organization, an initial browser agent, and a default
egress policy that blocks a documentation-only destination used by the
integration walkthrough. Run from the repository root:

    DATABASE_URL=... PYTHONPATH=api .venv/bin/python scripts/seed_dev.py

The script never deletes or overwrites existing users, organizations, agents,
or policies.
"""

from __future__ import annotations

import os
import sys

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.base import init_db, get_db_session
from app.db.models import Agent, Organization, OrganizationUser, Policy, User
from app.enterprise.auth import (
    create_organization,
    create_user,
    hash_password,
    verify_password,
)


DEFAULT_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@agentshield.dev")
DEFAULT_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin-change-me")
DEFAULT_ORG_NAME = os.environ.get("ADMIN_ORG_NAME", "Acme Security")
DEFAULT_ORG_SLUG = os.environ.get("ADMIN_ORG_SLUG", "acme")
DEFAULT_AGENT = os.environ.get("ADMIN_AGENT_NAME", "dashboard-agent")


def seed(db: Session) -> None:
    user = db.query(User).filter(User.email == DEFAULT_EMAIL).first()
    if user is None:
        user = create_user(
            db,
            email=DEFAULT_EMAIL,
            password=DEFAULT_PASSWORD,
            full_name="AgentShield Administrator",
        )
        print(f"created user {DEFAULT_EMAIL}")
    else:
        # Reconcile the development admin account in place. Never delete or
        # overwrite other users, and never touch database records unrelated to
        # this admin email. Only the password hash and active flag are updated
        # so the advertised development credential keeps working even if the
        # row was previously created with a stale password or deactivated.
        needs_update = False
        current_hash = user.password_hash
        if not current_hash or not verify_password(DEFAULT_PASSWORD, current_hash):
            user.password_hash = hash_password(DEFAULT_PASSWORD)
            needs_update = True
        if not user.is_active:
            user.is_active = True
            needs_update = True
        if needs_update:
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"reconciled user {DEFAULT_EMAIL}")
        else:
            print(f"user {DEFAULT_EMAIL} already exists")

    org = db.query(Organization).filter(Organization.slug == DEFAULT_ORG_SLUG).first()
    if org is None:
        org = create_organization(
            db,
            name=DEFAULT_ORG_NAME,
            slug=DEFAULT_ORG_SLUG,
            owner_user_id=user.id,
        )
        print(f"created organization {DEFAULT_ORG_SLUG}")
    else:
        print(f"organization {DEFAULT_ORG_SLUG} already exists")
        membership = (
            db.query(OrganizationUser)
            .filter(
                OrganizationUser.organization_id == org.id,
                OrganizationUser.user_id == user.id,
            )
            .first()
        )
        if membership is None:
            db.add(
                OrganizationUser(
                    organization_id=org.id,
                    user_id=user.id,
                    role="owner",
                )
            )
            db.commit()

    agent = (
        db.query(Agent)
        .filter(
            Agent.organization_id == org.id,
            Agent.name == DEFAULT_AGENT,
        )
        .first()
    )
    if agent is None:
        agent = Agent(
            organization_id=org.id,
            agent_id=f"agent-{os.urandom(6).hex()}",
            name=DEFAULT_AGENT,
            status="active",
        )
        db.add(agent)
        db.commit()
        print(f"created agent {agent.agent_id}")
    else:
        print(f"agent {agent.agent_id} already exists")

    policy = (
        db.query(Policy)
        .filter(
            Policy.organization_id == org.id,
            Policy.name == "Default browser egress",
        )
        .first()
    )
    if policy is None:
        policy = Policy(
            organization_id=org.id,
            name="Default browser egress",
            description=(
                "Fail-closed browser egress baseline. permits example.com and "
                "blocks the reserved integration test destination."
            ),
            allowed_domains=["example.com"],
            blocked_domains=["blocked.example", "metadata.example"],
            default_domain_policy="deny",
            allowed_ports=["80", "443"],
            allow_private_networks=False,
            is_active=True,
            is_default=True,
            created_by_user_id=user.id,
        )
        db.add(policy)
        db.commit()
        print("created default browser egress policy")
    else:
        print("default browser egress policy already exists")

    print("seed complete")
    print(f"email: {DEFAULT_EMAIL}")
    print(f"organization: {org.id} ({org.slug})")
    print(f"agent: {agent.agent_id}")


def main() -> int:
    settings = get_settings()
    if not settings.database_url:
        print("DATABASE_URL is required", file=sys.stderr)
        return 1
    init_db(settings)
    db = get_db_session()
    try:
        seed(db)
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
