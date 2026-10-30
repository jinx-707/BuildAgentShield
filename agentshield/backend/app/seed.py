from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .approvals import find_or_create_approval
from .audit import AuditService
from .config import Settings
from .contracts import Decision, Provenance, ToolRequest, TrustLevel
from .db import Agent, Database, Policy, Tenant, User
from .registry import DEFAULT_AGENT_PERMISSIONS
from .security import hash_password


AGENT_SEEDS = [
    (
        "research-agent",
        "Readonly researcher",
        "Active",
        ["documents.read", "local_files.read", "browser.read", "dlp.export"],
        {
            "allowed_paths": ["workspace/research", "/workspace/research"],
            "allowed_domains": ["acme.example", "docs.example"],
        },
    ),
    (
        "dev-assistant",
        "Developer agent",
        "Active",
        ["documents.read", "local_files.read", "terminal.run", "files.delete"],
        {
            "allowed_paths": ["workspace", "workspace/build/archive", "/workspace"],
            "allowed_domains": ["acme.example", "docs.example"],
        },
    ),
    (
        "email-assistant",
        "Email assistant",
        "Active",
        ["documents.read", "email.send", "browser.read"],
        {
            "allowed_paths": ["workspace/research", "/workspace/research"],
            "allowed_domains": ["acme.example", "example.test"],
        },
    ),
    (
        "shopping-agent",
        "Shopping agent",
        "Active",
        ["payments.execute", "browser.read"],
        {
            "allowed_domains": ["acme.example", "shop.example"],
            "allowed_merchants": ["Acme Software"],
            "payment_budget": 500,
        },
    ),
    (
        "data-analyst",
        "Custom",
        "Active",
        ["documents.read", "dlp.export", "local_files.read"],
        {
            "allowed_paths": ["workspace/data", "/workspace/data"],
            "allowed_domains": ["acme.example"],
        },
    ),
    (
        "browser-agent",
        "Readonly researcher",
        "Disabled",
        ["browser.read", "downloads.write"],
        {"allowed_domains": ["acme.example", "docs.example"]},
    ),
    (
        "simulator-agent",
        "Attack simulator",
        "Active",
        [
            "documents.read",
            "local_files.read",
            "system_files.read",
            "environment.read",
            "terminal.run",
            "files.delete",
            "browser.read",
            "email.send",
            "dlp.export",
            "downloads.write",
            "payments.execute",
            "external_api.call",
            "mcp.call",
        ],
        {
            "allowed_paths": ["workspace", "/workspace"],
            "allowed_domains": ["acme.example", "example.test"],
            "allowed_merchants": ["Acme Software"],
            "payment_budget": 500,
        },
    ),
]

POLICY_SEEDS = [
    (
        "pol_001",
        "Protected resource access",
        "Block access to system files, SSH keys, and environment secrets.",
        "Resource protection",
        "DENY when resource matches /.ssh/*, /etc/*, **/.env",
        3,
        True,
    ),
    (
        "pol_002",
        "Outbound data protection",
        "Inspect egress traffic and redact personally identifiable information.",
        "Data loss prevention",
        "REDACT when egress = true and data_classification = sensitive",
        2,
        True,
    ),
    (
        "pol_003",
        "Human approval for sensitive actions",
        "Require approval before email, payments, and destructive operations.",
        "Human oversight",
        "REQUIRE_APPROVAL for send_email, delete_file, run_command, initiate_payment",
        4,
        True,
    ),
    (
        "pol_004",
        "Payment budget guardrails",
        "Limit transactions to the agent budget and approved merchants only.",
        "Financial safety",
        "DENY when amount > budget or merchant not in merchant_allowlist",
        2,
        True,
    ),
    (
        "pol_005",
        "Untrusted content isolation",
        "Prevent external content from escalating privileges or invoking tools.",
        "Prompt injection",
        "QUARANTINE when provenance.trust = untrusted and injection = true",
        1,
        True,
    ),
]

AUDIT_SEEDS = [
    ("research-agent", "read_env_var", "Attempted access to a protected environment variable", "DENY", 96, "critical"),
    ("email-assistant", "send_email", "Outbound email contains personally identifiable information", "REQUIRE_APPROVAL", 72, "high"),
    ("dev-assistant", "run_command", "Potentially destructive terminal command detected", "DENY", 94, "critical"),
    ("research-agent", "browse_url", "Prompt injection detected in external webpage content", "QUARANTINE", 88, "critical"),
    ("shopping-agent", "initiate_payment", "Payment exceeds the configured transaction limit", "DENY", 85, "critical"),
    ("data-analyst", "export_data", "Sensitive fields removed from exported report", "REDACT", 54, "high"),
    ("research-agent", "read_document", "Read an approved workspace document", "ALLOW", 12, "low"),
    ("dev-assistant", "read_file", "Read a file within the authorized project scope", "ALLOW", 8, "low"),
]

APPROVAL_SEEDS = [
    (
        "email-assistant",
        "send_email",
        {
            "to": "finance@acme.example",
            "subject": "Q3 financial report",
            "attachment": "quarterly-report.pdf",
            "body": "Please find the Q3 report attached.",
        },
        72,
    ),
    (
        "dev-assistant",
        "delete_file",
        {"path": "workspace/build/archive", "recursive": True},
        64,
    ),
    (
        "shopping-agent",
        "initiate_payment",
        {"merchant": "Acme Software", "amount": 149, "currency": "USD"},
        58,
    ),
    (
        "data-analyst",
        "export_data",
        {"document": "research-summary.csv", "destination": "approved-storage", "format": "csv"},
        48,
    ),
]


async def seed_database(
    database: Database, settings: Settings, audit: AuditService
) -> None:
    async with database.session() as session:
        tenant = await session.scalar(
            select(Tenant).where(Tenant.slug == settings.admin_tenant_slug)
        )
        created = tenant is None
        if tenant is None:
            tenant = Tenant(slug=settings.admin_tenant_slug, name=settings.admin_tenant_name)
            session.add(tenant)
            await session.flush()

        user = await session.scalar(
            select(User).where(
                User.tenant_id == tenant.id,
                User.email == settings.admin_email,
            )
        )
        if user is None:
            session.add(
                User(
                    tenant_id=tenant.id,
                    email=settings.admin_email,
                    password_hash=hash_password(settings.admin_password),
                    role="admin",
                )
            )

        await _ensure_policies(session, tenant.id)

        if created and settings.seed_demo_data:
            agents = await _seed_agents(session, tenant.id)
            await _seed_approvals(session, settings, tenant.id, agents)
            await _seed_audit(session, audit, tenant.id, agents)
        await session.commit()


async def _ensure_policies(session: AsyncSession, tenant_id: str) -> None:
    existing = {
        policy.key
        for policy in (
            await session.scalars(select(Policy).where(Policy.tenant_id == tenant_id))
        ).all()
    }
    for key, name, description, category, rule, version, active in POLICY_SEEDS:
        if key in existing:
            continue
        session.add(
            Policy(
                tenant_id=tenant_id,
                key=key,
                name=name,
                description=description,
                category=category,
                rule=rule,
                version=version,
                active=active,
                immutable=True,
            )
        )
    await session.flush()


async def _seed_agents(session: AsyncSession, tenant_id: str) -> dict[str, Agent]:
    agents: dict[str, Agent] = {}
    for name, role, status, permissions, scopes in AGENT_SEEDS:
        agent = Agent(
            tenant_id=tenant_id,
            name=name,
            role=role,
            status=status,
            permissions=permissions,
            scopes=scopes,
            request_count=0,
        )
        session.add(agent)
        agents[name] = agent
    await session.flush()
    return agents


async def _seed_approvals(
    session: AsyncSession,
    settings: Settings,
    tenant_id: str,
    agents: dict[str, Agent],
) -> None:
    for agent_name, tool_name, arguments, risk in APPROVAL_SEEDS:
        agent = agents[agent_name]
        request = ToolRequest(
            request_id=f"seed_{uuid.uuid4().hex[:16]}",
            tool_name=tool_name,
            arguments=arguments,
            provenance=Provenance(
                source="seed",
                trust=TrustLevel.TRUSTED,
                data_classification="internal",
            ),
            reason="Seeded dashboard approval",
        )
        await find_or_create_approval(
            session,
            settings,
            tenant_id=tenant_id,
            agent_id=agent.id,
            request=request,
            risk_score=risk,
            reason="Seeded request awaiting human review.",
        )


async def _seed_audit(
    session: AsyncSession,
    audit: AuditService,
    tenant_id: str,
    agents: dict[str, Agent],
) -> None:
    for agent_name, tool, summary, decision, risk, risk_level in AUDIT_SEEDS:
        agent = agents[agent_name]
        await audit.append(
            session,
            tenant_id=tenant_id,
            actor_type="agent",
            actor_id=agent.id,
            action="seed.event",
            decision=decision,
            risk_score=risk,
            risk_level=risk_level,
            tool_name=tool,
            request_id=f"seed_{uuid.uuid4().hex[:16]}",
            details={
                "summary": summary,
                "agent_name": agent.name,
                "seeded": True,
                "policy_id": "seed",
            },
        )
