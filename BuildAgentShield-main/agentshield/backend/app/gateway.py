from __future__ import annotations

import asyncio
import hashlib
from collections import defaultdict
from datetime import timedelta
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .adapters import AdapterError
from .approvals import (
    approval_expired,
    approval_summary,
    ensure_aware,
    find_or_create_approval,
)
from .audit import AuditService
from .config import Settings
from .contracts import (
    ApprovalChallenge,
    AuthContext,
    Decision,
    Finding,
    RiskLevel,
    SecurityVerdict,
    ToolRequest,
    ToolResponse,
    ToolSpec,
    action_hash,
    canonical_json,
)
from .db import Agent, Approval, Database, IdempotencyRecord, QuarantineItem, utcnow
from .integration import IntegrationManager
from .policy import PolicyEngine
from .registry import get_tool, validate_tool_arguments
from .security import (
    hash_api_key,
    preview,
    sanitize_dict,
    verify_approval_token,
)


class GatewayError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class Gateway:
    def __init__(
        self,
        settings: Settings,
        database: Database,
        integrations: IntegrationManager,
        policy: PolicyEngine,
        audit: AuditService,
    ) -> None:
        self.settings = settings
        self.database = database
        self.integrations = integrations
        self.policy = policy
        self.audit = audit
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def execute(
        self,
        auth: AuthContext,
        request: ToolRequest,
        *,
        approval_token: str | None = None,
        idempotency_key: str | None = None,
    ) -> ToolResponse:
        async with self._locks[auth.tenant_id]:
            replay = await self._begin_idempotency(auth.tenant_id, request, idempotency_key)
            if replay is not None:
                return replay.model_copy(update={"idempotent_replay": True})
            try:
                response = await self._execute(auth, request, approval_token, idempotency_key)
                return response
            except GatewayError:
                await self._mark_idempotency_failed(auth.tenant_id, idempotency_key)
                raise
            except Exception:
                await self._mark_idempotency_failed(auth.tenant_id, idempotency_key)
                raise

    async def propose(self, auth: AuthContext, request: ToolRequest) -> ToolResponse:
        spec = get_tool(request.tool_name)
        if spec is None:
            async with self.database.session() as session:
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.HIGH,
                    risk_score=80,
                    reason="Tool is not registered in the execution gateway.",
                    findings=[
                        Finding(
                            code="unknown_tool",
                            severity=RiskLevel.HIGH,
                            reason="Unknown tools are denied by default.",
                            location="tool_name",
                        )
                    ],
                    policy_id="registry.default_deny",
                )
                response = await self._record_denial(session, auth, request, verdict, None)
                await session.commit()
                return response
        try:
            arguments = validate_tool_arguments(request.tool_name, request.arguments)
        except (ValidationError, ValueError) as exc:
            async with self.database.session() as session:
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.MEDIUM,
                    risk_score=45,
                    reason="Tool arguments failed strict schema validation.",
                    findings=[
                        Finding(
                            code="invalid_schema",
                            severity=RiskLevel.MEDIUM,
                            reason="Arguments do not match the registered tool schema.",
                            evidence=str(exc)[:250],
                            location="arguments",
                        )
                    ],
                    policy_id="registry.schema",
                )
                response = await self._record_denial(session, auth, request, verdict, None)
                await session.commit()
                return response
        request = request.model_copy(update={"arguments": arguments})
        async with self.database.session() as session:
            agent = await session.get(Agent, auth.agent_id) if auth.agent_id else None
            if agent is None or agent.tenant_id != auth.tenant_id:
                raise GatewayError("Agent identity is not valid for this tenant", 401)
            if self.integrations.p1_status not in {"MOCK", "REAL"}:
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=100,
                    reason="Security engine is unavailable; the gateway failed closed.",
                    findings=[
                        Finding(
                            code="inspection_failed",
                            severity=RiskLevel.CRITICAL,
                            reason="The P1 security engine is unavailable.",
                            location="integration.p1",
                        )
                    ],
                    policy_id="integration.p1_unavailable",
                )
                response = await self._record_denial(session, auth, request, verdict, None)
                await session.commit()
                return response
            try:
                findings = await self.integrations.security_engine.inspect_tool_call(
                    request, request.tool_name, arguments
                )
            except Exception:
                findings = [
                    Finding(
                        code="inspection_failed",
                        severity=RiskLevel.CRITICAL,
                        reason="The P1 inspection call raised an error.",
                        location="integration.p1",
                    )
                ]
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=100,
                    reason="Security inspection failed; the gateway failed closed.",
                    findings=findings,
                    policy_id="integration.inspection_failed",
                )
                response = await self._record_denial(session, auth, request, verdict, None)
                await session.commit()
                return response
            verdict = await self.policy.evaluate(
                auth, spec, arguments, request.provenance, findings
            )
            if verdict.decision in {Decision.DENY, Decision.QUARANTINE}:
                response = await self._record_denial(
                    session, auth, request, verdict, None, agent=agent
                )
                await session.commit()
                return response
            approval = None
            if verdict.decision == Decision.REQUIRE_APPROVAL:
                approval = await find_or_create_approval(
                    session,
                    self.settings,
                    tenant_id=auth.tenant_id,
                    agent_id=agent.id,
                    request=request,
                    risk_score=verdict.risk_score,
                    reason=verdict.reason,
                )
            event = await self.audit.append(
                session,
                tenant_id=auth.tenant_id,
                actor_type="agent",
                actor_id=agent.id,
                action="tool.proposed",
                decision=verdict.decision.value,
                risk_score=verdict.risk_score,
                risk_level=verdict.risk_level.value,
                tool_name=request.tool_name,
                request_id=request.request_id,
                details={
                    "summary": f"{request.tool_name} proposed without execution",
                    "agent_name": agent.name,
                    "policy_id": verdict.policy_id,
                    "arguments": sanitize_dict(arguments),
                    "approval_id": approval.id if approval else None,
                    "findings": [
                        finding.model_dump(mode="json") for finding in findings
                    ],
                },
            )
            response = ToolResponse(
                request_id=request.request_id,
                decision=verdict.decision,
                risk_level=verdict.risk_level,
                risk_score=verdict.risk_score,
                executed=False,
                findings=findings,
                reason=verdict.reason,
                approval=ApprovalChallenge(
                    id=approval.id,
                    status=approval.status,
                    expires_at=ensure_aware(approval.expires_at),
                    action_hash=approval.action_hash,
                    action_summary=approval.action_summary,
                )
                if approval
                else None,
                audit_id=event.id,
                status="proposed",
                tool=request.tool_name,
                execution_id=event.id,
                approval_id=approval.id if approval else None,
                result_provenance=request.provenance,
            )
            await session.commit()
            return response

    async def _execute(
        self,
        auth: AuthContext,
        request: ToolRequest,
        approval_token: str | None,
        idempotency_key: str | None,
    ) -> ToolResponse:
        spec = get_tool(request.tool_name)
        if spec is None:
            async with self.database.session() as session:
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.HIGH,
                    risk_score=80,
                    reason="Tool is not registered in the execution gateway.",
                    findings=[
                        Finding(
                            code="unknown_tool",
                            severity=RiskLevel.HIGH,
                            reason="Unknown tools are denied by default.",
                            location="tool_name",
                        )
                    ],
                    policy_id="registry.default_deny",
                )
                response = await self._record_denial(
                    session, auth, request, verdict, idempotency_key
                )
                await session.commit()
                return response

        try:
            arguments = validate_tool_arguments(request.tool_name, request.arguments)
        except (ValidationError, ValueError) as exc:
            async with self.database.session() as session:
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.MEDIUM,
                    risk_score=45,
                    reason="Tool arguments failed strict schema validation.",
                    findings=[
                        Finding(
                            code="invalid_schema",
                            severity=RiskLevel.MEDIUM,
                            reason="Arguments do not match the registered tool schema.",
                            evidence=str(exc)[:250],
                            location="arguments",
                        )
                    ],
                    policy_id="registry.schema",
                )
                response = await self._record_denial(
                    session, auth, request, verdict, idempotency_key
                )
                await session.commit()
                return response

        request = request.model_copy(update={"arguments": arguments})
        async with self.database.session() as session:
            agent = await session.get(Agent, auth.agent_id) if auth.agent_id else None
            if agent is None or agent.tenant_id != auth.tenant_id:
                raise GatewayError("Agent identity is not valid for this tenant", 401)
            if agent.status != "Active":
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.HIGH,
                    risk_score=80,
                    reason="Agent is disabled.",
                    findings=[],
                    policy_id="identity.disabled",
                )
                response = await self._record_denial(
                    session, auth, request, verdict, idempotency_key
                )
                await session.commit()
                return response

            if self.integrations.p1_status not in {"MOCK", "REAL"}:
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=100,
                    reason="Security engine is unavailable; the gateway failed closed.",
                    findings=[
                        Finding(
                            code="inspection_failed",
                            severity=RiskLevel.CRITICAL,
                            reason="The P1 security engine is unavailable.",
                            location="integration.p1",
                        )
                    ],
                    policy_id="integration.p1_unavailable",
                )
                response = await self._record_denial(
                    session, auth, request, verdict, idempotency_key
                )
                await session.commit()
                return response

            try:
                findings = await self.integrations.security_engine.inspect_input(
                    request, request.tool_name, arguments
                )
            except Exception:
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=100,
                    reason="Security inspection failed; the gateway failed closed.",
                    findings=[
                        Finding(
                            code="inspection_failed",
                            severity=RiskLevel.CRITICAL,
                            reason="The P1 inspection call raised an error.",
                            location="integration.p1",
                        )
                    ],
                    policy_id="integration.inspection_failed",
                )
                response = await self._record_denial(
                    session, auth, request, verdict, idempotency_key
                )
                await session.commit()
                return response

            verdict = await self.policy.evaluate(
                auth, spec, arguments, request.provenance, findings
            )

            if verdict.decision in {Decision.DENY, Decision.QUARANTINE}:
                response = await self._record_denial(
                    session,
                    auth,
                    request,
                    verdict,
                    idempotency_key,
                    agent=agent,
                )
                await session.commit()
                return response

            adapter = self.integrations.adapter_for(request.tool_name)
            if adapter is None or self.integrations.p2_status not in {"MOCK", "REAL"} and request.tool_name.startswith(("read_", "run_", "delete_")):
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=100,
                    reason="Tool adapter is unavailable; the gateway failed closed.",
                    findings=findings,
                    policy_id="integration.adapter_unavailable",
                )
                response = await self._record_denial(
                    session, auth, request, verdict, idempotency_key, agent=agent
                )
                await session.commit()
                return response
            if adapter is None or self.integrations.p3_status not in {"MOCK", "REAL"} and not request.tool_name.startswith(("read_", "run_", "delete_")):
                verdict = SecurityVerdict(
                    decision=Decision.DENY,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=100,
                    reason="Tool adapter is unavailable; the gateway failed closed.",
                    findings=findings,
                    policy_id="integration.adapter_unavailable",
                )
                response = await self._record_denial(
                    session, auth, request, verdict, idempotency_key, agent=agent
                )
                await session.commit()
                return response

            approval: Approval | None = None
            if verdict.decision == Decision.REQUIRE_APPROVAL:
                if not approval_token:
                    approval = await find_or_create_approval(
                        session,
                        self.settings,
                        tenant_id=auth.tenant_id,
                        agent_id=agent.id,
                        request=request,
                        risk_score=verdict.risk_score,
                        reason=verdict.reason,
                    )
                    event = await self.audit.append(
                        session,
                        tenant_id=auth.tenant_id,
                        actor_type="agent",
                        actor_id=agent.id,
                        action="approval.requested",
                        decision=Decision.REQUIRE_APPROVAL.value,
                        risk_score=verdict.risk_score,
                        risk_level=verdict.risk_level.value,
                        tool_name=request.tool_name,
                        request_id=request.request_id,
                        details={
                            "summary": f"{request.tool_name} requires human approval: {verdict.reason}",
                            "agent_name": agent.name,
                            "approval_id": approval.id,
                            "policy_id": verdict.policy_id,
                            "arguments": sanitize_dict(arguments),
                            "findings": [
                                finding.model_dump(mode="json") for finding in findings
                            ],
                        },
                    )
                    response = ToolResponse(
                        request_id=request.request_id,
                        decision=Decision.REQUIRE_APPROVAL,
                        risk_level=verdict.risk_level,
                        risk_score=verdict.risk_score,
                        executed=False,
                        findings=findings,
                        reason=verdict.reason,
                        approval=ApprovalChallenge(
                            id=approval.id,
                            status=approval.status,
                            expires_at=ensure_aware(approval.expires_at),
                            action_hash=approval.action_hash,
                            action_summary=approval.action_summary,
                        ),
                        audit_id=event.id,
                    )
                    await self._complete_idempotency(
                        session, auth.tenant_id, idempotency_key, response
                    )
                    await session.commit()
                    return response
                approval = await self._consume_approval(
                    session, auth, request, approval_token
                )
                if approval is None:
                    verdict = SecurityVerdict(
                        decision=Decision.DENY,
                        risk_level=RiskLevel.CRITICAL,
                        risk_score=100,
                        reason="Approval token is invalid, expired, tampered, or already consumed.",
                        findings=findings,
                        policy_id="approval.invalid_token",
                    )
                    response = await self._record_denial(
                        session,
                        auth,
                        request,
                        verdict,
                        idempotency_key,
                        agent=agent,
                    )
                    await session.commit()
                    return response

            try:
                await adapter.precheck(
                    request, request.tool_name, arguments, auth=auth
                )
                adapter_result = await adapter.execute(
                    request, request.tool_name, arguments, auth=auth
                )
            except AdapterError as exc:
                event = await self.audit.append(
                    session,
                    tenant_id=auth.tenant_id,
                    actor_type="agent",
                    actor_id=agent.id,
                    action="tool.failed",
                    decision=Decision.DENY.value,
                    risk_score=verdict.risk_score,
                    risk_level=verdict.risk_level.value,
                    tool_name=request.tool_name,
                    request_id=request.request_id,
                    details={
                        "summary": f"{request.tool_name} adapter failed closed: {exc}",
                        "agent_name": agent.name,
                        "policy_id": "adapter.precheck",
                        "arguments": sanitize_dict(arguments),
                        "findings": [finding.model_dump(mode="json") for finding in findings],
                    },
                )
                response = ToolResponse(
                    request_id=request.request_id,
                    decision=Decision.DENY,
                    risk_level=verdict.risk_level,
                    risk_score=verdict.risk_score,
                    executed=False,
                    findings=findings,
                    reason=str(exc),
                    audit_id=event.id,
                )
                await self._complete_idempotency(
                    session, auth.tenant_id, idempotency_key, response
                )
                await session.commit()
                return response
            except Exception:
                event = await self.audit.append(
                    session,
                    tenant_id=auth.tenant_id,
                    actor_type="agent",
                    actor_id=agent.id,
                    action="tool.failed",
                    decision=Decision.DENY.value,
                    risk_score=verdict.risk_score,
                    risk_level=verdict.risk_level.value,
                    tool_name=request.tool_name,
                    request_id=request.request_id,
                    details={
                        "summary": f"{request.tool_name} adapter failed; no result returned.",
                        "agent_name": agent.name,
                        "policy_id": "adapter.execution",
                        "findings": [finding.model_dump(mode="json") for finding in findings],
                    },
                )
                response = ToolResponse(
                    request_id=request.request_id,
                    decision=Decision.DENY,
                    risk_level=verdict.risk_level,
                    risk_score=verdict.risk_score,
                    executed=False,
                    findings=findings,
                    reason="Adapter execution failed; the gateway failed closed.",
                    audit_id=event.id,
                )
                await self._complete_idempotency(
                    session, auth.tenant_id, idempotency_key, response
                )
                await session.commit()
                return response

            output = sanitize_dict(adapter_result.output)
            final_decision = (
                Decision.ALLOW
                if verdict.decision == Decision.REQUIRE_APPROVAL
                else verdict.decision
            )
            try:
                output_findings = await self.integrations.security_engine.inspect_output(
                    request, request.tool_name, output
                )
            except Exception:
                output_findings = []
                output = {"redacted": True, "reason": "output inspection unavailable"}
                final_decision = Decision.REDACT
            if output_findings:
                findings.extend(output_findings)
                output = sanitize_dict(output)
                if any(
                    finding.severity in {RiskLevel.HIGH, RiskLevel.CRITICAL}
                    for finding in output_findings
                ):
                    final_decision = Decision.REDACT
            if verdict.decision == Decision.REDACT:
                final_decision = Decision.REDACT

            agent.request_count += 1
            event = await self.audit.append(
                session,
                tenant_id=auth.tenant_id,
                actor_type="agent",
                actor_id=agent.id,
                action="tool.executed",
                decision=final_decision.value,
                risk_score=verdict.risk_score,
                risk_level=verdict.risk_level.value,
                tool_name=request.tool_name,
                request_id=request.request_id,
                details={
                    "summary": f"{request.tool_name} executed through {adapter.name}",
                    "agent_name": agent.name,
                    "adapter": adapter.name,
                    "policy_id": verdict.policy_id,
                    "arguments": sanitize_dict(arguments),
                    "output_keys": sorted(output.keys()),
                    "approval_id": approval.id if approval else None,
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                    "mock": True,
                },
            )
            response = ToolResponse(
                request_id=request.request_id,
                decision=final_decision,
                risk_level=verdict.risk_level,
                risk_score=verdict.risk_score,
                executed=adapter_result.success,
                result=output,
                findings=findings,
                reason=verdict.reason,
                approval=ApprovalChallenge(
                    id=approval.id,
                    status="Consumed",
                    expires_at=ensure_aware(approval.expires_at),
                    action_hash=approval.action_hash,
                    action_summary=approval.action_summary,
                )
                if approval
                else None,
                audit_id=event.id,
            )
            await self._complete_idempotency(
                session, auth.tenant_id, idempotency_key, response
            )
            await session.commit()
            return response

    async def _consume_approval(
        self,
        session: AsyncSession,
        auth: AuthContext,
        request: ToolRequest,
        token: str,
    ) -> Approval | None:
        try:
            payload = verify_approval_token(self.settings, token)
        except ValueError:
            return None
        approval = await session.get(
            Approval, str(payload["approval_id"]), with_for_update=True
        )
        if approval is None or approval.tenant_id != auth.tenant_id:
            return None
        digest = action_hash(request.tool_name, request.arguments)
        if (
            approval.status != "Approved"
            or approval.consumed_at is not None
            or approval.expires_at is None
            or approval_expired(approval)
            or approval.action_hash != digest
            or payload["action_hash"] != digest
            or approval.nonce != payload["nonce"]
            or approval.token_hash
            != hashlib.sha256(token.encode("utf-8")).hexdigest()
            or approval.tool_name != request.tool_name
        ):
            return None
        approval.consumed_at = utcnow()
        await session.flush()
        return approval

    async def _record_denial(
        self,
        session: AsyncSession,
        auth: AuthContext,
        request: ToolRequest,
        verdict: SecurityVerdict,
        idempotency_key: str | None,
        *,
        agent: Agent | None = None,
    ) -> ToolResponse:
        if agent is None and auth.agent_id:
            agent = await session.get(Agent, auth.agent_id)
        agent_name = agent.name if agent else auth.principal_id
        quarantine_id = None
        if verdict.decision == Decision.QUARANTINE:
            item = QuarantineItem(
                tenant_id=auth.tenant_id,
                agent_id=auth.agent_id or "",
                tool_name=request.tool_name,
                reason=verdict.reason,
                content_preview=preview(
                    {
                        "arguments": sanitize_dict(request.arguments),
                        "source": request.provenance.source,
                    },
                    900,
                ),
            )
            session.add(item)
            await session.flush()
            quarantine_id = item.id
            action = "tool.quarantined"
            summary = f"{request.tool_name} quarantined: {verdict.reason}"
        else:
            action = "tool.denied"
            summary = f"{request.tool_name} denied: {verdict.reason}"
        event = await self.audit.append(
            session,
            tenant_id=auth.tenant_id,
            actor_type="agent",
            actor_id=auth.agent_id or auth.principal_id,
            action=action,
            decision=verdict.decision.value,
            risk_score=verdict.risk_score,
            risk_level=verdict.risk_level.value,
            tool_name=request.tool_name,
            request_id=request.request_id,
            details={
                "summary": summary,
                "agent_name": agent_name,
                "policy_id": verdict.policy_id,
                "arguments": sanitize_dict(request.arguments),
                "findings": [finding.model_dump(mode="json") for finding in verdict.findings],
                "quarantine_id": quarantine_id,
            },
        )
        response = ToolResponse(
            request_id=request.request_id,
            decision=verdict.decision,
            risk_level=verdict.risk_level,
            risk_score=verdict.risk_score,
            executed=False,
            findings=verdict.findings,
            reason=verdict.reason,
            audit_id=event.id,
            quarantine_id=quarantine_id,
        )
        await self._complete_idempotency(
            session, auth.tenant_id, idempotency_key, response
        )
        return response

    async def _begin_idempotency(
        self,
        tenant_id: str,
        request: ToolRequest,
        key: str | None,
    ) -> ToolResponse | None:
        if not key:
            return None
        if len(key) > 200:
            raise GatewayError("Idempotency key is too long", 400)
        request_hash = hashlib.sha256(
            canonical_json(
                {
                    "request_id": request.request_id,
                    "tool": request.tool_name,
                    "arguments": request.arguments,
                }
            ).encode("utf-8")
        ).hexdigest()
        async with self.database.session() as session:
            record = await session.scalar(
                select(IdempotencyRecord).where(
                    IdempotencyRecord.tenant_id == tenant_id,
                    IdempotencyRecord.key == key,
                )
            )
            if record is not None:
                if record.request_hash != request_hash:
                    raise GatewayError(
                        "Idempotency key was already used for a different action", 409
                    )
                if record.status == "complete" and record.response:
                    return ToolResponse.model_validate(record.response)
                raise GatewayError("Request with this idempotency key is in progress", 409)
            session.add(
                IdempotencyRecord(
                    tenant_id=tenant_id,
                    key=key,
                    request_hash=request_hash,
                    status="pending",
                    expires_at=utcnow() + timedelta(hours=24),
                )
            )
            await session.commit()
        return None

    async def _complete_idempotency(
        self,
        session: AsyncSession,
        tenant_id: str,
        key: str | None,
        response: ToolResponse,
    ) -> None:
        if not key:
            return
        record = await session.scalar(
            select(IdempotencyRecord)
            .where(
                IdempotencyRecord.tenant_id == tenant_id,
                IdempotencyRecord.key == key,
            )
            .with_for_update()
        )
        if record is not None:
            record.status = "complete"
            record.response = response.model_dump(mode="json")

    async def _mark_idempotency_failed(self, tenant_id: str, key: str | None) -> None:
        if not key:
            return
        async with self.database.session() as session:
            record = await session.scalar(
                select(IdempotencyRecord)
                .where(
                    IdempotencyRecord.tenant_id == tenant_id,
                    IdempotencyRecord.key == key,
                )
                .with_for_update()
            )
            if record is not None and record.status == "pending":
                record.status = "failed"
                await session.commit()
