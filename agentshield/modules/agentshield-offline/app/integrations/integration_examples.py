"""
AgentShield Offline — Integration Examples.

Illustrates how Person 1's and Person 4's adapters can replace the local
development adapters through dependency injection.

This file is NOT production code — it is documentation-as-code showing
the integration pattern. See docs/integration_guide.md for details.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Example: Replacing the local content inspector with Person 1's adapter
# ---------------------------------------------------------------------------
# 
# Person 1 implements a class that satisfies the ContentInspectionPort Protocol:
#
# class Person1ContentInspector:
#     async def inspect(
#         self,
#         content: str,
#         *,
#         source_metadata=None,
#     ) -> ContentInspectionResult:
#         # Calls Person 1's prompt injection detector, PII detector, DLP engine
#         response = await self._person1_client.scan(content, source_metadata)
#         return ContentInspectionResult(
#             passed=response.is_safe,
#             findings=response.findings,
#             risk_score=response.score,
#             inspector="person1_engine",
#         )
#
# Then in app/api/dependencies.py, replace the local inspector:
#
# from person1_integration import Person1ContentInspector
#
# def get_content_inspector() -> ContentInspectionPort:
#     return Person1ContentInspector(settings=get_settings())
#
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Example: Replacing the local audit adapter with Person 4's adapter
# ---------------------------------------------------------------------------
#
# class Person4AuditAdapter:
#     async def record(self, event: AuditEvent) -> None:
#         await self._central_audit_service.emit(
#             event_id=event.event_id,
#             agent_id=event.agent_id,
#             ...
#         )
#
# In app/api/dependencies.py:
#
# from person4_integration import Person4AuditAdapter
#
# def get_audit_adapter() -> AuditPort:
#     return Person4AuditAdapter(endpoint=settings.audit_endpoint)
#
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Example: Replacing the local policy adapter with Person 4's OPA adapter
# ---------------------------------------------------------------------------
#
# class Person4PolicyAdapter:
#     async def authorize(self, *, agent_id, tenant_id, operation, resource, context=None):
#         result = await self._opa_client.evaluate(
#             policy="agentshield.offline.allow",
#             input={"agent": agent_id, "tenant": tenant_id, "op": operation, "resource": resource}
#         )
#         if result.get("allow"):
#             return SecurityDecision.ALLOW
#         return SecurityDecision.DENY
#
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Example: Replacing the DenyByDefault approval adapter with Person 4's
# ---------------------------------------------------------------------------
#
# class Person4ApprovalAdapter:
#     async def request_approval(self, *, agent_id, tenant_id, operation, ...):
#         ticket = await self._approval_service.create(...)
#         approved = await self._approval_service.wait_for_decision(ticket, timeout)
#         return approved
#
# ---------------------------------------------------------------------------
