"""
AgentShield Central Execution Gateway.
Single, non-bypassable gateway for all external REST API calls and MCP tool invocations.
Enforces the mandatory 13-stage security pipeline:
  Agent Request
      ↓
  Agent Authentication
      ↓
  Connector Registration Check
      ↓
  Per-Agent Permission Check
      ↓
  Endpoint / Tool Validation
      ↓
  Request Schema Validation
      ↓
  Secret Broker Credential Injection
      ↓
  Outbound SecurityEngine Inspection
      ↓
  Hierarchical Rate Limiting
      ↓
  External Execution (REST / MCP)
      ↓
  Response Schema & Size Validation
      ↓
  Inbound SecurityEngine Inspection (Injection, Secrets, DLP)
      ↓
  Cryptographic Audit Logging
      ↓
  Safe Response to Agent
"""

from __future__ import annotations

import json
import time
from typing import Any
import uuid

from core.config import setup_logger
from core.connectors.api_connector import RestApiConnector
from core.connectors.mcp_connector import McpConnector
from core.connectors.models import (
    ConnectorAuditRecord,
    ConnectorRegistration,
    ConnectorType,
    ExecutionRequest,
    ExecutionResponse,
    ExecutionStatus,
    HttpMethod,
    McpToolDefinition,
    SecurityDecision,
)
from core.connectors.permissions import PermissionManager
from core.connectors.rate_limiter import RateLimiter
from core.connectors.registry import ConnectorRegistry
from core.connectors.secret_broker import SecretBroker
from core.provenance import ProvenanceEngine
from core.schemas import (
    Action,
    DetectionFinding,
    GuardrailContext,
    RiskLevel,
    SourceType,
    TrustLevel,
)
from core.security_engine import SecurityEngine

logger = setup_logger("agentshield.connectors.gateway")


class SecurityGateway:
    """
    Central Security Gateway orchestrating external API and MCP interactions.
    Guarantees that no external call can bypass security inspection, permissions,
    secret protection, or audit logging.
    """

    def __init__(
        self,
        security_engine: SecurityEngine | None = None,
        registry: ConnectorRegistry | None = None,
        permission_manager: PermissionManager | None = None,
        secret_broker: SecretBroker | None = None,
        rate_limiter: RateLimiter | None = None,
        provenance_engine: ProvenanceEngine | None = None,
        api_connector: RestApiConnector | None = None,
        mcp_connector: McpConnector | None = None,
        allow_private_network: bool = False,
    ) -> None:
        self.security_engine = security_engine or SecurityEngine()
        self.registry = registry or ConnectorRegistry()
        self.permission_manager = permission_manager or PermissionManager()
        self.secret_broker = secret_broker or SecretBroker(
            secret_scanner=self.security_engine.secret_scanner
        )
        self.rate_limiter = rate_limiter or RateLimiter()
        self.provenance_engine = provenance_engine or self.security_engine.provenance_engine
        self.api_connector = api_connector or RestApiConnector()
        self.mcp_connector = mcp_connector or McpConnector(
            injection_detector=self.security_engine.injection_detector
        )
        self.allow_private_network = allow_private_network

        self._audit_records: list[ConnectorAuditRecord] = []

    # -----------------------------------------------------------------------
    # Central Execution Pipeline
    # -----------------------------------------------------------------------

    async def execute(self, request: ExecutionRequest) -> ExecutionResponse:
        """
        Executes an external API or MCP tool call through the mandatory security gateway pipeline.
        Every path (allowed or rejected) produces an audit log and cryptographic provenance record.
        """
        start_time = time.perf_counter()
        agent_id = (request.agent_id or "").strip()
        connector_id = (request.connector_id or "").strip()
        tool_name = request.tool_name
        endpoint_path = request.endpoint
        http_method = request.method

        ctx = GuardrailContext(
            session_id=request.session_id or str(uuid.uuid4()),
            agent_id=agent_id or "unknown_agent",
            user_id=request.user_id,
            metadata={"connector_id": connector_id, **request.metadata},
        )

        # -------------------------------------------------------------------
        # 1. Agent Authentication Check
        # -------------------------------------------------------------------
        if not agent_id:
            return self._reject(
                reason="Authentication failed: Missing or invalid agent identifier",
                agent_id="anonymous",
                connector_id=connector_id or "unknown",
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
            )

        # -------------------------------------------------------------------
        # 2. Connector Registration Check
        # -------------------------------------------------------------------
        connector = self.registry.get_connector(connector_id)
        if not connector:
            return self._reject(
                reason=f"Connector '{connector_id}' is not registered in AgentShield registry",
                agent_id=agent_id,
                connector_id=connector_id,
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
            )

        if not connector.enabled:
            return self._reject(
                reason=f"Connector '{connector_id}' is currently disabled by administrative policy",
                agent_id=agent_id,
                connector_id=connector_id,
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
            )

        # -------------------------------------------------------------------
        # 3. Per-Agent Permission Check (Server-Side)
        # -------------------------------------------------------------------
        has_perm, perm_reason = self.permission_manager.check_permission(
            agent_id=agent_id,
            connector_id=connector_id,
            method=http_method,
            tool_name=tool_name,
            arguments=request.arguments,
        )
        if not has_perm:
            return self._reject(
                reason=perm_reason or "Permission denied by server-side policy",
                agent_id=agent_id,
                connector_id=connector_id,
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
            )

        # -------------------------------------------------------------------
        # 4. Endpoint / Tool Validation
        # -------------------------------------------------------------------
        matched_endpoint = None
        matched_tool: McpToolDefinition | None = None

        if connector.connector_type == ConnectorType.REST_API:
            if not endpoint_path:
                return self._reject(
                    reason=f"REST API connector '{connector_id}' requires an endpoint path",
                    agent_id=agent_id,
                    connector_id=connector_id,
                    tool_name=tool_name,
                    http_method=http_method.value if http_method else None,
                    endpoint=endpoint_path,
                    start_time=start_time,
                    context=ctx,
                )

            matched_endpoint = self.registry.match_endpoint(connector, endpoint_path, http_method)
            if not matched_endpoint:
                return self._reject(
                    reason=(
                        f"Endpoint '{endpoint_path}' with method '{http_method.value}' "
                        f"is not registered for connector '{connector_id}'"
                    ),
                    agent_id=agent_id,
                    connector_id=connector_id,
                    tool_name=tool_name,
                    http_method=http_method.value if http_method else None,
                    endpoint=endpoint_path,
                    start_time=start_time,
                    context=ctx,
                )

        elif connector.connector_type == ConnectorType.MCP:
            if not tool_name:
                return self._reject(
                    reason=f"MCP connector '{connector_id}' requires a tool_name",
                    agent_id=agent_id,
                    connector_id=connector_id,
                    tool_name=tool_name,
                    http_method=None,
                    endpoint=None,
                    start_time=start_time,
                    context=ctx,
                )

            matched_tool = self.registry.get_tool(connector_id, tool_name)
            if not matched_tool:
                return self._reject(
                    reason=f"MCP tool '{tool_name}' is not registered on connector '{connector_id}'",
                    agent_id=agent_id,
                    connector_id=connector_id,
                    tool_name=tool_name,
                    http_method=None,
                    endpoint=None,
                    start_time=start_time,
                    context=ctx,
                )

            if not matched_tool.is_approved:
                return self._reject(
                    reason=f"MCP tool '{tool_name}' has not been approved for execution (untrusted)",
                    agent_id=agent_id,
                    connector_id=connector_id,
                    tool_name=tool_name,
                    http_method=None,
                    endpoint=None,
                    start_time=start_time,
                    context=ctx,
                )

        # -------------------------------------------------------------------
        # 5. Request Schema & Payload Size Validation
        # -------------------------------------------------------------------
        payload_data = request.body if request.body is not None else request.arguments
        payload_str = json.dumps(payload_data, default=str) if payload_data else ""
        if len(payload_str.encode("utf-8")) > connector.max_payload_size_bytes:
            return self._reject(
                reason=(
                    f"Request payload size ({len(payload_str.encode('utf-8'))} bytes) "
                    f"exceeds maximum allowed {connector.max_payload_size_bytes} bytes"
                ),
                agent_id=agent_id,
                connector_id=connector_id,
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
            )

        # Validate input schema
        if matched_tool and matched_tool.input_schema:
            try:
                McpConnector.validate_arguments(matched_tool, request.arguments)
            except Exception as schema_err:
                return self._reject(
                    reason=f"Request argument schema validation failed: {schema_err}",
                    agent_id=agent_id,
                    connector_id=connector_id,
                    tool_name=tool_name,
                    http_method=None,
                    endpoint=None,
                    start_time=start_time,
                    context=ctx,
                )

        # -------------------------------------------------------------------
        # 6. Secret Broker: Credential Retrieval & Header Injection
        # -------------------------------------------------------------------
        # Make a copy of caller headers so original request remains pristine
        working_headers, working_params = self.secret_broker.inject_auth(
            auth_config=connector.auth_config,
            headers=request.headers,
            query_params=request.arguments if http_method == HttpMethod.GET else None,
        )

        # -------------------------------------------------------------------
        # 7. Outbound Security Inspection (Existing SecurityEngine)
        # -------------------------------------------------------------------
        outbound_tool_name = tool_name or endpoint_path or "external_call"
        outbound_check = await self.security_engine.inspect_output(
            tool_call={
                "tool_name": outbound_tool_name,
                "tool_args": request.arguments or request.body or {},
            },
            context=ctx,
            mode="tool_call",
            raise_on_block=False,
        )

        if not outbound_check.allowed or outbound_check.action in (Action.BLOCK, Action.QUARANTINE):
            factors = "; ".join(outbound_check.risk_assessment.factors) or "Security policy violation"
            return self._reject(
                reason=f"Outbound request blocked by SecurityEngine: {factors}",
                agent_id=agent_id,
                connector_id=connector_id,
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
                findings=outbound_check.findings,
                risk_score=outbound_check.risk_assessment.overall_score,
            )

        # -------------------------------------------------------------------
        # 8. Hierarchical Rate Limiting Check
        # -------------------------------------------------------------------
        rate_ok, rate_msg = self.rate_limiter.check_rate_limit(
            agent_id=agent_id,
            connector_id=connector_id,
            tool_name=tool_name or endpoint_path,
        )
        if not rate_ok:
            return self._reject(
                reason=rate_msg or "Rate limit exceeded",
                agent_id=agent_id,
                connector_id=connector_id,
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
            )

        # -------------------------------------------------------------------
        # 9. External Execution (REST API / MCP)
        # -------------------------------------------------------------------
        raw_response: Any = None
        try:
            if connector.connector_type == ConnectorType.REST_API:
                assert matched_endpoint is not None
                status_code, raw_response, _ = await self.api_connector.execute_request(
                    connector=connector,
                    endpoint=matched_endpoint,
                    method=http_method,
                    path=endpoint_path or matched_endpoint.path,
                    headers=working_headers,
                    query_params=working_params if http_method == HttpMethod.GET else None,
                    body=request.body if request.body is not None else (request.arguments if http_method != HttpMethod.GET else None),
                    allow_private_network=self.allow_private_network,
                )
            elif connector.connector_type == ConnectorType.MCP:
                assert matched_tool is not None
                raw_response = await self.mcp_connector.call_tool(
                    connector=connector,
                    tool=matched_tool,
                    arguments=request.arguments,
                    headers=working_headers,
                )
        except Exception as exec_err:
            logger.error("External connector execution failed: %s", type(exec_err).__name__)
            return self._reject(
                reason="External connector execution failed.",
                agent_id=agent_id,
                connector_id=connector_id,
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
                status=ExecutionStatus.FAILED,
            )

        # -------------------------------------------------------------------
        # 10. Response Schema & Payload Size Validation
        # -------------------------------------------------------------------
        resp_str = json.dumps(raw_response, default=str) if isinstance(raw_response, (dict, list)) else str(raw_response)
        if len(resp_str.encode("utf-8")) > connector.max_payload_size_bytes:
            return self._reject(
                reason=(
                    f"External response size ({len(resp_str.encode('utf-8'))} bytes) "
                    f"exceeds maximum allowed {connector.max_payload_size_bytes} bytes"
                ),
                agent_id=agent_id,
                connector_id=connector_id,
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
            )

        # -------------------------------------------------------------------
        # 11. Inbound Security Inspection (Existing SecurityEngine)
        # -------------------------------------------------------------------
        # External tool output is untrusted. We inspect for:
        # 1. Indirect prompt injection attacks (trying to hijack the agent)
        # 2. Leaked credentials / secrets in returned content
        # 3. PII and DLP policy violations
        inbound_check = await self.security_engine.inspect_output(
            tool_call={
                "tool_name": outbound_tool_name,
                "tool_output": raw_response,
            },
            context=ctx,
            mode="tool_output",
            raise_on_block=False,
        )

        # Also inspect as external untrusted data
        data_check = await self.security_engine.inspect_data(
            content=resp_str,
            source_type=SourceType.TOOL_OUTPUT,
            trust_level=TrustLevel.LOW,
            source_uri=connector.base_url or connector.mcp_server_url,
            context=ctx,
            raise_on_block=False,
        )

        # Combine security determinations
        all_findings: list[DetectionFinding] = []
        all_findings.extend(inbound_check.findings)
        all_findings.extend(data_check.findings)
        # Deduplicate findings by rule_id and detector
        unique_findings = {f"{f.detector.value}:{f.rule_id}:{f.description}": f for f in all_findings}.values()
        findings_list = list(unique_findings)

        is_blocked = (
            not inbound_check.allowed
            or not data_check.allowed
            or inbound_check.action in (Action.BLOCK, Action.QUARANTINE)
            or data_check.action in (Action.BLOCK, Action.QUARANTINE)
        )

        if is_blocked:
            factors = "; ".join(
                inbound_check.risk_assessment.factors + data_check.risk_assessment.factors
            ) or "Malicious or sensitive content detected in external tool output"
            return self._reject(
                reason=f"Inbound tool output blocked by SecurityEngine: {factors}",
                agent_id=agent_id,
                connector_id=connector_id,
                tool_name=tool_name,
                http_method=http_method.value if http_method else None,
                endpoint=endpoint_path,
                start_time=start_time,
                context=ctx,
                findings=findings_list,
                risk_score=max(
                    inbound_check.risk_assessment.overall_score,
                    data_check.risk_assessment.overall_score,
                ),
            )

        # Check if masking was applied (e.g. PII sanitized)
        sanitized_res = raw_response
        if inbound_check.action == Action.MASK or data_check.action == Action.MASK:
            sanitized_res = inbound_check.sanitized_output or data_check.sanitized_prompt
        # Scrub any secrets from secret broker
        sanitized_res = self.secret_broker.scrub_data(sanitized_res)

        # -------------------------------------------------------------------
        # 12. Audit Logging & Cryptographic Provenance
        # -------------------------------------------------------------------
        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        prov_record = self.provenance_engine.create_record(
            input_text=f"gateway-exec:{connector_id}:{tool_name or endpoint_path}",
            action=Action.ALLOW if not findings_list else Action.WARN,
            risk_level=inbound_check.risk_assessment.level,
            output_text=str(sanitized_res)[:200],  # truncated summary only, never full secret
            session_id=ctx.session_id,
            agent_id=agent_id,
            source_type=SourceType.TOOL_OUTPUT,
            trust_level=TrustLevel.LOW,
            source_uri=connector.base_url or connector.mcp_server_url,
            metadata={
                "connector_id": connector_id,
                "tool_name": tool_name,
                "endpoint": endpoint_path,
                "duration_ms": duration_ms,
            },
        )

        audit_rec = ConnectorAuditRecord(
            agent_id=agent_id,
            connector_id=connector_id,
            tool_name=tool_name,
            http_method=http_method.value if http_method else None,
            endpoint=endpoint_path,
            security_decision=SecurityDecision.ALLOW,
            execution_status=ExecutionStatus.SUCCESS,
            duration_ms=duration_ms,
            findings_count=len(findings_list),
            risk_score=inbound_check.risk_assessment.overall_score,
            provenance_record_id=prov_record.record_id,
        )
        self._audit_records.append(audit_rec)

        # -------------------------------------------------------------------
        # 13. Safe Response Returned to Agent
        # -------------------------------------------------------------------
        return ExecutionResponse(
            status=ExecutionStatus.SUCCESS,
            security_decision=SecurityDecision.ALLOW,
            allowed=True,
            data=raw_response,
            sanitized_data=sanitized_res,
            audit_record=audit_rec,
            latency_ms=duration_ms,
            findings=findings_list,
        )

    # -----------------------------------------------------------------------
    # Rejection Helper
    # -----------------------------------------------------------------------

    def _reject(
        self,
        reason: str,
        agent_id: str,
        connector_id: str,
        tool_name: Optional[str] = None,
        http_method: Optional[str] = None,
        endpoint: Optional[str] = None,
        start_time: float = 0.0,
        context: Optional[GuardrailContext] = None,
        findings: Optional[list[DetectionFinding]] = None,
        risk_score: float = 0.0,
        status: ExecutionStatus = ExecutionStatus.REJECTED,
    ) -> ExecutionResponse:
        """
        Constructs a structured rejection response and guarantees provenance ledger recording.
        Resilient: Audit failures (secret broker, provenance engine, audit record creation)
        never escalate into unhandled exceptions or convert a rejection into an allowed request.
        """
        FALLBACK_REASON = "Request rejected; audit details unavailable."

        try:
            try:
                duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            except Exception:
                duration_ms = 0.0

            # F4: Sanitize findings upfront so malformed objects cannot crash Pydantic later
            safe_findings: list[DetectionFinding] = []
            if findings:
                try:
                    for f in findings:
                        if isinstance(f, DetectionFinding):
                            safe_findings.append(f)
                except Exception:
                    safe_findings = []

            safe_status = status if isinstance(status, ExecutionStatus) else ExecutionStatus.REJECTED
            audit_complete = True

            # ---------------------------------------------------------------
            # 1. Secret Scrubbing with Fail-Safe Fallback
            # ---------------------------------------------------------------
            clean_reason = FALLBACK_REASON
            try:
                if self.secret_broker is not None and reason:
                    scrubbed = self.secret_broker.scrub_text(reason)
                    clean_reason = scrubbed if scrubbed else FALLBACK_REASON
                elif not reason:
                    clean_reason = FALLBACK_REASON
                else:
                    audit_complete = False
            except Exception:
                # Never expose raw reason or raw exception details in logs/response
                clean_reason = FALLBACK_REASON
                audit_complete = False
                try:
                    logger.error("Audit secret scrubbing failed; using safe fallback rejection message")
                except Exception:
                    pass

            # ---------------------------------------------------------------
            # 2. Cryptographic Provenance Ledger Entry
            # ---------------------------------------------------------------
            prov_record = None
            try:
                if self.provenance_engine is not None:
                    prov_record = self.provenance_engine.create_record(
                        input_text=f"gateway-rejection:{connector_id}:{tool_name or endpoint}",
                        action=Action.BLOCK,
                        risk_level=RiskLevel.HIGH if risk_score > 0.7 else RiskLevel.MEDIUM,
                        output_text=f"[EXECUTION_BLOCKED: {clean_reason}]",
                        session_id=context.session_id if context else None,
                        agent_id=agent_id,
                        source_type=SourceType.AGENT,
                        metadata={
                            "stage": "gateway_evaluation",
                            "rejection_reason": clean_reason,
                            "connector_id": connector_id,
                            "tool_name": tool_name,
                            "endpoint": endpoint,
                            "audit_status": "complete" if audit_complete else "incomplete",
                        },
                    )
                else:
                    audit_complete = False
            except Exception:
                prov_record = None
                audit_complete = False
                try:
                    logger.error("Failed to create provenance record during gateway rejection")
                except Exception:
                    pass

            # ---------------------------------------------------------------
            # 3. Connector Audit Record Construction & Storage
            # ---------------------------------------------------------------
            audit_rec = None
            # Avoid creating misleading partial audit records:
            # Only construct and record ConnectorAuditRecord if provenance succeeded
            if prov_record is not None:
                try:
                    audit_meta = {
                        "audit_status": "complete" if audit_complete else "incomplete",
                        "persistence_status": "pending",
                    }
                    audit_rec = ConnectorAuditRecord(
                        agent_id=agent_id,
                        connector_id=connector_id,
                        tool_name=tool_name,
                        http_method=http_method,
                        endpoint=endpoint,
                        security_decision=SecurityDecision.BLOCK,
                        execution_status=safe_status,
                        rejection_reason=clean_reason,
                        duration_ms=duration_ms,
                        findings_count=len(safe_findings),
                        risk_score=risk_score,
                        provenance_record_id=prov_record.record_id,
                        metadata=audit_meta,
                    )
                    try:
                        self._audit_records.append(audit_rec)
                        audit_rec.metadata["persistence_status"] = "persisted"
                    except Exception:
                        # F3: Persistence failed! Never claim "complete".
                        # Do not mutate prov_record to preserve cryptographic integrity.
                        # Truthfully mark audit status as incomplete and document persistence failure.
                        audit_complete = False
                        audit_rec.metadata["audit_status"] = "incomplete"
                        audit_rec.metadata["persistence_status"] = "failed"
                        try:
                            logger.error("Failed to append audit record to gateway registry")
                        except Exception:
                            pass
                except Exception:
                    audit_rec = None
                    audit_complete = False
                    try:
                        logger.error("Failed to construct ConnectorAuditRecord")
                    except Exception:
                        pass
            else:
                # Provenance failed: avoid creating misleading partial audit record
                audit_complete = False

            # ---------------------------------------------------------------
            # 4. Safe Logging
            # ---------------------------------------------------------------
            try:
                logger.warning(
                    "GATEWAY BLOCKED: agent='%s', connector='%s', tool='%s', reason='%s'",
                    agent_id,
                    connector_id,
                    tool_name or endpoint,
                    clean_reason,
                )
            except Exception:
                pass

            # ---------------------------------------------------------------
            # 5. Guaranteed Structured Rejection Response
            # ---------------------------------------------------------------
            return ExecutionResponse(
                status=safe_status,
                security_decision=SecurityDecision.BLOCK,
                allowed=False,
                data=None,
                sanitized_data=None,
                rejection_reason=clean_reason,
                audit_record=audit_rec,
                latency_ms=duration_ms,
                findings=safe_findings,
            )

        except Exception:
            # F4: Outermost safety net: under no circumstance may _reject raise an exception
            try:
                safe_fallback_findings: list[DetectionFinding] = []
                if findings:
                    try:
                        for f in findings:
                            if isinstance(f, DetectionFinding):
                                safe_fallback_findings.append(f)
                    except Exception:
                        safe_fallback_findings = []

                safe_fallback_status = status if isinstance(status, ExecutionStatus) else ExecutionStatus.BLOCKED

                return ExecutionResponse(
                    status=safe_fallback_status,
                    security_decision=SecurityDecision.BLOCK,
                    allowed=False,
                    data=None,
                    sanitized_data=None,
                    rejection_reason="Request rejected; audit details unavailable.",
                    audit_record=None,
                    latency_ms=0.0,
                    findings=safe_fallback_findings,
                )
            except Exception:
                return ExecutionResponse.model_construct(
                    status=ExecutionStatus.BLOCKED,
                    security_decision=SecurityDecision.BLOCK,
                    allowed=False,
                    data=None,
                    sanitized_data=None,
                    rejection_reason="Request rejected; audit details unavailable.",
                    audit_record=None,
                    latency_ms=0.0,
                    findings=[],
                )

    def get_audit_records(self) -> list[ConnectorAuditRecord]:
        """Returns all recorded gateway audit entries."""
        return list(self._audit_records)

    def clear_audit_records(self) -> None:
        """Clears audit records (for testing)."""
        self._audit_records.clear()
