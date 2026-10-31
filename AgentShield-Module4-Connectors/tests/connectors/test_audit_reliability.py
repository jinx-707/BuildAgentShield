"""
Regression Tests for Fail-Closed Audit Reliability in Module 4 (SecurityGateway._reject).
Tests:
  1. Normal rejection: returns allowed=False and records audit/provenance successfully.
  2. Secret broker failure: returns allowed=False without exposing the original reason.
  3. Provenance engine failure: returns allowed=False without propagating an exception.
  4. Audit-record construction failure: returns allowed=False without propagating an exception.
  5. Audit append failure: rejection remains intact.
  6. Sensitive information in rejection reason: never appears in fallback logs or response.
  7. External operation is never executed when audit components fail.
  8. Existing rejection behavior and response compatibility remain intact.
"""

from unittest.mock import AsyncMock, MagicMock
import logging
import pytest

from core.connectors.gateway import SecurityGateway
from core.connectors.models import (
    AgentPermissionRule,
    ConnectorRegistration,
    ConnectorType,
    EndpointDefinition,
    ExecutionRequest,
    ExecutionStatus,
    HttpMethod,
    PermissionAction,
    SecurityDecision,
)
from core.connectors.permissions import PermissionManager
from core.connectors.registry import ConnectorRegistry
from core.provenance import ProvenanceEngine
from core.schemas import Action, GuardrailContext, RiskLevel


@pytest.fixture
def mock_gateway():
    """Builds a lightweight SecurityGateway with mockable components for fast isolated testing."""
    registry = ConnectorRegistry()
    permissions = PermissionManager()
    provenance = ProvenanceEngine()
    secret_broker = MagicMock()
    # Default secret broker scrubs normally
    secret_broker.scrub_text.side_effect = lambda text: text

    api_connector = MagicMock()
    api_connector.execute_request = AsyncMock()

    mcp_connector = MagicMock()
    mcp_connector.call_tool = AsyncMock()

    sec_engine = MagicMock()
    sec_engine.secret_scanner = MagicMock()
    sec_engine.provenance_engine = provenance

    gw = SecurityGateway(
        security_engine=sec_engine,
        registry=registry,
        permission_manager=permissions,
        secret_broker=secret_broker,
        provenance_engine=provenance,
        api_connector=api_connector,
        mcp_connector=mcp_connector,
        allow_private_network=True,
    )
    return gw


@pytest.mark.anyio
async def test_1_normal_rejection_records_audit_and_provenance(mock_gateway):
    """Scenario 1: Normal rejection returns allowed=False and records audit/provenance successfully."""
    gw = mock_gateway
    req = ExecutionRequest(
        agent_id="agent_001",
        connector_id="unregistered_connector",
        endpoint="/api/v1/test",
    )
    resp = await gw.execute(req)

    assert resp.allowed is False
    assert resp.status == ExecutionStatus.REJECTED
    assert resp.security_decision == SecurityDecision.BLOCK
    assert "not registered in AgentShield registry" in resp.rejection_reason

    # Audit record must be present and linked to provenance record
    assert resp.audit_record is not None
    assert resp.audit_record.provenance_record_id is not None
    assert resp.audit_record.metadata.get("audit_status") == "complete"

    # Provenance ledger must contain entry
    ledger = gw.provenance_engine.get_ledger()
    assert len(ledger) > 0
    assert ledger[-1].record_id == resp.audit_record.provenance_record_id


@pytest.mark.anyio
async def test_2_secret_broker_failure_safe_fallback(mock_gateway):
    """Scenario 2: Secret broker failure returns allowed=False without exposing original reason."""
    gw = mock_gateway
    # Simulate secret broker crash
    gw.secret_broker.scrub_text.side_effect = RuntimeError("Secret vault connection timeout")

    ctx = GuardrailContext(agent_id="test_agent")
    sensitive_reason = "Unauthorized call with bearer token: sk-proj-SUPER_SECRET_TOKEN_99999"

    resp = gw._reject(
        reason=sensitive_reason,
        agent_id="test_agent",
        connector_id="conn_test",
        tool_name=None,
        http_method="GET",
        endpoint="/test",
        start_time=0.0,
        context=ctx,
    )

    # Must remain safely rejected
    assert resp.allowed is False
    assert resp.security_decision == SecurityDecision.BLOCK
    assert resp.rejection_reason == "Request rejected; audit details unavailable."

    # Raw sensitive token must NOT appear in response
    assert "sk-proj-SUPER_SECRET_TOKEN_99999" not in str(resp.model_dump())


@pytest.mark.anyio
async def test_3_provenance_engine_failure_handled_gracefully(mock_gateway):
    """Scenario 3: Provenance engine failure returns allowed=False without propagating exception."""
    gw = mock_gateway
    # Mock provenance engine crash
    gw.provenance_engine.create_record = MagicMock(side_effect=RuntimeError("Ledger database disk failure"))

    req = ExecutionRequest(
        agent_id="agent_001",
        connector_id="unregistered_conn",
    )

    # Must NOT raise RuntimeError!
    resp = await gw.execute(req)

    assert resp.allowed is False
    assert resp.status == ExecutionStatus.REJECTED
    assert resp.security_decision == SecurityDecision.BLOCK
    # Misleading partial audit record is avoided when provenance fails
    assert resp.audit_record is None


@pytest.mark.anyio
async def test_4_audit_record_construction_failure_handled(mock_gateway, monkeypatch):
    """Scenario 4: Audit-record construction failure returns allowed=False without propagating exception."""
    gw = mock_gateway

    # Simulate failure in ConnectorAuditRecord constructor
    def failing_audit_constructor(*args, **kwargs):
        raise TypeError("Simulated schema mismatch in ConnectorAuditRecord")

    monkeypatch.setattr("core.connectors.gateway.ConnectorAuditRecord", failing_audit_constructor)

    req = ExecutionRequest(
        agent_id="agent_001",
        connector_id="unregistered_conn",
    )

    # Must NOT raise TypeError!
    resp = await gw.execute(req)

    assert resp.allowed is False
    assert resp.status == ExecutionStatus.REJECTED
    assert resp.security_decision == SecurityDecision.BLOCK
    assert resp.audit_record is None


@pytest.mark.anyio
async def test_5_audit_append_failure_rejection_intact(mock_gateway):
    """Scenario 5 (F3 & F6): Audit append failure keeps rejection intact and marks audit incomplete."""
    gw = mock_gateway

    # Simulate failure appending to audit records
    gw._audit_records = MagicMock()
    gw._audit_records.append.side_effect = RuntimeError("In-memory list storage failed")

    req = ExecutionRequest(
        agent_id="agent_001",
        connector_id="unregistered_conn",
    )

    # Must NOT raise RuntimeError!
    resp = await gw.execute(req)

    assert resp.allowed is False
    assert resp.status == ExecutionStatus.REJECTED
    assert resp.security_decision == SecurityDecision.BLOCK
    assert resp.rejection_reason is not None

    # F6: Assert that failed audit persistence NEVER produces audit_status="complete"
    assert resp.audit_record is not None
    assert resp.audit_record.metadata.get("audit_status") != "complete"
    assert resp.audit_record.metadata.get("audit_status") == "incomplete"
    assert resp.audit_record.metadata.get("persistence_status") == "failed"

    # F3: Assert that the provenance record in the ledger was not mutated or invalidated
    ledger = gw.provenance_engine.get_ledger()
    assert len(ledger) > 0
    prov_rec = ledger[-1]
    assert prov_rec.record_id == resp.audit_record.provenance_record_id
    assert prov_rec.metadata.get("connector_id") == "unregistered_conn"
    assert prov_rec.signature is not None


@pytest.mark.anyio
async def test_6_sensitive_info_never_in_fallback_logs_or_response(mock_gateway):
    """Scenario 6 (F5): Sensitive information never appears in fallback logs or response.
    Directly captures logs from gateway logger because logger propagation is disabled.
    """
    import io
    from core.connectors.gateway import logger as gw_logger

    gw = mock_gateway
    secret_key = "sk-live-CRITICAL_LEAK_KEY_12345678"

    # Secret broker crashes with exception mentioning the key
    gw.secret_broker.scrub_text.side_effect = Exception(f"Scrubber exploded on key: {secret_key}")

    ctx = GuardrailContext(agent_id="test_agent")
    reason = f"Access denied: invalid credential {secret_key}"

    # Directly attach handler to gw_logger to capture output even with propagate=False
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.setLevel(logging.DEBUG)
    gw_logger.addHandler(handler)
    try:
        resp = gw._reject(
            reason=reason,
            agent_id="test_agent",
            connector_id="conn_1",
            tool_name="tool_1",
            http_method="GET",
            endpoint="/path",
            start_time=0.0,
            context=ctx,
        )
    finally:
        gw_logger.removeHandler(handler)

    captured_logs = log_stream.getvalue()

    # Check that logs were actually captured directly from gateway logger
    assert len(captured_logs) > 0
    assert "Audit secret scrubbing failed" in captured_logs
    assert "GATEWAY BLOCKED" in captured_logs

    # Check response
    assert resp.allowed is False
    assert secret_key not in resp.rejection_reason
    assert secret_key not in str(resp.model_dump())
    assert resp.rejection_reason == "Request rejected; audit details unavailable."

    # Check that secret and scrubber exception text are absent from actual captured logs
    assert secret_key not in captured_logs
    assert "Scrubber exploded" not in captured_logs


@pytest.mark.anyio
async def test_7_external_operation_never_executed_when_audit_fails(mock_gateway):
    """Scenario 7: External operation is never executed when audit components fail."""
    gw = mock_gateway
    # Both secret broker and provenance fail
    gw.secret_broker.scrub_text.side_effect = RuntimeError("Broker down")
    gw.provenance_engine.create_record = MagicMock(side_effect=RuntimeError("Provenance down"))

    # Register connector but deny permission to agent
    reg = ConnectorRegistration(
        connector_id="target_api",
        name="Target API",
        connector_type=ConnectorType.REST_API,
        base_url="https://api.target.com",
        allowed_endpoints=[EndpointDefinition(path="/run", methods=[HttpMethod.POST])],
    )
    gw.registry.register_connector(reg)

    # Request rejected because agent has no permission
    req = ExecutionRequest(
        agent_id="unauthorized_agent",
        connector_id="target_api",
        endpoint="/run",
        method=HttpMethod.POST,
    )

    resp = await gw.execute(req)

    # Must be rejected
    assert resp.allowed is False
    assert resp.security_decision == SecurityDecision.BLOCK

    # CRITICAL: External API execution was NEVER called!
    gw.api_connector.execute_request.assert_not_called()
    gw.mcp_connector.call_tool.assert_not_called()


@pytest.mark.anyio
async def test_8_existing_rejection_behavior_and_compatibility_intact(mock_gateway):
    """Scenario 8: Existing rejection behavior and response compatibility remain intact."""
    gw = mock_gateway
    ctx = GuardrailContext(agent_id="test_agent")

    resp = gw._reject(
        reason="Rate limit exceeded for agent 'test_agent'",
        agent_id="test_agent",
        connector_id="conn_1",
        tool_name="query_db",
        http_method="POST",
        endpoint="/query",
        start_time=0.0,
        context=ctx,
        status=ExecutionStatus.REJECTED,
    )

    assert resp.allowed is False
    assert resp.status == ExecutionStatus.REJECTED
    assert resp.security_decision == SecurityDecision.BLOCK
    assert resp.data is None
    assert resp.sanitized_data is None
    assert "Rate limit exceeded" in resp.rejection_reason
    assert resp.audit_record is not None
    assert resp.audit_record.execution_status == ExecutionStatus.REJECTED
    assert resp.audit_record.security_decision == SecurityDecision.BLOCK
    assert resp.audit_record.provenance_record_id is not None
    assert resp.audit_record.metadata.get("audit_status") == "complete"


@pytest.mark.anyio
async def test_9_upstream_execution_failure_sanitizes_logs_and_reason(mock_gateway):
    """Scenario 9 (F1 & F2): Upstream execution failure logs class name only (no raw exception or exc_info)
    and returns a fixed sanitized rejection reason.
    """
    import io
    from core.connectors.gateway import logger as gw_logger

    gw = mock_gateway

    # Register a valid connector and grant permission to reach execution stage
    reg = ConnectorRegistration(
        connector_id="exec_test_api",
        name="Exec Test API",
        connector_type=ConnectorType.REST_API,
        base_url="https://api.example.com",
        allowed_endpoints=[EndpointDefinition(path="/data", methods=[HttpMethod.GET])],
    )
    gw.registry.register_connector(reg)
    gw.permission_manager.grant_permission(
        AgentPermissionRule(
            rule_id="rule_1",
            agent_id="agent_exec",
            connector_id="exec_test_api",
            action=PermissionAction.ALLOW,
        )
    )

    # Configure mock secret broker and security engine to pass cleanly to execution stage
    gw.secret_broker.inject_auth.return_value = ({}, {})
    eval_result = MagicMock()
    eval_result.allowed = True
    eval_result.action = Action.ALLOW
    eval_result.findings = []
    eval_result.risk_assessment.overall_score = 0.0
    eval_result.risk_assessment.factors = []
    gw.security_engine.evaluate_request = AsyncMock(return_value=eval_result)
    gw.security_engine.inspect_output = AsyncMock(return_value=eval_result)

    # Simulate upstream execution error containing sensitive DB password and internal host
    sensitive_leak = "db_password=SUPER_SECRET_PASS_9988 at internal host 10.240.0.1"
    gw.api_connector.execute_request.side_effect = RuntimeError(f"Connection failed: {sensitive_leak}")

    # Directly capture gateway logger output
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.setLevel(logging.DEBUG)
    gw_logger.addHandler(handler)
    try:
        req = ExecutionRequest(
            agent_id="agent_exec",
            connector_id="exec_test_api",
            endpoint="/data",
            method=HttpMethod.GET,
        )
        resp = await gw.execute(req)
    finally:
        gw_logger.removeHandler(handler)

    captured_logs = log_stream.getvalue()

    # F2: Structured rejection response with fixed sanitized message
    assert resp.allowed is False
    assert resp.status == ExecutionStatus.FAILED
    assert resp.security_decision == SecurityDecision.BLOCK
    assert resp.rejection_reason == "External connector execution failed."
    assert sensitive_leak not in resp.rejection_reason
    assert "SUPER_SECRET_PASS_9988" not in str(resp.model_dump())

    # F1: Logs only the exception class name; no raw exception text and no traceback/exc_info
    assert "External connector execution failed: RuntimeError" in captured_logs
    assert sensitive_leak not in captured_logs
    assert "SUPER_SECRET_PASS_9988" not in captured_logs
    assert "10.240.0.1" not in captured_logs
    assert "Traceback" not in captured_logs


def test_10_outer_safety_net_handles_malformed_findings_and_status(mock_gateway):
    """Scenario 10 (F4): Outer safety net gracefully handles malformed findings and invalid status
    without raising an unsanitized exception, preserving fail-closed behavior.
    """
    gw = mock_gateway

    # Pass non-DetectionFinding objects and an invalid status type
    malformed_findings = [{"bad_key": "bad_value"}, 12345, "invalid_finding_string"]
    invalid_status = "NOT_A_VALID_STATUS_ENUM"

    resp = gw._reject(
        reason="Test rejection with malformed inputs",
        agent_id="agent_test",
        connector_id="conn_test",
        findings=malformed_findings,  # type: ignore
        status=invalid_status,  # type: ignore
    )

    assert resp.allowed is False
    assert resp.security_decision == SecurityDecision.BLOCK
    # All non-DetectionFinding instances must have been safely filtered
    assert resp.findings == []
    # Status safely falls back to a valid ExecutionStatus enum
    assert isinstance(resp.status, ExecutionStatus)
