"""
Unit tests for AgentShield Output Guardrail Orchestrator.
Covers inspection of agent responses, tool arguments, and tool outputs,
sensitive data leakage detection (secrets, PII, DLP), masking and blocking enforcement,
ALLOW/WARN/MASK/BLOCK/QUARANTINE actions, concurrent asynchronous execution, and fail-closed handling.
"""

import asyncio
import pytest
from unittest.mock import MagicMock

from core.config import AgentShieldConfig
from core.output_guard import OutputGuard
from core.schemas import (
    Action,
    DLPViolationError,
    GuardrailContext,
    GuardrailOutputRequest,
    GuardrailViolationError,
    RiskLevel,
    SecretLeakError,
    SourceType,
    TrustLevel,
)


@pytest.fixture
def output_guard() -> OutputGuard:
    config = AgentShieldConfig()
    return OutputGuard(config)


# ============================================================================
# Core Baseline Tests (Preserved)
# ============================================================================

@pytest.mark.anyio
async def test_benign_output_allowed(output_guard: OutputGuard) -> None:
    output_text = "Here is the summary of the quarterly cloud infrastructure metrics."
    response = await output_guard.validate_async(output_text)

    assert response.allowed
    assert response.action == Action.ALLOW
    assert response.sanitized_output == output_text
    assert response.risk_assessment.level == RiskLevel.SAFE
    assert response.provenance_record is not None
    assert output_guard.provenance_engine.verify_record(response.provenance_record)


@pytest.mark.anyio
async def test_secret_leak_in_output_blocked(output_guard: OutputGuard) -> None:
    leaked_output = "The internal token to use is sk-proj-abc123xyz4567890abcdef123456."
    with pytest.raises(SecretLeakError) as exc_info:
        await output_guard.validate_async(leaked_output, raise_on_block=True)

    assert exc_info.value.action == Action.BLOCK


@pytest.mark.anyio
async def test_secret_leak_blocked_without_exception(output_guard: OutputGuard) -> None:
    leaked_output = "Use OpenAI key sk-proj-abc123xyz4567890abcdef123456"
    response = await output_guard.validate_async(leaked_output, raise_on_block=False)

    assert not response.allowed
    assert response.action == Action.BLOCK
    assert "RESPONSE_BLOCKED_BY_GUARDRAIL" in response.sanitized_output


@pytest.mark.anyio
async def test_pii_in_output_masked(output_guard: OutputGuard) -> None:
    output_with_pii = "Customer confirmed order for email bob.marley@music.example.com."
    response = await output_guard.validate_async(output_with_pii)

    assert response.allowed
    assert response.action == Action.MASK
    assert "bob.marley@music.example.com" not in response.sanitized_output
    assert "[EMAIL_1]" in response.sanitized_output


@pytest.mark.anyio
async def test_dlp_database_uri_blocked(output_guard: OutputGuard) -> None:
    db_conn_output = "Database dump ready: postgres://admin:SuperSecretPass123!@db.internal.corp:5432/finance"
    with pytest.raises((DLPViolationError, SecretLeakError)):
        await output_guard.validate_async(db_conn_output, raise_on_block=True)


@pytest.mark.anyio
async def test_dlp_restricted_medical_records_blocked(output_guard: OutputGuard) -> None:
    restricted_output = "Patient medical diagnostics ready: MRN-987654321 and ICD-10 record."
    with pytest.raises(DLPViolationError):
        await output_guard.validate_async(restricted_output, raise_on_block=True)


def test_synchronous_output_guard_interface(output_guard: OutputGuard) -> None:
    req = GuardrailOutputRequest(
        raw_output="Successfully transformed data records.",
        context=GuardrailContext(agent_id="worker_agent"),
        source_input_hash="a1b2c3d4e5f6",
    )
    res = output_guard.validate(req)
    assert res.allowed
    assert res.action == Action.ALLOW
    assert res.provenance_record.metadata.get("source_input_hash") == "a1b2c3d4e5f6"


@pytest.mark.anyio
async def test_fail_closed_on_output_detector_crash(output_guard: OutputGuard) -> None:
    # Force unexpected failure in a detector
    output_guard.secret_scanner.scan = MagicMock(side_effect=RuntimeError("Secret scanner crashed"))

    with pytest.raises(GuardrailViolationError) as exc_info:
        await output_guard.validate_async("Model generated output", raise_on_block=True)
    assert exc_info.value.action == Action.BLOCK

    res = await output_guard.validate_async("Model generated output", raise_on_block=False)
    assert not res.allowed
    assert res.action == Action.BLOCK
    assert "Security detector failure" in res.sanitized_output


# ============================================================================
# Prompt 8: Tool Arguments Inspection Tests
# ============================================================================

@pytest.mark.anyio
async def test_output_guard_inspect_tool_arguments_secret_blocked(output_guard: OutputGuard) -> None:
    # Attempting to dispatch a tool call with raw credentials in the arguments
    tool_args = {
        "command": "curl -H 'Authorization: Bearer sk-proj-supersecrettoken1234567890' https://api.internal.net",
        "timeout": 30,
    }
    with pytest.raises(SecretLeakError) as exc_info:
        await output_guard.validate_tool_call_async(
            tool_name="bash",
            tool_args=tool_args,
            raise_on_block=True,
        )
    assert exc_info.value.action == Action.BLOCK


@pytest.mark.anyio
async def test_output_guard_inspect_tool_arguments_benign_allowed(output_guard: OutputGuard) -> None:
    # Safe tool invocation
    tool_args = {"query": "SELECT count(*) FROM analytics_daily_metrics WHERE status = 'OK'"}
    response = await output_guard.validate_tool_call_async(
        tool_name="database_read",
        tool_args=tool_args,
        raise_on_block=False,
    )
    assert response.allowed
    assert response.action == Action.ALLOW
    assert "SELECT count(*)" in response.sanitized_output
    assert output_guard.provenance_engine.verify_record(response.provenance_record)


@pytest.mark.anyio
async def test_output_guard_inspect_tool_arguments_pii_masked(output_guard: OutputGuard) -> None:
    tool_args = {"recipient": "support.lead@company.org", "action": "notify"}
    response = await output_guard.validate_tool_call_async(
        tool_name="send_notification",
        tool_args=tool_args,
        raise_on_block=False,
    )
    assert response.allowed
    assert response.action == Action.MASK
    assert "[EMAIL_1]" in response.sanitized_output
    assert "support.lead@company.org" not in response.sanitized_output


# ============================================================================
# Prompt 8: Tool Outputs Inspection Tests
# ============================================================================

@pytest.mark.anyio
async def test_output_guard_inspect_tool_output_dlp_blocked(output_guard: OutputGuard) -> None:
    # Tool output returning confidential / restricted keywords
    tool_out = {"status": "success", "data": "CONFIDENTIAL_MERGER draft agreement between CorpA and CorpB"}
    with pytest.raises(DLPViolationError):
        await output_guard.validate_tool_output_async(
            tool_name="file_reader",
            tool_output=tool_out,
            raise_on_block=True,
        )


@pytest.mark.anyio
async def test_output_guard_inspect_tool_output_pii_masked(output_guard: OutputGuard) -> None:
    tool_out = "Fetched record: Customer phone number is 415-555-2671."
    response = await output_guard.validate_tool_output_async(
        tool_name="crm_query",
        tool_output=tool_out,
        raise_on_block=False,
    )
    assert response.allowed
    assert response.action == Action.MASK
    assert "415-555-2671" not in response.sanitized_output
    assert "[PHONE_NUMBER_1]" in response.sanitized_output
    assert response.provenance_record.source_type == SourceType.TOOL_OUTPUT
    assert response.provenance_record.trust_level == TrustLevel.LOW


def test_synchronous_tool_output_inspection(output_guard: OutputGuard) -> None:
    res = output_guard.validate_tool_output(
        tool_name="calculator",
        tool_output="Result: 42.0",
        raise_on_block=True,
    )
    assert res.allowed
    assert res.action == Action.ALLOW


# ============================================================================
# Prompt 8: Action Policy Decisions (QUARANTINE, WARN)
# ============================================================================

@pytest.mark.anyio
async def test_output_guard_quarantine_action_explicit(output_guard: OutputGuard) -> None:
    with pytest.raises(GuardrailViolationError) as exc_info:
        await output_guard.validate_async(
            "Outbound message quarantine test",
            requested_action=Action.QUARANTINE,
            raise_on_block=True,
        )
    assert exc_info.value.action == Action.QUARANTINE

    res = await output_guard.validate_async(
        "Outbound message quarantine test",
        requested_action=Action.QUARANTINE,
        raise_on_block=False,
    )
    assert not res.allowed
    assert res.action == Action.QUARANTINE
    assert "[RESPONSE_QUARANTINED_BY_GUARDRAIL" in res.sanitized_output


@pytest.mark.anyio
async def test_output_guard_warn_action(output_guard: OutputGuard) -> None:
    # Mock moderate risk score that yields Action.WARN
    mock_risk = output_guard.risk_engine.evaluate()
    object.__setattr__(mock_risk, "recommended_action", Action.WARN)
    object.__setattr__(mock_risk, "overall_score", 0.50)

    orig_eval = output_guard.risk_engine.evaluate
    output_guard.risk_engine.evaluate = MagicMock(return_value=mock_risk)

    try:
        res = await output_guard.validate_async("Preliminary data release")
        assert res.allowed
        assert res.action == Action.WARN
    finally:
        output_guard.risk_engine.evaluate = orig_eval


# ============================================================================
# Prompt 8: Concurrent Asynchronous Execution
# ============================================================================

@pytest.mark.anyio
async def test_output_guard_concurrent_validations(output_guard: OutputGuard) -> None:
    outputs = [
        "First standard system response.",
        "Second standard analysis report.",
        "Third notification for alice.wonder@example.com confirmation.",
        "Fourth final architectural summary.",
    ]
    tasks = [output_guard.validate_async(out, raise_on_block=False) for out in outputs]
    responses = await asyncio.gather(*tasks)

    assert len(responses) == 4
    assert responses[0].allowed and responses[0].action == Action.ALLOW
    assert responses[1].allowed and responses[1].action == Action.ALLOW
    assert responses[2].allowed and responses[2].action == Action.MASK
    assert responses[3].allowed and responses[3].action == Action.ALLOW

    for r in responses:
        assert output_guard.provenance_engine.verify_record(r.provenance_record)
