"""
Unit Tests for AgentShield Hierarchical Rate Limiter.
Tests:
  - Per-Agent rate limiting
  - Per-Connector rate limiting
  - Per-Tool rate limiting
  - Multi-tier quota enforcement
  - Sliding window expiration & reset
"""

import time
import pytest

from core.connectors.rate_limiter import RateLimiter


@pytest.fixture
def limiter():
    return RateLimiter()


def test_agent_rate_limiting(limiter):
    """Enforces per-agent call quotas within sliding window."""
    limiter.set_agent_limit("agent_x", max_requests=2, window_seconds=10.0)

    # 1st and 2nd allowed
    ok1, _ = limiter.check_rate_limit(agent_id="agent_x", connector_id="conn_1")
    assert ok1 is True
    ok2, _ = limiter.check_rate_limit(agent_id="agent_x", connector_id="conn_1")
    assert ok2 is True

    # 3rd rejected
    ok3, msg3 = limiter.check_rate_limit(agent_id="agent_x", connector_id="conn_1")
    assert ok3 is False
    assert "Agent 'agent_x' exceeded limit of 2 requests" in msg3


def test_connector_rate_limiting(limiter):
    """Enforces connector-wide quota across all agents."""
    limiter.set_connector_limit("shared_api", max_requests=2, window_seconds=10.0)

    ok1, _ = limiter.check_rate_limit("agent_1", "shared_api")
    assert ok1 is True
    ok2, _ = limiter.check_rate_limit("agent_2", "shared_api")
    assert ok2 is True

    # Connector quota exhausted even though agent_3 has not made any calls
    ok3, msg3 = limiter.check_rate_limit("agent_3", "shared_api")
    assert ok3 is False
    assert "Connector 'shared_api' exceeded limit of 2 requests" in msg3


def test_tool_rate_limiting(limiter):
    """Enforces specific rate limits on expensive tools."""
    limiter.set_tool_limit("ai_service", "heavy_inference", max_requests=1, window_seconds=10.0)

    ok1, _ = limiter.check_rate_limit("agent_1", "ai_service", tool_name="heavy_inference")
    assert ok1 is True

    ok2, msg2 = limiter.check_rate_limit("agent_1", "ai_service", tool_name="heavy_inference")
    assert ok2 is False
    assert "Tool 'heavy_inference' on connector 'ai_service' exceeded limit" in msg2

    # Different tool on same connector is unaffected
    ok_other, _ = limiter.check_rate_limit("agent_1", "ai_service", tool_name="light_tool")
    assert ok_other is True


def test_sliding_window_expiration(limiter):
    """Old requests outside the time window expire and release quota."""
    # Window of 0.2 seconds for fast test
    limiter.set_agent_limit("fast_agent", max_requests=1, window_seconds=0.2)

    ok1, _ = limiter.check_rate_limit("fast_agent", "conn_1")
    assert ok1 is True

    # Immediately rejected
    ok2, _ = limiter.check_rate_limit("fast_agent", "conn_1")
    assert ok2 is False

    # Wait for window to expire
    time.sleep(0.25)

    # Allowed again
    ok3, _ = limiter.check_rate_limit("fast_agent", "conn_1")
    assert ok3 is True


def test_reset(limiter):
    """Reset clears all historical quotas."""
    limiter.set_agent_limit("test_agent", max_requests=1, window_seconds=60.0)
    limiter.check_rate_limit("test_agent", "conn_1")
    assert limiter.check_rate_limit("test_agent", "conn_1")[0] is False

    limiter.reset()
    # After reset, uses default quota
    assert limiter.check_rate_limit("test_agent", "conn_1")[0] is True
