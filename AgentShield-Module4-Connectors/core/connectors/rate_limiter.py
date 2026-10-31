"""
AgentShield Hierarchical Rate Limiter.
Enforces multi-tier rate limiting:
  1. Per-Agent limits
  2. Per-Connector limits
  3. Per-Tool limits
Thread-safe sliding window implementation.
"""

from __future__ import annotations

from collections import defaultdict
import threading
import time
from typing import Any

from core.config import setup_logger

logger = setup_logger("agentshield.connectors.rate_limiter")


class RateLimitRule:
    """Configuration for a rate limit tier."""
    def __init__(self, max_requests: int, window_seconds: float = 60.0) -> None:
        self.max_requests = max(1, max_requests)
        self.window_seconds = max(0.1, window_seconds)


class RateLimiter:
    """
    Sliding window rate limiter enforcing multi-level quotas across
    agent, connector, and tool boundaries.
    """

    def __init__(
        self,
        default_agent_rpm: int = 120,
        default_connector_rpm: int = 300,
        default_tool_rpm: int = 60,
    ) -> None:
        self._lock = threading.RLock()
        self.default_agent_rule = RateLimitRule(default_agent_rpm, 60.0)
        self.default_connector_rule = RateLimitRule(default_connector_rpm, 60.0)
        self.default_tool_rule = RateLimitRule(default_tool_rpm, 60.0)

        # Custom rules
        self._agent_rules: dict[str, RateLimitRule] = {}
        self._connector_rules: dict[str, RateLimitRule] = {}
        self._tool_rules: dict[tuple[str, str], RateLimitRule] = {}

        # History queues: key -> list of timestamp floats
        self._agent_history: dict[str, list[float]] = defaultdict(list)
        self._connector_history: dict[str, list[float]] = defaultdict(list)
        self._tool_history: dict[tuple[str, str], list[float]] = defaultdict(list)

    def set_agent_limit(self, agent_id: str, max_requests: int, window_seconds: float = 60.0) -> None:
        """Sets custom rate limit for a specific agent."""
        with self._lock:
            self._agent_rules[agent_id] = RateLimitRule(max_requests, window_seconds)

    def set_connector_limit(self, connector_id: str, max_requests: int, window_seconds: float = 60.0) -> None:
        """Sets custom rate limit for an entire connector."""
        with self._lock:
            self._connector_rules[connector_id] = RateLimitRule(max_requests, window_seconds)

    def set_tool_limit(
        self,
        connector_id: str,
        tool_name: str,
        max_requests: int,
        window_seconds: float = 60.0,
    ) -> None:
        """Sets custom rate limit for a specific tool on a connector."""
        with self._lock:
            self._tool_rules[(connector_id, tool_name)] = RateLimitRule(max_requests, window_seconds)

    def check_rate_limit(
        self,
        agent_id: str,
        connector_id: str,
        tool_name: str | None = None,
    ) -> tuple[bool, str | None]:
        """
        Validates whether the requested call complies with all rate limit tiers.
        If compliant, records the request timestamp and returns (True, None).
        If non-compliant, rejects the request and returns (False, error_message).
        """
        now = time.time()
        with self._lock:
            # 1. Check Agent Limit
            agent_rule = self._agent_rules.get(agent_id, self.default_agent_rule)
            agent_window_start = now - agent_rule.window_seconds
            agent_reqs = [t for t in self._agent_history[agent_id] if t > agent_window_start]
            if len(agent_reqs) >= agent_rule.max_requests:
                msg = (
                    f"Rate limit exceeded: Agent '{agent_id}' exceeded limit of "
                    f"{agent_rule.max_requests} requests per {agent_rule.window_seconds}s"
                )
                logger.warning(msg)
                return False, msg

            # 2. Check Connector Limit
            conn_rule = self._connector_rules.get(connector_id, self.default_connector_rule)
            conn_window_start = now - conn_rule.window_seconds
            conn_reqs = [t for t in self._connector_history[connector_id] if t > conn_window_start]
            if len(conn_reqs) >= conn_rule.max_requests:
                msg = (
                    f"Rate limit exceeded: Connector '{connector_id}' exceeded limit of "
                    f"{conn_rule.max_requests} requests per {conn_rule.window_seconds}s"
                )
                logger.warning(msg)
                return False, msg

            # 3. Check Tool Limit (if applicable)
            if tool_name:
                tool_key = (connector_id, tool_name)
                tool_rule = self._tool_rules.get(tool_key, self.default_tool_rule)
                tool_window_start = now - tool_rule.window_seconds
                tool_reqs = [t for t in self._tool_history[tool_key] if t > tool_window_start]
                if len(tool_reqs) >= tool_rule.max_requests:
                    msg = (
                        f"Rate limit exceeded: Tool '{tool_name}' on connector '{connector_id}' "
                        f"exceeded limit of {tool_rule.max_requests} requests per {tool_rule.window_seconds}s"
                    )
                    logger.warning(msg)
                    return False, msg

            # All passed! Record timestamps in sliding windows
            agent_reqs.append(now)
            self._agent_history[agent_id] = agent_reqs

            conn_reqs.append(now)
            self._connector_history[connector_id] = conn_reqs

            if tool_name:
                tool_key = (connector_id, tool_name)
                tool_reqs.append(now)
                self._tool_history[tool_key] = tool_reqs

            return True, None

    def reset(self) -> None:
        """Clears all historical timestamps and custom rules."""
        with self._lock:
            self._agent_history.clear()
            self._connector_history.clear()
            self._tool_history.clear()
            self._agent_rules.clear()
            self._connector_rules.clear()
            self._tool_rules.clear()
