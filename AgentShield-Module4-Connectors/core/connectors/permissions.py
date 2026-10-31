"""
AgentShield Per-Agent Tool Permissions System.
Server-side authorization engine governing which agents can access which connectors,
methods, and tools. Strictly prevents privilege escalation via argument tampering.
"""

from __future__ import annotations

import threading
from typing import Any

from core.config import setup_logger
from core.connectors.models import (
    AgentPermissionRule,
    HttpMethod,
    PermissionAction,
    PermissionEscalationError,
    PermissionScope,
)

logger = setup_logger("agentshield.connectors.permissions")


class PermissionManager:
    """
    Authoritative server-side permission registry and enforcer.
    Guarantees:
      - Default-deny architecture for all agent-tool interactions.
      - Never trusts client-supplied credentials, identities, or permission claims.
      - Restricts HTTP methods according to defined scope (e.g. READ_ONLY blocks DELETE).
      - Intercepts and blocks privilege escalation attacks embedded in arguments.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Key: (agent_id, connector_id) -> AgentPermissionRule
        self._rules: dict[tuple[str, str], AgentPermissionRule] = {}

    def grant_permission(self, rule: AgentPermissionRule) -> None:
        """Registers or updates a per-agent permission policy."""
        with self._lock:
            key = (rule.agent_id, rule.connector_id)
            self._rules[key] = rule
            logger.info(
                "Permission configured: agent='%s', connector='%s', action='%s', scope='%s'",
                rule.agent_id,
                rule.connector_id,
                rule.action.value,
                rule.scope.value,
            )

    def revoke_permission(self, agent_id: str, connector_id: str) -> bool:
        """Revokes a permission rule, restoring default-deny."""
        with self._lock:
            key = (agent_id, connector_id)
            if key in self._rules:
                del self._rules[key]
                logger.info("Revoked permission for agent='%s' on connector='%s'", agent_id, connector_id)
                return True
            return False

    def get_permission(self, agent_id: str, connector_id: str) -> AgentPermissionRule | None:
        """Retrieves rule for an agent and connector, falling back to wildcard agent '*'."""
        with self._lock:
            rule = self._rules.get((agent_id, connector_id))
            if rule is None:
                # Check wildcard agent
                rule = self._rules.get(("*", connector_id))
            return rule

    def check_permission(
        self,
        agent_id: str,
        connector_id: str,
        method: HttpMethod | str | None = None,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
    ) -> tuple[bool, str | None]:
        """
        Server-side validation of whether an agent is permitted to perform the operation.
        Returns:
            (allowed: bool, rejection_reason: str | None)
        """
        with self._lock:
            rule = self.get_permission(agent_id, connector_id)

            # 1. Default-deny if no rule found
            if rule is None:
                reason = f"Access denied: No permission rule granted for agent '{agent_id}' on connector '{connector_id}'"
                logger.warning(reason)
                return False, reason

            # 2. Explicit DENY action check
            if rule.action == PermissionAction.DENY:
                reason = f"Access denied: Policy explicitly denies agent '{agent_id}' access to connector '{connector_id}'"
                logger.warning(reason)
                return False, reason

            # 3. HTTP Method & Scope validation (for REST APIs)
            if method is not None:
                norm_method = HttpMethod(method) if isinstance(method, str) else method

                # Check explicitly denied methods
                if norm_method in rule.denied_methods:
                    reason = f"Access denied: Method '{norm_method.value}' is explicitly denied for agent '{agent_id}'"
                    logger.warning(reason)
                    return False, reason

                # Check scope constraints
                if rule.scope == PermissionScope.READ_ONLY:
                    if norm_method not in (HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS):
                        reason = (
                            f"Access denied: READ_ONLY scope prohibits mutating method '{norm_method.value}' "
                            f"on connector '{connector_id}'"
                        )
                        logger.warning(reason)
                        return False, reason

                elif rule.scope == PermissionScope.READ_WRITE:
                    if norm_method == HttpMethod.DELETE:
                        reason = (
                            f"Access denied: READ_WRITE scope does not permit destructive DELETE "
                            f"on connector '{connector_id}'"
                        )
                        logger.warning(reason)
                        return False, reason

                elif rule.scope == PermissionScope.CUSTOM:
                    if rule.allowed_methods is not None and norm_method not in rule.allowed_methods:
                        reason = (
                            f"Access denied: Method '{norm_method.value}' not in custom allowed methods "
                            f"for agent '{agent_id}' on '{connector_id}'"
                        )
                        logger.warning(reason)
                        return False, reason

            # 4. Tool Name validation (for MCP and named tools)
            if tool_name is not None:
                if tool_name in rule.denied_tools:
                    reason = f"Access denied: Tool '{tool_name}' is explicitly denied for agent '{agent_id}'"
                    logger.warning(reason)
                    return False, reason

                if rule.allowed_tools is not None and tool_name not in rule.allowed_tools:
                    reason = (
                        f"Access denied: Tool '{tool_name}' is not in permitted tool list "
                        f"for agent '{agent_id}' on connector '{connector_id}'"
                    )
                    logger.warning(reason)
                    return False, reason

            # 5. Argument Tampering & Privilege Escalation Detection
            if arguments:
                escalation_err = self._detect_argument_escalation(rule, arguments)
                if escalation_err:
                    logger.error(
                        "SECURITY ALERT: Privilege escalation attempt by agent '%s' on '%s': %s",
                        agent_id,
                        connector_id,
                        escalation_err,
                    )
                    return False, escalation_err

            return True, None

    def _detect_argument_escalation(
        self,
        rule: AgentPermissionRule,
        arguments: dict[str, Any],
    ) -> str | None:
        """
        Deeply inspects arguments to prevent an agent from tampering with parameters
        to escalate privileges (e.g. modifying role=admin, sudo=true, internal_override=1).
        """
        # A. Check forbidden argument keys
        for key in rule.forbidden_argument_keys:
            if self._key_exists_recursive(arguments, key):
                return f"Privilege escalation blocked: unauthorized parameter '{key}' present in arguments"

        # B. Check explicit argument value constraints
        for constrained_key, allowed_value in rule.argument_constraints.items():
            if constrained_key in arguments:
                actual = arguments[constrained_key]
                if isinstance(allowed_value, list):
                    if actual not in allowed_value:
                        return (
                            f"Privilege escalation blocked: parameter '{constrained_key}={actual}' "
                            f"violates allowed values {allowed_value}"
                        )
                elif actual != allowed_value:
                    return (
                        f"Privilege escalation blocked: parameter '{constrained_key}={actual}' "
                        f"does not match required value '{allowed_value}'"
                    )

        # C. Check for embedded role escalation strings
        escalation_patterns = [
            ('"role": "admin"', "role:admin injection"),
            ('"is_admin": true', "admin flag escalation"),
            ('"superuser": true', "superuser flag escalation"),
            ('"grant": "all"', "grant:all escalation"),
            ('"permissions": ["*"]', "wildcard permission escalation"),
        ]
        args_str = str(arguments).lower()
        for pat, desc in escalation_patterns:
            if pat.lower() in args_str:
                return f"Privilege escalation blocked: {desc} detected in arguments"

        return None

    def _key_exists_recursive(self, data: Any, target_key: str) -> bool:
        """Recursively checks if target_key exists in nested dicts or lists."""
        if isinstance(data, dict):
            for k, v in data.items():
                if str(k).lower() == target_key.lower():
                    return True
                if self._key_exists_recursive(v, target_key):
                    return True
        elif isinstance(data, list):
            for item in data:
                if self._key_exists_recursive(item, target_key):
                    return True
        return False

    def clear(self) -> None:
        """Clears all permission rules."""
        with self._lock:
            self._rules.clear()
