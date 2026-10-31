"""
MCP tool argument validator.
Validates arguments against the tool's input schema before invocation.
Also inspects responses as untrusted content.
"""
from __future__ import annotations

import logging
from typing import Any

from app.capabilities.online.mcp.tool_registry import ToolSchema
from app.core.exceptions import MCPToolValidationError

logger = logging.getLogger(__name__)


def validate_tool_arguments(
    schema: ToolSchema,
    arguments: dict[str, Any],
) -> tuple[bool, str]:
    """
    Validate tool call arguments against input schema.
    Returns (valid, reason).
    """
    input_schema = schema.input_schema
    if not input_schema:
        return True, ""

    required = input_schema.get("required", [])
    properties = input_schema.get("properties", {})

    for field in required:
        if field not in arguments:
            return False, f"Required argument '{field}' missing"

    for key, value in arguments.items():
        if key in properties:
            prop = properties[key]
            expected_type = prop.get("type")
            if expected_type and not _type_matches(value, expected_type):
                return False, (
                    f"Argument '{key}' has wrong type "
                    f"(expected {expected_type}, got {type(value).__name__})"
                )
            # Check max string length to prevent injection via oversized args
            if isinstance(value, str) and len(value) > 10000:
                return False, (
                    f"Argument '{key}' exceeds maximum length (10000 chars)"
                )

    return True, ""


def _type_matches(value: Any, expected: str) -> bool:
    m = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
        "null": type(None),
    }
    t = m.get(expected)
    return isinstance(value, t) if t else True


def sanitize_tool_result(result: Any, max_size: int = 102400) -> Any:
    """
    Sanitize a MCP tool result before returning to agent.
    Treats all MCP responses as untrusted.
    """
    if isinstance(result, str):
        if len(result) > max_size:
            return result[:max_size] + "...[TRUNCATED - untrusted MCP response]"
        return result
    if isinstance(result, dict):
        # Recursively sanitize string values
        return {k: sanitize_tool_result(v, max_size) for k, v in result.items()}
    if isinstance(result, list):
        return [sanitize_tool_result(item, max_size) for item in result[:100]]
    return result
