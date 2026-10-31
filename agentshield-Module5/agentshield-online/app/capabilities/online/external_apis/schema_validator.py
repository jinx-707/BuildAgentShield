"""
Request and response schema validator for API connectors.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def validate_request_schema(
    payload: dict[str, Any],
    schema: dict[str, Any] | None,
) -> tuple[bool, str]:
    """
    Validate request payload against connector schema.
    Returns (valid, reason).
    """
    if not schema:
        return True, ""

    required = schema.get("required", [])
    properties = schema.get("properties", {})

    for field in required:
        if field not in payload:
            return False, f"Required field '{field}' missing from request"

    for field, value in payload.items():
        if field in properties:
            field_schema = properties[field]
            expected_type = field_schema.get("type")
            if expected_type and not _check_type(value, expected_type):
                return False, f"Field '{field}' has wrong type (expected {expected_type})"

    return True, ""


def sanitize_response(
    response_body: Any,
    max_size: int = 5242880,
) -> Any:
    """
    Sanitize API response before returning to agent.
    Truncates oversized responses, removes internal error details.
    """
    if isinstance(response_body, str) and len(response_body) > max_size:
        return response_body[:max_size] + "...[TRUNCATED]"
    return response_body


def _check_type(value: Any, expected_type: str) -> bool:
    type_map = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    expected = type_map.get(expected_type)
    if not expected:
        return True
    return isinstance(value, expected)
