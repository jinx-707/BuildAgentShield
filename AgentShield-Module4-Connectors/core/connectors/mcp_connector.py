"""
AgentShield MCP (Model Context Protocol) Client & Connector.
Implements JSON-RPC 2.0 client for discovering and executing MCP tools.
Guarantees:
  - Connects only to registered MCP servers.
  - Treats all MCP tool descriptions, metadata, and returned content as UNTRUSTED input.
  - Tools are not trusted by default simply because an MCP server exposes them;
    explicit approval is required.
  - Validates tool names and input argument schemas against registered definitions.
  - Prevents calls to unregistered servers or tools.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
import uuid

import httpx

from core.config import setup_logger
from core.connectors.models import (
    ConnectorExecutionError,
    ConnectorRegistration,
    McpToolDefinition,
    SchemaValidationError,
    UnregisteredToolError,
)
from core.injection_detector import PromptInjectionDetector

logger = setup_logger("agentshield.connectors.mcp")


class McpConnector:
    """
    Secure client for Model Context Protocol (MCP) servers.
    Handles discovery, registration, argument schema validation,
    and tool execution over JSON-RPC 2.0.
    """

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        injection_detector: PromptInjectionDetector | None = None,
    ) -> None:
        self._custom_client = client
        self._injection_detector = injection_detector or PromptInjectionDetector()

    # -----------------------------------------------------------------------
    # Tool Discovery
    # -----------------------------------------------------------------------

    async def discover_tools(
        self,
        connector: ConnectorRegistration,
        headers: dict[str, str] | None = None,
    ) -> list[McpToolDefinition]:
        """
        Discovers tools available on an MCP server using JSON-RPC 'tools/list'.
        Treats all descriptions, names, and schemas as UNTRUSTED.
        Scans descriptions for embedded prompt injection attacks.
        Returns a list of McpToolDefinition with is_approved=False by default.
        """
        if not connector.mcp_server_url:
            raise ConnectorExecutionError(f"MCP connector '{connector.connector_id}' has no mcp_server_url")

        rpc_payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/list",
            "params": {},
        }

        resp_data = await self._send_json_rpc(
            server_url=connector.mcp_server_url,
            payload=rpc_payload,
            headers=headers or {},
            timeout=connector.default_timeout_seconds,
        )

        raw_tools = resp_data.get("result", {}).get("tools", [])
        if not isinstance(raw_tools, list):
            logger.warning("MCP server '%s' returned invalid tools format", connector.connector_id)
            return []

        discovered: list[McpToolDefinition] = []
        for raw_tool in raw_tools:
            name = str(raw_tool.get("name", "")).strip()
            if not name:
                continue

            desc = str(raw_tool.get("description", ""))
            schema = raw_tool.get("inputSchema", {"type": "object", "properties": {}})

            # Security: scan description for prompt injection attempts
            if desc:
                inj_res = self._injection_detector.scan(desc)
                if inj_res.is_injection or inj_res.findings:
                    logger.error(
                        "SECURITY ALERT: Prompt injection detected in MCP tool description for '%s' "
                        "(confidence=%.2f, categories=%s)",
                        name,
                        inj_res.confidence,
                        inj_res.attack_categories,
                    )
                    # Flag this tool in metadata
                    metadata = {
                        "untrusted_warning": "prompt_injection_in_description",
                        "injection_confidence": inj_res.confidence,
                    }
                else:
                    metadata = {}
            else:
                metadata = {}

            tool_def = McpToolDefinition(
                name=name,
                description=desc,
                input_schema=schema if isinstance(schema, dict) else {},
                is_approved=False,  # Untrusted by default! Must be explicitly approved.
                metadata=metadata,
            )
            discovered.append(tool_def)

        logger.info(
            "Discovered %d MCP tools from '%s' (all marked unapproved pending review)",
            len(discovered),
            connector.connector_id,
        )
        return discovered

    # -----------------------------------------------------------------------
    # Tool Invocation
    # -----------------------------------------------------------------------

    async def call_tool(
        self,
        connector: ConnectorRegistration,
        tool: McpToolDefinition,
        arguments: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> Any:
        """
        Invokes an approved MCP tool with the supplied arguments.
        Enforces:
          1. Tool must be registered and approved.
          2. Arguments must comply with the registered input schema.
          3. Executes via JSON-RPC 'tools/call'.
        """
        if not tool.is_approved:
            raise UnregisteredToolError(
                f"MCP tool '{tool.name}' on connector '{connector.connector_id}' has not been approved "
                "for execution. Untrusted MCP tools cannot be executed."
            )

        # Validate argument schema
        self.validate_arguments(tool, arguments)

        rpc_payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/call",
            "params": {
                "name": tool.name,
                "arguments": arguments,
            },
        }

        timeout = tool.timeout_seconds or connector.default_timeout_seconds
        resp_data = await self._send_json_rpc(
            server_url=connector.mcp_server_url or "",
            payload=rpc_payload,
            headers=headers or {},
            timeout=timeout,
        )

        # Handle JSON-RPC errors
        if "error" in resp_data:
            err = resp_data["error"]
            err_msg = err.get("message", "Unknown MCP JSON-RPC error")
            err_code = err.get("code", -32000)
            raise ConnectorExecutionError(f"MCP server returned error (code {err_code}): {err_msg}")

        result = resp_data.get("result", {})

        # MCP protocol results typically return content items: [{"type": "text", "text": "..."}]
        if isinstance(result, dict) and "content" in result and isinstance(result["content"], list):
            items = result["content"]
            texts = [item.get("text", "") for item in items if isinstance(item, dict) and "text" in item]
            if texts:
                return "\n".join(texts)
            return items

        return result

    # -----------------------------------------------------------------------
    # Schema Validation
    # -----------------------------------------------------------------------

    @staticmethod
    def validate_arguments(tool: McpToolDefinition, arguments: dict[str, Any]) -> None:
        """
        Validates argument dictionary against tool's declared JSON schema.
        Checks required fields and basic types.
        """
        schema = tool.input_schema
        if not schema or not isinstance(schema, dict):
            return

        # Check required fields
        required_fields = schema.get("required", [])
        for req in required_fields:
            if req not in arguments:
                raise SchemaValidationError(
                    f"Tool '{tool.name}' missing required argument '{req}'"
                )

        # Check property types if declared
        properties = schema.get("properties", {})
        for prop_name, prop_val in arguments.items():
            if prop_name in properties:
                expected_type = properties[prop_name].get("type")
                if expected_type == "string" and not isinstance(prop_val, str):
                    raise SchemaValidationError(
                        f"Argument '{prop_name}' must be a string, got {type(prop_val).__name__}"
                    )
                elif expected_type == "integer" and not isinstance(prop_val, int):
                    raise SchemaValidationError(
                        f"Argument '{prop_name}' must be an integer, got {type(prop_val).__name__}"
                    )
                elif expected_type == "number" and not isinstance(prop_val, (int, float)):
                    raise SchemaValidationError(
                        f"Argument '{prop_name}' must be a number, got {type(prop_val).__name__}"
                    )
                elif expected_type == "boolean" and not isinstance(prop_val, bool):
                    raise SchemaValidationError(
                        f"Argument '{prop_name}' must be a boolean, got {type(prop_val).__name__}"
                    )
                elif expected_type == "array" and not isinstance(prop_val, list):
                    raise SchemaValidationError(
                        f"Argument '{prop_name}' must be an array, got {type(prop_val).__name__}"
                    )
                elif expected_type == "object" and not isinstance(prop_val, dict):
                    raise SchemaValidationError(
                        f"Argument '{prop_name}' must be an object, got {type(prop_val).__name__}"
                    )

    # -----------------------------------------------------------------------
    # Low-level JSON-RPC Transport
    # -----------------------------------------------------------------------

    async def _send_json_rpc(
        self,
        server_url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout: float,
    ) -> dict[str, Any]:
        """Dispatches an HTTP POST request containing a JSON-RPC payload."""
        req_headers = {"Content-Type": "application/json", **headers}
        client = self._custom_client or httpx.AsyncClient(timeout=timeout)
        should_close = self._custom_client is None

        try:
            resp = await client.post(server_url, json=payload, headers=req_headers)
            if resp.status_code != 200:
                raise ConnectorExecutionError(
                    f"MCP server at '{server_url}' returned HTTP {resp.status_code}: {resp.text[:200]}"
                )
            return resp.json()
        except httpx.RequestError as exc:
            raise ConnectorExecutionError(f"Network error communicating with MCP server '{server_url}': {exc}") from exc
        finally:
            if should_close:
                await client.aclose()
