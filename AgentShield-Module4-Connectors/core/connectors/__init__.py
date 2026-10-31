"""
AgentShield Module 4 — External APIs & MCP Security Gateway.
Modular runtime gateway protecting AI agents when interacting with external REST APIs
and Model Context Protocol (MCP) servers and tools.
"""

from core.connectors.api_connector import RestApiConnector
from core.connectors.gateway import SecurityGateway
from core.connectors.mcp_connector import McpConnector
from core.connectors.models import (
    AgentPermissionRule,
    AuthenticationConfig,
    AuthType,
    ConnectorAuditRecord,
    ConnectorError,
    ConnectorExecutionError,
    ConnectorRegistration,
    ConnectorType,
    EndpointDefinition,
    ExecutionRequest,
    ExecutionResponse,
    ExecutionStatus,
    GatewaySecurityViolationError,
    HttpMethod,
    McpToolDefinition,
    PermissionAction,
    PermissionDeniedError,
    PermissionEscalationError,
    PermissionScope,
    RateLimitExceededError,
    SchemaValidationError,
    SecurityDecision,
    SSRFSecurityError,
    UnregisteredConnectorError,
    UnregisteredEndpointError,
    UnregisteredToolError,
)
from core.connectors.permissions import PermissionManager
from core.connectors.rate_limiter import RateLimiter
from core.connectors.registry import ConnectorRegistry
from core.connectors.router import create_connectors_app, get_gateway, router, set_gateway
from core.connectors.secret_broker import SecretBroker

__all__ = [
    # Gateway & Managers
    "SecurityGateway",
    "ConnectorRegistry",
    "PermissionManager",
    "SecretBroker",
    "RateLimiter",
    "RestApiConnector",
    "McpConnector",
    # FastAPI
    "router",
    "create_connectors_app",
    "get_gateway",
    "set_gateway",
    # Enums
    "ConnectorType",
    "HttpMethod",
    "AuthType",
    "PermissionAction",
    "PermissionScope",
    "SecurityDecision",
    "ExecutionStatus",
    # Models
    "AuthenticationConfig",
    "EndpointDefinition",
    "McpToolDefinition",
    "ConnectorRegistration",
    "AgentPermissionRule",
    "ExecutionRequest",
    "ExecutionResponse",
    "ConnectorAuditRecord",
    # Exceptions
    "ConnectorError",
    "UnregisteredConnectorError",
    "UnregisteredEndpointError",
    "UnregisteredToolError",
    "PermissionDeniedError",
    "PermissionEscalationError",
    "SSRFSecurityError",
    "RateLimitExceededError",
    "SchemaValidationError",
    "GatewaySecurityViolationError",
    "ConnectorExecutionError",
]
