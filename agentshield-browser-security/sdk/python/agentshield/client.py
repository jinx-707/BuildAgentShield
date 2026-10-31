"""AgentShield Python SDK for AI agent integration.

Provides a client that authenticates with the AgentShield API and mediates AI
agent actions (navigate, browser actions, tool calls) through the AgentShield
enforcement architecture: Policy Engine -> Browser Worker -> Egress Proxy.

Agent credentials (agent_id + secret) are held by the caller; the secret is
never logged or transmitted except in the authenticated request to AgentShield.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


class AgentShieldError(Exception):
    """Raised when the AgentShield API returns an error."""


class AgentShieldAuthError(AgentShieldError):
    """Raised when agent authentication fails."""


class AgentShieldClient:
    """Client for the AgentShield AI Agent Security API.

    Parameters
    ----------
    base_url:
        Base URL of the AgentShield API (e.g. http://localhost:8000).
    agent_id:
        Agent identifier issued by AgentShield.
    secret:
        Agent secret issued by AgentShield. Kept in memory only; never logged.
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        *,
        base_url: str,
        agent_id: str,
        secret: str,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._agent_id = agent_id
        self._secret = secret
        self._client = httpx.Client(base_url=self._base_url, timeout=timeout)
        self._access_token: str | None = None
        self._organization_id: str | None = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> dict[str, Any]:
        """Authenticate the agent and cache the access token.

        The secret is sent once to /v1/ai-agent/authenticate and is not
        retained beyond the returned token.
        """
        resp = self._client.post(
            "/v1/ai-agent/authenticate",
            json={"agent_id": self._agent_id, "secret": self._secret},
        )
        if resp.status_code == 401:
            raise AgentShieldAuthError("invalid agent id or secret")
        if resp.status_code >= 400:
            raise AgentShieldError(
                f"authentication failed: {resp.status_code} {resp.text}"
            )
        data = resp.json()
        self._access_token = data.get("access_token") or data.get("token")
        self._organization_id = data.get("organization_id")
        return {
            "agent_id": data.get("agent_id"),
            "organization_id": self._organization_id,
            "name": data.get("name"),
        }

    @property
    def organization_id(self) -> str | None:
        return self._organization_id

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        return headers

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._access_token is None:
            self.authenticate()
        resp = self._client.post(path, json=payload, headers=self._headers())
        if resp.status_code == 401:
            # Token may have expired; re-authenticate once.
            self.authenticate()
            resp = self._client.post(path, json=payload, headers=self._headers())
        if resp.status_code >= 400:
            raise AgentShieldError(
                f"request failed: {resp.status_code} {resp.text}"
            )
        return resp.json()

    # ------------------------------------------------------------------
    # Agent actions (mediated through AgentShield enforcement)
    # ------------------------------------------------------------------

    def navigate(
        self,
        *,
        url: str,
        session_id: str | None = None,
        wait_until: str = "networkidle2",
        timeout_ms: int = 15000,
    ) -> dict[str, Any]:
        """Navigate a browser session through AgentShield enforcement.

        The request flows: SDK -> API -> Policy Engine -> Browser Worker ->
        Egress Proxy -> Destination. The result includes the policy decision,
        threat detection, DLP, and risk assessment.
        """
        return self._post(
            "/v1/ai-agent/action",
            {
                "action": "navigate",
                "target": url,
                "session_id": session_id,
                "tool_args": {
                    "wait_until": wait_until,
                    "timeout_ms": timeout_ms,
                },
            },
        )

    def action(
        self,
        *,
        action: str,
        target: str | None = None,
        session_id: str | None = None,
        tool_name: str | None = None,
        tool_args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a generic agent action through AgentShield enforcement.

        Supported actions: navigate, click, type, scroll, extract, screenshot,
        tool_call, file_download, form_submit, sensitive_access.
        """
        return self._post(
            "/v1/ai-agent/action",
            {
                "action": action,
                "target": target,
                "session_id": session_id,
                "tool_name": tool_name,
                "tool_args": tool_args or {},
            },
        )

    def tool_call(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Invoke an agent tool through AgentShield permission governance."""
        return self.action(
            action="tool_call",
            tool_name=tool_name,
            tool_args=tool_args or {},
            session_id=session_id,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AgentShieldClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
