from __future__ import annotations

import time
import uuid
from typing import Any

import httpx


class AgentShieldError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None, payload: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


def _payload(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    source: str,
    trust: str,
    data_classification: str,
    request_id: str | None,
    session_id: str | None,
    idempotency_key: str | None,
    user_intent: str,
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "request_id": request_id or f"sdk_{uuid.uuid4().hex}",
        "tool_name": tool_name,
        "arguments": arguments,
        "provenance": {
            "source": source,
            "trust": trust,
            "data_classification": data_classification,
            "tainted": trust == "untrusted",
            "origin": source,
            "taint_labels": [trust] if trust == "untrusted" else [],
        },
        "user_intent": user_intent,
    }
    if session_id:
        body["session_id"] = session_id
    if idempotency_key:
        body["idempotency_key"] = idempotency_key
    return body


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code >= 400:
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        raise AgentShieldError(
            f"AgentShield request failed ({response.status_code})",
            response.status_code,
            payload,
        )


def _decode(response: httpx.Response) -> Any:
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()
    return response.text


class AsyncAgentShieldClient:
    def __init__(
        self,
        base_url: str,
        agent_key: str | None = None,
        dashboard_token: str | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_key = agent_key
        self.dashboard_token = dashboard_token
        self.timeout = timeout
        self._http = httpx.AsyncClient(
            base_url=self.base_url, timeout=timeout, transport=transport
        )

    def _headers(
        self, *, agent: bool = True, approval_token: str | None = None
    ) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if agent and self.agent_key:
            headers["X-Agent-Key"] = self.agent_key
        elif self.dashboard_token:
            headers["Authorization"] = f"Bearer {self.dashboard_token}"
        if approval_token:
            headers["X-Approval-Token"] = approval_token
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        agent: bool = True,
        approval_token: str | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        headers = self._headers(agent=agent, approval_token=approval_token)
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        response = await self._http.request(
            method, f"/v1{path}", json=json, headers=headers
        )
        _raise_for_status(response)
        return _decode(response)

    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        source: str = "sdk",
        trust: str = "trusted",
        data_classification: str = "internal",
        request_id: str | None = None,
        approval_token: str | None = None,
        idempotency_key: str | None = None,
        session_id: str | None = None,
        user_intent: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await self.request(
            "POST",
            "/tools/execute",
            json=_payload(
                tool_name,
                arguments,
                source=source,
                trust=trust,
                data_classification=data_classification,
                request_id=request_id,
                session_id=session_id,
                idempotency_key=idempotency_key,
                user_intent=user_intent,
                metadata=metadata,
            ),
            approval_token=approval_token,
            idempotency_key=idempotency_key,
        )

    async def propose(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        return await self.request(
            "POST",
            "/tools/propose",
            json=_payload(
                tool_name,
                arguments,
                source=kwargs.get("source", "sdk"),
                trust=kwargs.get("trust", "trusted"),
                data_classification=kwargs.get("data_classification", "internal"),
                request_id=kwargs.get("request_id"),
                session_id=kwargs.get("session_id"),
                idempotency_key=None,
                user_intent=kwargs.get("user_intent", ""),
                metadata=kwargs.get("metadata"),
            ),
        )

    async def execute_once(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        idempotency_key: str | None = None,
        **provenance: Any,
    ) -> dict[str, Any]:
        return await self.execute(
            tool_name,
            arguments,
            idempotency_key=idempotency_key or f"idem_{uuid.uuid4().hex}",
            **provenance,
        )

    async def list_tools(self) -> dict[str, Any]:
        return await self.request("GET", "/tools", agent=False)

    async def get_approval(self, approval_id: str) -> dict[str, Any]:
        return await self.request("GET", f"/approvals/{approval_id}", agent=False)

    async def approve(self, approval_id: str, comment: str = "") -> dict[str, Any]:
        return await self.request(
            "POST",
            f"/approvals/{approval_id}/approve",
            json={"comment": comment},
            agent=False,
        )

    async def reject(self, approval_id: str, comment: str = "") -> dict[str, Any]:
        return await self.request(
            "POST",
            f"/approvals/{approval_id}/reject",
            json={"comment": comment},
            agent=False,
        )

    async def wait_for_approval(
        self,
        approval_id: str,
        *,
        timeout: float = 300.0,
        interval: float = 2.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            approval = await self.get_approval(approval_id)
            if approval.get("status") in {"Approved", "Rejected", "Expired"}:
                return approval
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Approval {approval_id} did not resolve in time")
            await __import__("asyncio").sleep(interval)

    async def run_simulator(self, scenario_ids: list[str] | None = None) -> dict[str, Any]:
        return await self.request(
            "POST",
            "/simulator/run",
            json={"scenario_ids": scenario_ids or []},
            agent=False,
        )

    async def health(self) -> dict[str, Any]:
        response = await self._http.get("/ready")
        _raise_for_status(response)
        return _decode(response)

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncAgentShieldClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


class AgentShieldClient:
    def __init__(
        self,
        base_url: str,
        agent_key: str | None = None,
        dashboard_token: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_key = agent_key
        self.dashboard_token = dashboard_token
        self.timeout = timeout
        self._http = httpx.Client(
            base_url=self.base_url, timeout=timeout, transport=transport
        )

    def _headers(
        self, *, agent: bool = True, approval_token: str | None = None
    ) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if agent and self.agent_key:
            headers["X-Agent-Key"] = self.agent_key
        elif self.dashboard_token:
            headers["Authorization"] = f"Bearer {self.dashboard_token}"
        if approval_token:
            headers["X-Approval-Token"] = approval_token
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        agent: bool = True,
        approval_token: str | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        headers = self._headers(agent=agent, approval_token=approval_token)
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        response = self._http.request(method, f"/v1{path}", json=json, headers=headers)
        _raise_for_status(response)
        return _decode(response)

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        source: str = "sdk",
        trust: str = "trusted",
        data_classification: str = "internal",
        request_id: str | None = None,
        approval_token: str | None = None,
        idempotency_key: str | None = None,
        session_id: str | None = None,
        user_intent: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/tools/execute",
            json=_payload(
                tool_name,
                arguments,
                source=source,
                trust=trust,
                data_classification=data_classification,
                request_id=request_id,
                session_id=session_id,
                idempotency_key=idempotency_key,
                user_intent=user_intent,
                metadata=metadata,
            ),
            approval_token=approval_token,
            idempotency_key=idempotency_key,
        )

    def propose(
        self, tool_name: str, arguments: dict[str, Any], **kwargs: Any
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/tools/propose",
            json=_payload(
                tool_name,
                arguments,
                source=kwargs.get("source", "sdk"),
                trust=kwargs.get("trust", "trusted"),
                data_classification=kwargs.get("data_classification", "internal"),
                request_id=kwargs.get("request_id"),
                session_id=kwargs.get("session_id"),
                idempotency_key=None,
                user_intent=kwargs.get("user_intent", ""),
                metadata=kwargs.get("metadata"),
            ),
        )

    def execute_once(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        idempotency_key: str | None = None,
        **provenance: Any,
    ) -> dict[str, Any]:
        return self.execute(
            tool_name,
            arguments,
            idempotency_key=idempotency_key or f"idem_{uuid.uuid4().hex}",
            **provenance,
        )

    def list_tools(self) -> dict[str, Any]:
        return self.request("GET", "/tools", agent=False)

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        return self.request("GET", f"/approvals/{approval_id}", agent=False)

    def approve(self, approval_id: str, comment: str = "") -> dict[str, Any]:
        return self.request(
            "POST",
            f"/approvals/{approval_id}/approve",
            json={"comment": comment},
            agent=False,
        )

    def reject(self, approval_id: str, comment: str = "") -> dict[str, Any]:
        return self.request(
            "POST",
            f"/approvals/{approval_id}/reject",
            json={"comment": comment},
            agent=False,
        )

    def wait_for_approval(
        self,
        approval_id: str,
        *,
        timeout: float = 300.0,
        interval: float = 2.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            approval = self.get_approval(approval_id)
            if approval.get("status") in {"Approved", "Rejected", "Expired"}:
                return approval
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Approval {approval_id} did not resolve in time")
            time.sleep(interval)

    def run_simulator(self, scenario_ids: list[str] | None = None) -> dict[str, Any]:
        return self.request(
            "POST",
            "/simulator/run",
            json={"scenario_ids": scenario_ids or []},
            agent=False,
        )

    def health(self) -> dict[str, Any]:
        response = self._http.get("/ready")
        _raise_for_status(response)
        return _decode(response)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "AgentShieldClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class SecureAgent:
    def __init__(self, client: AgentShieldClient | AsyncAgentShieldClient) -> None:
        self.client = client

    def run(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        session_id: str | None = None,
        user_intent: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        if not isinstance(self.client, AgentShieldClient):
            raise TypeError("run() is only available on the synchronous client")
        return self.client.execute_once(
            tool_name,
            arguments,
            session_id=session_id,
            user_intent=user_intent,
            **kwargs,
        )

    async def arun(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        session_id: str | None = None,
        user_intent: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        if not isinstance(self.client, AsyncAgentShieldClient):
            raise TypeError("arun() is only available on the asynchronous client")
        return await self.client.execute_once(
            tool_name,
            arguments,
            session_id=session_id,
            user_intent=user_intent,
            **kwargs,
        )
