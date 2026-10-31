"""
Puppeteer Manager — Python-side client for the Node.js browser worker.
The LLM never directly calls the browser worker.
All commands are authenticated and validated here before forwarding.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.configuration import get_settings
from app.core.exceptions import BrowserError, BrowserSessionError

logger = logging.getLogger(__name__)


class PuppeteerManager:
    """
    Thin authenticated HTTP client for the Node.js Puppeteer worker.
    The worker runs at BROWSER_WORKER_URL and requires BROWSER_WORKER_API_KEY.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._base_url = settings.browser_worker_url.rstrip("/")
        self._api_key = settings.browser_worker_api_key

    def _headers(self) -> dict[str, str]:
        return {
            "X-AgentShield-Key": self._api_key,
            "Content-Type": "application/json",
        }

    async def _post(
        self,
        path: str,
        payload: dict[str, Any],
        timeout: float = 45.0,
    ) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                resp = await client.post(url, json=payload, headers=self._headers())
                resp.raise_for_status()
                return resp.json()
        except httpx.ConnectError:
            raise BrowserError(
                f"Cannot connect to browser worker at {self._base_url}. "
                "Ensure the Node.js Puppeteer worker is running: cd browser-worker && npm start"
            )
        except httpx.HTTPStatusError as e:
            error_detail = ""
            try:
                error_detail = e.response.json().get("error", "")
            except Exception:
                pass
            raise BrowserError(f"Browser worker error {e.response.status_code}: {error_detail}")
        except httpx.TimeoutException:
            raise BrowserError(f"Browser worker request timed out after {timeout}s")

    async def navigate(
        self,
        url: str,
        session_id: str,
        timeout_ms: int = 30000,
    ) -> dict[str, Any]:
        return await self._post("/navigate", {
            "url": url,
            "sessionId": session_id,
            "timeout": timeout_ms,
        })

    async def extract_text(
        self,
        session_id: str,
        selector: str | None = None,
    ) -> dict[str, Any]:
        return await self._post("/extract", {
            "sessionId": session_id,
            "selector": selector,
        })

    async def click(
        self,
        session_id: str,
        selector: str,
    ) -> dict[str, Any]:
        return await self._post("/click", {
            "sessionId": session_id,
            "selector": selector,
        })

    async def get_metadata(self, session_id: str) -> dict[str, Any]:
        return await self._post("/metadata", {"sessionId": session_id})

    async def create_session(self) -> dict[str, Any]:
        return await self._post("/session/create", {})

    async def close_session(self, session_id: str) -> dict[str, Any]:
        return await self._post("/session/close", {"sessionId": session_id})

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self._base_url}/health",
                    headers=self._headers(),
                )
                return resp.status_code == 200
        except Exception:
            return False
