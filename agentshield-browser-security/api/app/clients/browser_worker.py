from dataclasses import dataclass

import httpx
from pydantic import ValidationError

from app.config import Settings
from app.middleware import AGENT_ID_HEADER, REQUEST_ID_HEADER, SESSION_ID_HEADER
from app.schemas.action import WorkerActionResponse
from app.schemas.browser import WorkerNavigateResponse
from app.schemas.extract import WorkerExtractResponse
from app.schemas.health import WorkerHealthResponse
from app.schemas.session import SessionCloseResponse, SessionStatus


class BrowserWorkerError(Exception):
    """Base error for browser worker communication failures."""


class BrowserWorkerUnavailable(BrowserWorkerError):
    """The browser worker could not be reached."""


class BrowserWorkerTimeout(BrowserWorkerError):
    """The browser worker did not respond within the configured timeout."""


class BrowserWorkerResponseError(BrowserWorkerError):
    """The browser worker returned an invalid or unsuccessful response."""


class BrowserWorkerPolicyError(BrowserWorkerResponseError):
    """The browser worker rejected a navigation for a security reason."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True)
class ScreenshotResult:
    content: bytes
    content_type: str
    width: int
    height: int
    bytes: int
    full_page: bool
    elapsed_ms: int


def _png_dimensions(content: bytes) -> tuple[int, int]:
    if len(content) < 24 or not content.startswith(PNG_SIGNATURE):
        raise BrowserWorkerResponseError(
            "Browser worker returned an invalid screenshot image"
        )
    width = int.from_bytes(content[16:20], "big")
    height = int.from_bytes(content[20:24], "big")
    if width < 1 or height < 1:
        raise BrowserWorkerResponseError(
            "Browser worker returned an invalid screenshot image"
        )
    return width, height


class BrowserWorkerClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = settings.browser_worker_url
        self._request_timeout = settings.browser_worker_timeout_seconds
        self._health_timeout = settings.browser_worker_health_timeout_seconds
        self._auth_token = settings.worker_auth_token
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._request_timeout),
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def health_live(self) -> WorkerHealthResponse:
        return await self._get_health("/health/live")

    async def health_ready(self) -> WorkerHealthResponse:
        return await self._get_health("/health/ready")

    async def navigate(
        self,
        *,
        url: str,
        wait_until: str,
        timeout_ms: int,
        request_id: str,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> WorkerNavigateResponse:
        payload = {
            "url": url,
            "wait_until": wait_until,
            "timeout_ms": timeout_ms,
        }
        request_timeout = max(self._request_timeout, timeout_ms / 1000.0 + 5.0)
        headers = {REQUEST_ID_HEADER: request_id}
        # The identity crosses the hop as a header, not as body field, and is
        # forwarded byte-for-byte: no trimming, case folding, or regeneration.
        if session_id is not None:
            headers[SESSION_ID_HEADER] = session_id
        if agent_id is not None:
            headers[AGENT_ID_HEADER] = agent_id
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        try:
            response = await self._client.post(
                "/v1/navigate",
                json=payload,
                headers=headers,
                timeout=httpx.Timeout(request_timeout),
            )
        except httpx.TimeoutException as exc:
            raise BrowserWorkerTimeout(
                "Browser worker navigation request timed out"
            ) from exc
        except httpx.HTTPError as exc:
            raise BrowserWorkerUnavailable(
                "Browser worker is unavailable"
            ) from exc

        if response.status_code != 200:
            try:
                detail = response.json()
            except ValueError:
                detail = {}

            code = detail.get("code") if isinstance(detail, dict) else None
            message = detail.get("message") if isinstance(detail, dict) else None
            if not isinstance(code, str):
                code = (
                    "WORKER_AUTH_FAILED"
                    if response.status_code == 401
                    else "browser_worker_failure"
                )
            if not isinstance(message, str):
                message = f"Browser worker returned HTTP {response.status_code}"

            if response.status_code in {400, 401, 403, 404, 409, 422, 503}:
                raise BrowserWorkerPolicyError(
                    code,
                    message,
                    status_code=response.status_code,
                )

            raise BrowserWorkerResponseError(message)

        try:
            return WorkerNavigateResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise BrowserWorkerResponseError(
                "Browser worker returned an invalid navigation response"
            ) from exc

    async def create_session(
        self,
        *,
        agent_id: str,
        request_id: str,
        idle_timeout_ms: int | None = None,
        max_age_ms: int | None = None,
    ) -> SessionStatus:
        payload: dict[str, int] = {}
        if idle_timeout_ms is not None:
            payload["idle_timeout_ms"] = idle_timeout_ms
        if max_age_ms is not None:
            payload["max_age_ms"] = max_age_ms
        response = await self._request(
            "POST",
            "/v1/session",
            request_id=request_id,
            agent_id=agent_id,
            json=payload,
            policy_statuses={400, 401, 403, 404, 409, 422, 503},
        )
        try:
            return SessionStatus.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise BrowserWorkerResponseError(
                "Browser worker returned an invalid session response"
            ) from exc

    async def get_session(
        self, *, session_id: str, agent_id: str, request_id: str
    ) -> SessionStatus:
        response = await self._request(
            "GET",
            f"/v1/session/{session_id}",
            request_id=request_id,
            agent_id=agent_id,
            policy_statuses={400, 401, 403, 404, 409, 422, 503},
        )
        try:
            return SessionStatus.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise BrowserWorkerResponseError(
                "Browser worker returned an invalid session response"
            ) from exc

    async def close_session(
        self, *, session_id: str, agent_id: str, request_id: str
    ) -> SessionCloseResponse:
        response = await self._request(
            "DELETE",
            f"/v1/session/{session_id}",
            request_id=request_id,
            agent_id=agent_id,
            policy_statuses={400, 401, 403, 404, 409, 422, 503},
        )
        try:
            return SessionCloseResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise BrowserWorkerResponseError(
                "Browser worker returned an invalid session close response"
            ) from exc

    async def extract(
        self,
        *,
        session_id: str,
        agent_id: str,
        request_id: str,
    ) -> WorkerExtractResponse:
        response = await self._request(
            "POST",
            "/v1/extract",
            request_id=request_id,
            agent_id=agent_id,
            session_id=session_id,
            json={},
            policy_statuses={400, 401, 403, 404, 409, 422, 503},
        )
        try:
            return WorkerExtractResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise BrowserWorkerResponseError(
                "Browser worker returned an invalid extraction response"
            ) from exc

    async def action(
        self,
        *,
        session_id: str,
        agent_id: str,
        request_id: str,
        action: dict,
        timeout_ms: int,
    ) -> WorkerActionResponse:
        request_timeout = max(
            self._request_timeout, timeout_ms / 1000.0 + 5.0
        )
        payload = {**action, "timeout_ms": timeout_ms}
        response = await self._request(
            "POST",
            "/v1/action",
            request_id=request_id,
            agent_id=agent_id,
            session_id=session_id,
            json=payload,
            policy_statuses={400, 401, 403, 404, 409, 413, 422, 429, 503, 504},
            request_timeout=request_timeout,
        )
        try:
            return WorkerActionResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise BrowserWorkerResponseError(
                "Browser worker returned an invalid action response"
            ) from exc

    async def screenshot(
        self,
        *,
        session_id: str,
        agent_id: str,
        request_id: str,
        full_page: bool,
        clip: dict | None,
        timeout_ms: int,
    ) -> ScreenshotResult:
        payload: dict = {"full_page": full_page, "timeout_ms": timeout_ms}
        if clip is not None:
            payload["clip"] = clip

        headers = {REQUEST_ID_HEADER: request_id, AGENT_ID_HEADER: agent_id}
        headers[SESSION_ID_HEADER] = session_id
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        request_timeout = max(
            self._request_timeout, timeout_ms / 1000.0 + 5.0
        )
        try:
            response = await self._client.post(
                "/v1/screenshot",
                json=payload,
                headers=headers,
                timeout=httpx.Timeout(request_timeout),
            )
        except httpx.TimeoutException as exc:
            raise BrowserWorkerTimeout(
                "Browser worker screenshot request timed out"
            ) from exc
        except httpx.HTTPError as exc:
            raise BrowserWorkerUnavailable(
                "Browser worker is unavailable"
            ) from exc

        if response.status_code != 200:
            self._raise_worker_error(
                response, {400, 401, 403, 404, 409, 413, 422, 429, 503, 504}
            )

        content_type = response.headers.get("content-type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "image/png":
            raise BrowserWorkerResponseError(
                "Browser worker returned a non-PNG screenshot response"
            )

        content = response.content
        try:
            width = int(response.headers["x-screenshot-width"])
            height = int(response.headers["x-screenshot-height"])
            byte_count = int(response.headers["x-screenshot-bytes"])
            elapsed_ms = int(response.headers["x-screenshot-elapsed-ms"])
        except (KeyError, TypeError, ValueError) as exc:
            raise BrowserWorkerResponseError(
                "Browser worker returned incomplete screenshot metadata"
            ) from exc

        full_page_header = response.headers.get("x-screenshot-full-page", "")
        if full_page_header not in {"true", "false"}:
            raise BrowserWorkerResponseError(
                "Browser worker returned invalid screenshot metadata"
            )
        if width < 1 or height < 1 or byte_count != len(content) or elapsed_ms < 0:
            raise BrowserWorkerResponseError(
                "Browser worker returned inconsistent screenshot metadata"
            )
        if _png_dimensions(content) != (width, height):
            raise BrowserWorkerResponseError(
                "Browser worker returned inconsistent screenshot dimensions"
            )

        return ScreenshotResult(
            content=content,
            content_type="image/png",
            width=width,
            height=height,
            bytes=byte_count,
            full_page=full_page_header == "true",
            elapsed_ms=elapsed_ms,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        request_id: str,
        agent_id: str | None = None,
        session_id: str | None = None,
        json: dict | None = None,
        policy_statuses: set[int] | None = None,
        request_timeout: float | None = None,
    ) -> httpx.Response:
        headers = {REQUEST_ID_HEADER: request_id}
        if agent_id is not None:
            headers[AGENT_ID_HEADER] = agent_id
        if session_id is not None:
            headers[SESSION_ID_HEADER] = session_id
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        try:
            request_kwargs: dict = {"json": json, "headers": headers}
            if request_timeout is not None:
                request_kwargs["timeout"] = httpx.Timeout(request_timeout)
            response = await self._client.request(method, path, **request_kwargs)
        except httpx.TimeoutException as exc:
            raise BrowserWorkerTimeout(
                "Browser worker request timed out"
            ) from exc
        except httpx.HTTPError as exc:
            raise BrowserWorkerUnavailable("Browser worker is unavailable") from exc

        if response.status_code != 200 and not (
            method == "POST"
            and path == "/v1/session"
            and response.status_code == 201
        ):
            self._raise_worker_error(
                response, policy_statuses or {400, 401, 403, 409, 422}
            )
        return response

    def _raise_worker_error(
        self, response: httpx.Response, policy_statuses: set[int]
    ) -> None:
        try:
            detail = response.json()
        except ValueError:
            detail = {}

        code = detail.get("code") if isinstance(detail, dict) else None
        message = detail.get("message") if isinstance(detail, dict) else None
        if not isinstance(code, str):
            code = (
                "WORKER_AUTH_FAILED"
                if response.status_code == 401
                else "browser_worker_failure"
            )
        if not isinstance(message, str):
            message = f"Browser worker returned HTTP {response.status_code}"

        if response.status_code in policy_statuses:
            raise BrowserWorkerPolicyError(
                code,
                message,
                status_code=response.status_code,
            )

        raise BrowserWorkerResponseError(message)

    async def _get_health(self, path: str) -> WorkerHealthResponse:
        try:
            response = await self._client.get(
                path, timeout=httpx.Timeout(self._health_timeout)
            )
        except httpx.TimeoutException as exc:
            raise BrowserWorkerTimeout(
                "Browser worker health check timed out"
            ) from exc
        except httpx.HTTPError as exc:
            raise BrowserWorkerUnavailable(
                "Browser worker is unavailable"
            ) from exc

        if response.status_code not in {200, 503}:
            raise BrowserWorkerResponseError(
                f"Browser worker health check returned HTTP {response.status_code}"
            )

        try:
            return WorkerHealthResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise BrowserWorkerResponseError(
                "Browser worker returned an invalid health response"
            ) from exc
