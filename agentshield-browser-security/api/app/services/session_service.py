from app.clients.browser_worker import BrowserWorkerClient
from app.schemas.session import (
    SessionCloseResponse,
    SessionCreateRequest,
    SessionStatus,
)


class SessionService:
    """Thin API-side lifecycle facade over the worker's session registry.

    Authorization is not decided here: the worker checks that the authenticated
    agent identity owns the session before it touches a browser context. The API
    only validates the identity shape and forwards it verbatim.
    """

    def __init__(self, worker_client: BrowserWorkerClient) -> None:
        self._worker_client = worker_client

    async def create(
        self,
        request: SessionCreateRequest,
        *,
        agent_id: str,
        request_id: str,
    ) -> SessionStatus:
        return await self._worker_client.create_session(
            agent_id=agent_id,
            request_id=request_id,
            idle_timeout_ms=request.idle_timeout_ms,
            max_age_ms=request.max_age_ms,
        )

    async def get(
        self, *, session_id: str, agent_id: str, request_id: str
    ) -> SessionStatus:
        return await self._worker_client.get_session(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
        )

    async def close(
        self, *, session_id: str, agent_id: str, request_id: str
    ) -> SessionCloseResponse:
        return await self._worker_client.close_session(
            session_id=session_id,
            agent_id=agent_id,
            request_id=request_id,
        )
