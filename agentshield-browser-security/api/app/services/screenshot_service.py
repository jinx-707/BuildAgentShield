from app.clients.browser_worker import BrowserWorkerClient, ScreenshotResult
from app.schemas.screenshot import ScreenshotRequest


class ScreenshotService:
    """Capture a bounded screenshot from an owned persistent browser session.

    The worker enforces ownership, dimensions, byte size, rate, concurrency,
    and timeout limits. Images remain in memory and the API never exposes a
    filesystem path or forwards worker response headers verbatim.
    """

    def __init__(self, worker_client: BrowserWorkerClient) -> None:
        self._worker_client = worker_client

    async def capture(
        self,
        request: ScreenshotRequest,
        *,
        agent_id: str,
        request_id: str,
    ) -> ScreenshotResult:
        clip = request.clip.model_dump() if request.clip is not None else None
        return await self._worker_client.screenshot(
            session_id=request.session_id,
            agent_id=agent_id,
            request_id=request_id,
            full_page=request.full_page,
            clip=clip,
            timeout_ms=request.timeout_ms,
        )
