"""Request ID tracking and propagation middleware."""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

HEADER_REQUEST_ID = "X-Request-ID"


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Ensures every incoming request carries a unique correlation ID for end-to-end tracing."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get(HEADER_REQUEST_ID)
        if not request_id:
            request_id = str(uuid.uuid4())

        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[HEADER_REQUEST_ID] = request_id
        return response

