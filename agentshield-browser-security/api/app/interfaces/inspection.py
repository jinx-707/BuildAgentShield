from typing import Protocol

from app.schemas.browser import InspectionResult


class ContentInspectionRequest:
    def __init__(self, *, request_id: str, url: str, content: str) -> None:
        self.request_id = request_id
        self.url = url
        self.content = content


class ContentInspector(Protocol):
    name: str

    async def inspect(self, request: ContentInspectionRequest) -> InspectionResult:
        """Inspect untrusted browser content and return findings."""
        ...
