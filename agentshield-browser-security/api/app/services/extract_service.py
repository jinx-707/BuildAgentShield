from app.clients.browser_worker import BrowserWorkerClient
from app.interfaces.inspection import ContentInspectionRequest, ContentInspector
from app.schemas.extract import (
    ExtractRequest,
    ExtractResponse,
    ExtractionContent,
    ExtractionSecurity,
    ExtractionTruncation,
)


class ExtractService:
    """Extract untrusted page text from an owned browser session.

    The worker returns plain text and structured records only, never raw HTML.
    The API independently runs the configured prompt-injection inspector over
    the extracted text and attaches an explicit untrusted-content designation
    to every response, regardless of inspection findings.
    """

    def __init__(
        self,
        worker_client: BrowserWorkerClient,
        content_inspector: ContentInspector,
    ) -> None:
        self._worker_client = worker_client
        self._content_inspector = content_inspector

    async def extract(
        self,
        request: ExtractRequest,
        *,
        agent_id: str,
        request_id: str,
    ) -> ExtractResponse:
        worker_result = await self._worker_client.extract(
            session_id=request.session_id,
            agent_id=agent_id,
            request_id=request_id,
        )

        inspection = await self._content_inspector.inspect(
            ContentInspectionRequest(
                request_id=request_id,
                url=worker_result.metadata.url,
                content=worker_result.text,
            )
        )

        warnings = ["UNTRUSTED_PAGE_CONTENT"]
        if worker_result.hidden_content_excluded:
            warnings.append("HIDDEN_CONTENT_EXCLUDED")
        if worker_result.text_truncated:
            warnings.append("TEXT_TRUNCATED")
        if worker_result.links_truncated:
            warnings.append("LINKS_TRUNCATED")
        if worker_result.lists_truncated:
            warnings.append("LISTS_TRUNCATED")
        if worker_result.tables_truncated:
            warnings.append("TABLES_TRUNCATED")

        content_truncated = any(
            (
                worker_result.text_truncated,
                worker_result.links_truncated,
                worker_result.lists_truncated,
                worker_result.tables_truncated,
            )
        )

        return ExtractResponse(
            request_id=request_id,
            session_id=worker_result.session_id,
            metadata=worker_result.metadata,
            content=ExtractionContent(
                text=worker_result.text,
                byte_length=len(worker_result.text.encode("utf-8")),
                text_truncated=worker_result.text_truncated,
            ),
            links=worker_result.links,
            lists=worker_result.lists,
            tables=worker_result.tables,
            truncation=ExtractionTruncation(
                text=worker_result.text_truncated,
                links=worker_result.links_truncated,
                lists=worker_result.lists_truncated,
                tables=worker_result.tables_truncated,
            ),
            content_truncated=content_truncated,
            security=ExtractionSecurity(
                trust_label="untrusted",
                content_classification=inspection.content_classification,
                warnings=warnings,
                hidden_content_excluded=worker_result.hidden_content_excluded,
                hidden_element_count=worker_result.hidden_element_count,
            ),
            inspection=inspection,
        )
