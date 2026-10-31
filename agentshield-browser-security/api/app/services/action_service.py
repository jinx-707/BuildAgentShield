from app.clients.browser_worker import BrowserWorkerClient
from app.interfaces.inspection import ContentInspectionRequest, ContentInspector
from app.schemas.action import (
    ActionContent,
    ActionResponse,
    ActionSecurity,
    BrowserActionRequest,
)


def _merge_warnings(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    for group in groups:
        for warning in group:
            if warning not in merged:
                merged.append(warning)
    return merged


class ActionService:
    """Run one guarded browser action inside an owned persistent session.

    The worker is authoritative for ownership, URL policy, and element state.
    The API independently treats all returned page text as untrusted, inspects
    it for prompt injection, and applies a second redaction pass for typed
    values so a worker regression cannot echo caller-supplied secrets.
    """

    def __init__(
        self,
        worker_client: BrowserWorkerClient,
        content_inspector: ContentInspector,
    ) -> None:
        self._worker_client = worker_client
        self._content_inspector = content_inspector

    async def act(
        self,
        request: BrowserActionRequest,
        *,
        agent_id: str,
        request_id: str,
    ) -> ActionResponse:
        worker_result = await self._worker_client.action(
            session_id=request.session_id,
            agent_id=agent_id,
            request_id=request_id,
            action=request.action_payload(),
            timeout_ms=request.timeout_ms,
        )

        text = worker_result.text
        text_truncated = worker_result.text_truncated
        extra_warnings: list[str] = []

        if request.action == "type" and request.text:
            if len(request.text) >= 4:
                text = text.replace(request.text, "[REDACTED]")
                extra_warnings.append("TYPED_VALUE_REDACTED")
            else:
                text = ""
                text_truncated = True
                extra_warnings.append("TYPED_VALUE_TEXT_WITHHELD")

        inspection = await self._content_inspector.inspect(
            ContentInspectionRequest(
                request_id=request_id,
                url=worker_result.final_url,
                content=text,
            )
        )

        warnings = _merge_warnings(
            ["UNTRUSTED_PAGE_CONTENT"],
            worker_result.warnings,
            extra_warnings,
        )
        if text_truncated and "TEXT_TRUNCATED" not in warnings:
            warnings.append("TEXT_TRUNCATED")

        return ActionResponse(
            request_id=request_id,
            session_id=worker_result.session_id,
            action=worker_result.action,
            success=worker_result.success,
            target=worker_result.target,
            final_url=worker_result.final_url,
            title=worker_result.title,
            content=ActionContent(
                text=text,
                byte_length=len(text.encode("utf-8")),
                text_truncated=text_truncated,
            ),
            scroll=worker_result.scroll,
            form=worker_result.form,
            security=ActionSecurity(
                trust_label="untrusted",
                content_classification=inspection.content_classification,
                warnings=warnings,
                hidden_content_excluded=worker_result.hidden_content_excluded,
                hidden_element_count=worker_result.hidden_element_count,
            ),
            inspection=inspection,
            elapsed_ms=worker_result.elapsed_ms,
            redirect_count=worker_result.redirect_count,
            blocked_request_count=worker_result.blocked_request_count,
            blocked_target_count=worker_result.blocked_target_count,
        )
