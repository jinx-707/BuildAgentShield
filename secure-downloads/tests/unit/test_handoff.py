"""Tests for the approved-only document handoff gate and adapters."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from integrations.handoff import (
    AnalysisDocument,
    DisabledAnalysisAdapter,
    DocumentHandoffPayload,
    DocumentHandoffService,
    HandoffError,
    MockDocumentAnalysisAdapter,
)
from models.download import Download, DownloadState
from security.errors import (
    ANALYSIS_DISABLED,
    HANDOFF_ERROR,
    INVALID_STATE,
    DownloadSecurityError,
)
from services.document_processor import ProcessedDocument
from storage.manager import StorageManager


PDF_BYTES = b"%PDF-1.4\nhandoff test document\n%%EOF\n"


class FakeRepository:
    def __init__(self, record: Download) -> None:
        self.record = record
        self.completed: list[tuple[str, str]] = []

    async def get(self, *, download_id: str, tenant_id: str) -> Download:
        return self.record

    async def mark_handoff_completed(
        self, *, download_id: str, tenant_id: str
    ) -> Download:
        self.completed.append((download_id, tenant_id))
        self.record.handoff_completed = True
        return self.record


def make_record(
    storage: StorageManager,
    *,
    data: bytes = PDF_BYTES,
    state: DownloadState = DownloadState.APPROVED,
) -> Download:
    path, temp_ref = storage.allocate_temp_path()
    path.write_bytes(data)
    approved_ref = storage.move_to_approved(temp_ref)

    record = Download()
    record.id = "dl-handoff"
    record.tenant_id = "tenant-x"
    record.agent_id = "agent-1"
    record.original_url = "https://example.com/report.pdf"
    record.state = state
    record.storage_ref = approved_ref.ref_string
    record.file_sha256 = hashlib.sha256(data).hexdigest()
    record.file_size = len(data)
    record.detected_mime_type = "application/pdf"
    record.original_filename = "report.pdf"
    record.created_at = datetime.now(tz=timezone.utc)
    record.updated_at = datetime.now(tz=timezone.utc)
    record.handoff_completed = False
    return record


@pytest.fixture
def storage(tmp_path) -> StorageManager:
    manager = StorageManager(str(tmp_path / "storage"))
    manager.initialize()
    return manager


def make_service(storage, record, adapter=None):
    repo = FakeRepository(record)
    service = DocumentHandoffService(
        adapter=adapter or MockDocumentAnalysisAdapter(),
        storage_manager=storage,
        repository=repo,
    )
    return service, repo


class TestVerifyApprovedOnly:
    async def test_only_approved_files_pass_the_gate(self, storage):
        for state in (
            DownloadState.QUARANTINED,
            DownloadState.PENDING,
            DownloadState.FAILED,
            DownloadState.REJECTED,
            DownloadState.EXPIRED,
        ):
            record = make_record(storage, state=state)
            service, _ = make_service(storage, record)
            with pytest.raises(DownloadSecurityError) as exc_info:
                await service.verify(download_id=record.id, tenant_id=record.tenant_id)
            assert exc_info.value.code == INVALID_STATE

    async def test_verify_returns_opaque_approved_ref(self, storage):
        record = make_record(storage)
        service, _ = make_service(storage, record)

        verified = await service.verify(
            download_id=record.id, tenant_id=record.tenant_id
        )

        assert verified.storage_ref == record.storage_ref
        assert verified.storage_ref.startswith("approved/")
        assert verified.payload.file_ref == record.storage_ref
        assert verified.payload.sha256 == record.file_sha256

    async def test_non_approved_zone_ref_is_rejected(self, storage):
        record = make_record(storage)
        record.storage_ref = "temporary/some-uuid"
        service, _ = make_service(storage, record)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await service.verify(download_id=record.id, tenant_id=record.tenant_id)
        assert exc_info.value.code == HANDOFF_ERROR
        assert "approved zone" in exc_info.value.message

    async def test_missing_file_blocks_handoff(self, storage):
        record = make_record(storage)
        storage.delete(
            storage_ref_to_parse(record.storage_ref)
        )
        service, _ = make_service(storage, record)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await service.verify(download_id=record.id, tenant_id=record.tenant_id)
        assert exc_info.value.code == HANDOFF_ERROR
        assert "no longer exists" in exc_info.value.message

    async def test_checksum_mismatch_blocks_handoff(self, storage):
        record = make_record(storage)
        # Tamper with the file after recording the hash.
        path = storage.get_approved_path(storage_ref_to_parse(record.storage_ref))
        path.write_bytes(b"%PDF-1.4\ntampered\n%%EOF\n")
        service, _ = make_service(storage, record)

        with pytest.raises(DownloadSecurityError) as exc_info:
            await service.verify(download_id=record.id, tenant_id=record.tenant_id)
        assert exc_info.value.code == HANDOFF_ERROR
        assert "checksum" in exc_info.value.message.lower()


class TestSubmit:
    async def test_submit_passes_approved_bytes_and_bounded_text(self, storage):
        record = make_record(storage)
        adapter = MockDocumentAnalysisAdapter()
        service, _ = make_service(storage, record, adapter)
        verified = await service.verify(
            download_id=record.id, tenant_id=record.tenant_id
        )
        processed = ProcessedDocument(
            document_type="pdf",
            page_count=1,
            text="hello from the approved document",
            text_truncated=False,
            warnings=["NO_EXTRACTABLE_TEXT"],
        )

        response = await service.submit(
            verified,
            content=PDF_BYTES,
            processed=processed,
            correlation_id="corr-1",
        )

        assert response.status == "completed"
        assert response.correlation_id == "corr-1"
        assert "MOCK_ANALYSIS_PROVIDER" in response.warnings
        assert len(adapter.submissions) == 1
        submitted: AnalysisDocument = adapter.submissions[0]
        assert submitted.content == PDF_BYTES
        assert submitted.payload.download_id == record.id
        assert submitted.payload.file_ref.startswith("approved/")
        assert submitted.extracted_text == processed.text
        assert submitted.page_count == 1

    async def test_complete_marks_handoff_completed(self, storage):
        record = make_record(storage)
        service, repo = make_service(storage, record)
        verified = await service.verify(
            download_id=record.id, tenant_id=record.tenant_id
        )

        await service.complete(verified)

        assert repo.completed == [(record.id, record.tenant_id)]
        assert record.handoff_completed is True

    async def test_adapter_failure_does_not_mark_success(self, storage):
        record = make_record(storage)
        adapter = MockDocumentAnalysisAdapter(should_fail=True)
        service, repo = make_service(storage, record, adapter)
        verified = await service.verify(
            download_id=record.id, tenant_id=record.tenant_id
        )
        processed = ProcessedDocument("pdf", 1, "", True, [])

        with pytest.raises(HandoffError) as exc_info:
            await service.submit(
                verified,
                content=PDF_BYTES,
                processed=processed,
                correlation_id="corr-1",
            )
        assert exc_info.value.retriable is True
        assert repo.completed == []


class TestAdapters:
    async def test_mock_adapter_records_submissions(self):
        adapter = MockDocumentAnalysisAdapter()
        document = AnalysisDocument(
            payload=DocumentHandoffPayload(
                download_id="d1",
                tenant_id="t1",
                agent_id="a1",
                file_ref="approved/uuid",
                mime_type="application/pdf",
                file_size=len(PDF_BYTES),
                sha256="abc",
            ),
            content=PDF_BYTES,
            document_type="pdf",
            page_count=1,
            extracted_text="text",
            text_truncated=False,
            warnings=(),
        )

        response = await adapter.analyze(document, correlation_id="corr")

        assert len(adapter.submissions) == 1
        assert response.analysis_id
        assert adapter.provider_name == "mock"

    async def test_mock_adapter_fail_mode(self):
        adapter = MockDocumentAnalysisAdapter(
            should_fail=True, fail_code="ANALYSIS_UNAVAILABLE"
        )
        document = AnalysisDocument(
            payload=DocumentHandoffPayload(
                download_id="d1",
                tenant_id="t1",
                agent_id="a1",
                file_ref="approved/uuid",
                mime_type="application/pdf",
                file_size=1,
                sha256="abc",
            ),
            content=b"x",
            document_type="pdf",
            page_count=1,
            extracted_text="",
            text_truncated=False,
            warnings=(),
        )
        with pytest.raises(HandoffError) as exc_info:
            await adapter.analyze(document, correlation_id="corr")
        assert exc_info.value.code == "ANALYSIS_UNAVAILABLE"

    async def test_disabled_adapter_raises_disabled(self):
        adapter = DisabledAnalysisAdapter()
        document = AnalysisDocument(
            payload=DocumentHandoffPayload(
                download_id="d1",
                tenant_id="t1",
                agent_id="a1",
                file_ref="approved/uuid",
                mime_type="application/pdf",
                file_size=1,
                sha256="abc",
            ),
            content=b"x",
            document_type="pdf",
            page_count=1,
            extracted_text="",
            text_truncated=False,
            warnings=(),
        )
        with pytest.raises(HandoffError) as exc_info:
            await adapter.analyze(document, correlation_id="corr")
        assert exc_info.value.code == ANALYSIS_DISABLED


def storage_ref_to_parse(ref_string: str):
    from storage.manager import StorageRef

    return StorageRef.parse(ref_string)
