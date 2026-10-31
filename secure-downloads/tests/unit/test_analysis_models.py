"""Tests for provider contract schemas and response sanitization."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from integrations.analysis_models import (
    ANALYSIS_SCHEMA_VERSION,
    MAX_FINDINGS,
    MAX_METADATA_KEYS,
    MAX_WARNINGS,
    AnalysisRequest,
    AnalysisRequestDocument,
    NormalizedAnalysisResult,
    ProviderAnalysisResponse,
    build_normalized_result,
    clean_text,
)


def valid_response(**overrides) -> dict:
    payload = {
        "schema_version": "1",
        "analysis_id": "provider-analysis-1",
        "correlation_id": "corr-1",
        "status": "completed",
        "document": {"document_type": "pdf", "page_count": 2},
        "summary": "A two-page report.",
        "findings": [
            {"id": "f1", "severity": "low", "title": "Minor issue", "detail": "Detail"}
        ],
        "confidence": {"overall": 0.82},
        "metadata": {"pages": 2, "producer": "test"},
        "warnings": ["provider-warning"],
        "processed_at": "2026-01-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


class TestCleanText:
    def test_removes_control_characters_and_caps(self):
        cleaned = clean_text("a\x00b\x07c\x1bd" + "x" * 100, 10)
        assert "\x00" not in cleaned
        assert len(cleaned) == 10

    def test_collapses_horizontal_whitespace(self):
        assert clean_text("a \t b", 10) == "a b"


class TestProviderResponse:
    def test_valid_response_parses(self):
        response = ProviderAnalysisResponse.model_validate(valid_response())
        assert response.analysis_id == "provider-analysis-1"
        assert response.document.page_count == 2
        assert response.confidence == {"overall": 0.82}

    def test_unknown_fields_are_ignored(self):
        payload = valid_response(malicious="ignore me")
        response = ProviderAnalysisResponse.model_validate(payload)
        assert not hasattr(response, "malicious")

    def test_control_characters_are_stripped_from_text(self):
        response = ProviderAnalysisResponse.model_validate(
            valid_response(summary="bad\x00summary")
        )
        assert response.summary == "badsummary"

    def test_finding_fields_are_capped(self):
        payload = valid_response(
            findings=[
                {"id": "f", "severity": "high", "title": "t" * 500, "detail": "d" * 5000}
            ]
        )
        response = ProviderAnalysisResponse.model_validate(payload)
        assert len(response.findings[0].title) == 200
        assert len(response.findings[0].detail) == 2_000

    def test_too_many_findings_rejected(self):
        payload = valid_response(
            findings=[{"severity": "info"} for _ in range(MAX_FINDINGS + 1)]
        )
        with pytest.raises(ValidationError):
            ProviderAnalysisResponse.model_validate(payload)

    def test_warnings_are_cleaned_and_capped(self):
        response = ProviderAnalysisResponse.model_validate(
            valid_response(warnings=[f"w{i}" for i in range(MAX_WARNINGS + 5)])
        )
        assert len(response.warnings) == MAX_WARNINGS

    def test_failed_status_requires_error(self):
        with pytest.raises(ValidationError):
            ProviderAnalysisResponse.model_validate(valid_response(status="failed"))

    def test_failed_status_with_error_parses(self):
        response = ProviderAnalysisResponse.model_validate(
            valid_response(
                status="failed",
                error={"code": "x", "message": "nope", "retryable": True},
            )
        )
        assert response.error is not None
        assert response.error.retryable is True

    def test_error_code_is_sanitized(self):
        response = ProviderAnalysisResponse.model_validate(
            valid_response(
                status="failed",
                error={"code": "bad code<script>", "message": "nope"},
            )
        )
        assert response.error.code == "badcodescript"

    def test_processed_at_accepts_z_suffix(self):
        response = ProviderAnalysisResponse.model_validate(
            valid_response(processed_at="2026-05-01T12:30:00Z")
        )
        assert response.processed_at is not None
        assert response.processed_at.year == 2026

    def test_invalid_processed_at_rejected(self):
        with pytest.raises(ValidationError):
            ProviderAnalysisResponse.model_validate(
                valid_response(processed_at="not-a-date")
            )


class TestConfidence:
    def test_confidence_must_be_numeric_within_range(self):
        with pytest.raises(ValidationError):
            ProviderAnalysisResponse.model_validate(
                valid_response(confidence={"overall": 1.5})
            )
        with pytest.raises(ValidationError):
            ProviderAnalysisResponse.model_validate(
                valid_response(confidence={"overall": True})
            )
        with pytest.raises(ValidationError):
            ProviderAnalysisResponse.model_validate(valid_response(confidence=[]))

    def test_confidence_absent_stays_absent(self):
        payload = valid_response()
        payload.pop("confidence")
        response = ProviderAnalysisResponse.model_validate(payload)
        assert response.confidence is None


class TestMetadata:
    def test_non_scalar_metadata_rejected(self):
        with pytest.raises(ValidationError):
            ProviderAnalysisResponse.model_validate(
                valid_response(metadata={"nested": {"a": 1}})
            )

    def test_boolean_and_null_metadata_dropped(self):
        response = ProviderAnalysisResponse.model_validate(
            valid_response(metadata={"flag": True, "nothing": None, "n": 3})
        )
        assert response.metadata == {"n": 3}

    def test_metadata_key_cap(self):
        with pytest.raises(ValidationError):
            ProviderAnalysisResponse.model_validate(
                valid_response(
                    metadata={f"k{i}": i for i in range(MAX_METADATA_KEYS + 1)}
                )
            )


class TestRequestSchema:
    def test_request_forbids_extra_fields(self):
        with pytest.raises(ValidationError):
            AnalysisRequest.model_validate(
                {
                    "schema_version": "1",
                    "correlation_id": "c",
                    "document": {"unexpected": True},
                    "content_base64": "",
                }
            )
        with pytest.raises(ValidationError):
            AnalysisRequestDocument.model_validate(
                {
                    "download_id": "d",
                    "tenant_id": "t",
                    "agent_id": "a",
                    "sha256": "s",
                    "mime_type": "application/pdf",
                    "size_bytes": 1,
                    "page_count": 1,
                    "text_truncated": False,
                    "extracted_text": "",
                    "smuggled": "field",
                }
            )


class TestNormalizedResult:
    def _build(self, response: ProviderAnalysisResponse, **overrides) -> NormalizedAnalysisResult:
        options = {
            "download_id": "dl-1",
            "analysis_id": "job-1",
            "provider": "http",
            "document_type": "pdf",
            "page_count": 2,
            "extracted_text": "local text",
            "text_truncated": False,
            "sha256": "abc",
            "response": response,
            "local_warnings": ["LOCAL_WARNING"],
        }
        options.update(overrides)
        return build_normalized_result(**options)

    def test_provenance_is_separated(self):
        response = ProviderAnalysisResponse.model_validate(valid_response())
        result = self._build(response)

        assert result.document_type == "pdf"          # local
        assert result.extracted_text == "local text"  # local
        assert result.summary == "A two-page report." # provider
        assert result.provider_analysis_id == "provider-analysis-1"
        assert result.provider_correlation_id == "corr-1"
        assert result.confidence == {"overall": 0.82}
        assert result.schema_version == ANALYSIS_SCHEMA_VERSION

    def test_warnings_are_merged_and_deduplicated(self):
        response = ProviderAnalysisResponse.model_validate(
            valid_response(warnings=["LOCAL_WARNING", "provider-warning"])
        )
        result = self._build(response)
        assert result.warnings == ["LOCAL_WARNING", "provider-warning"]

    def test_unknown_provider_document_type_becomes_none(self):
        response = ProviderAnalysisResponse.model_validate(
            valid_response(document={})
        )
        result = self._build(response)
        assert result.provider_document_type is None

    def test_normalized_result_forbids_extra(self):
        response = ProviderAnalysisResponse.model_validate(valid_response())
        result = self._build(response)
        data = result.model_dump()
        data["smuggled"] = True
        with pytest.raises(ValidationError):
            NormalizedAnalysisResult.model_validate(data)
