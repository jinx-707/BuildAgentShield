from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.browser import InspectionResult


class SearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    max_results: int | None = Field(default=None, ge=1, le=20)
    safe_search: bool = True

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("query must not be blank")
        return stripped


class SearchResult(BaseModel):
    title: str
    url: str
    snippet: str = ""
    source: str
    position: int = Field(ge=1)
    retrieved_at: datetime
    trust_label: Literal["untrusted"] = "untrusted"


class SearchResponse(BaseModel):
    request_id: str
    query: str
    provider: str
    provider_mode: Literal["full", "limited_fallback"]
    provider_notice: str | None = None
    results: list[SearchResult] = Field(default_factory=list)
    filtered_count: int = 0
    results_truncated: bool = False
    elapsed_ms: int
    trust_label: Literal["untrusted"] = "untrusted"
    inspection: InspectionResult
