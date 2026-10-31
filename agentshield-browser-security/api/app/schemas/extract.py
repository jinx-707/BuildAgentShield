from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.browser import InspectionResult, SESSION_ID_PATTERN


class ExtractRequest(BaseModel):
    session_id: str = Field(pattern=SESSION_ID_PATTERN)


class PageMetadata(BaseModel):
    title: str = ""
    url: str
    description: str | None = None
    canonical_url: str | None = None
    site_name: str | None = None
    language: str | None = None


class ExtractedLink(BaseModel):
    text: str
    url: str
    rel: str | None = None


class ExtractedList(BaseModel):
    ordered: bool
    items: list[str] = Field(default_factory=list)


class ExtractedTable(BaseModel):
    caption: str | None = None
    headers: list[str] = Field(default_factory=list)
    rows: list[list[str]] = Field(default_factory=list)


class WorkerExtractResponse(BaseModel):
    request_id: str
    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    metadata: PageMetadata
    text: str
    text_truncated: bool = False
    links: list[ExtractedLink] = Field(default_factory=list)
    links_truncated: bool = False
    lists: list[ExtractedList] = Field(default_factory=list)
    lists_truncated: bool = False
    tables: list[ExtractedTable] = Field(default_factory=list)
    tables_truncated: bool = False
    hidden_content_excluded: bool = False
    hidden_element_count: int = 0
    elapsed_ms: int = 0


class ExtractionContent(BaseModel):
    text: str
    byte_length: int
    text_truncated: bool


class ExtractionTruncation(BaseModel):
    text: bool = False
    links: bool = False
    lists: bool = False
    tables: bool = False


class ExtractionSecurity(BaseModel):
    trust_label: Literal["untrusted"] = "untrusted"
    content_classification: str = "untrusted"
    warnings: list[str] = Field(default_factory=list)
    hidden_content_excluded: bool = False
    hidden_element_count: int = 0


class ExtractResponse(BaseModel):
    request_id: str
    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    metadata: PageMetadata
    content: ExtractionContent
    links: list[ExtractedLink] = Field(default_factory=list)
    lists: list[ExtractedList] = Field(default_factory=list)
    tables: list[ExtractedTable] = Field(default_factory=list)
    truncation: ExtractionTruncation
    content_truncated: bool = False
    security: ExtractionSecurity
    inspection: InspectionResult
