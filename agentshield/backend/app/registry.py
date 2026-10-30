from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from .contracts import ToolSpec


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ReadDocumentInput(StrictInput):
    document: str = Field(min_length=1, max_length=500)


class ReadFileInput(StrictInput):
    path: str = Field(min_length=1, max_length=1000)


class ReadSystemFileInput(StrictInput):
    path: str = Field(min_length=1, max_length=1000)


class ReadEnvVarInput(StrictInput):
    name: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    source: str | None = Field(default=None, max_length=200)


class RunCommandInput(StrictInput):
    command: str = Field(min_length=1, max_length=2000)


class DeleteFileInput(StrictInput):
    path: str = Field(min_length=1, max_length=1000)
    recursive: bool = False


class BrowseUrlInput(StrictInput):
    url: HttpUrl
    trust: Literal["trusted", "untrusted", "unknown"] = "unknown"
    content: str | None = Field(default=None, max_length=20000)


class SendEmailInput(StrictInput):
    to: str = Field(min_length=3, max_length=254)
    subject: str = Field(default="", max_length=200)
    body: str = Field(default="", max_length=20000)
    attachment: str | None = Field(default=None, max_length=500)
    pii: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def validate_recipient(self) -> "SendEmailInput":
        if "@" not in self.to or " " in self.to:
            raise ValueError("invalid recipient")
        return self


class ExportDataInput(StrictInput):
    document: str = Field(min_length=1, max_length=500)
    destination: str = Field(min_length=1, max_length=500)
    format: Literal["csv", "json", "pdf"] = "csv"
    data_classification: str | None = Field(default=None, max_length=30)


class DownloadFileInput(StrictInput):
    url: HttpUrl
    filename: str | None = Field(default=None, max_length=255)


class InitiatePaymentInput(StrictInput):
    amount: float = Field(ge=0, le=1_000_000)
    currency: Literal["USD", "EUR", "GBP"] = "USD"
    merchant: str = Field(default="", max_length=200)
    token: str | None = Field(default=None, max_length=500)


class CallExternalApiInput(StrictInput):
    endpoint: HttpUrl
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    body: dict[str, Any] = Field(default_factory=dict)


class McpCallInput(StrictInput):
    server: str = Field(min_length=1, max_length=200)
    method: str = Field(min_length=1, max_length=200)
    parameters: dict[str, Any] = Field(default_factory=dict)


TOOL_INPUTS: dict[str, type[StrictInput]] = {
    "read_document": ReadDocumentInput,
    "read_file": ReadFileInput,
    "read_system_file": ReadSystemFileInput,
    "read_env_var": ReadEnvVarInput,
    "run_command": RunCommandInput,
    "delete_file": DeleteFileInput,
    "browse_url": BrowseUrlInput,
    "send_email": SendEmailInput,
    "export_data": ExportDataInput,
    "download_file": DownloadFileInput,
    "initiate_payment": InitiatePaymentInput,
    "call_external_api": CallExternalApiInput,
    "mcp_call": McpCallInput,
}


def _spec(
    name: str,
    category: str,
    description: str,
    permission: str,
    risk: int,
    *,
    approval: bool = False,
    egress: bool = False,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        category=category,
        description=description,
        permission=permission,
        risk_score=risk,
        requires_approval=approval,
        supports_egress=egress,
        input_schema=TOOL_INPUTS[name].model_json_schema(),
    )


REGISTRY: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in [
        _spec("read_document", "Documents", "Read an approved workspace document", "documents.read", 8),
        _spec("read_file", "Local files", "Read a file inside the authorized workspace scope", "local_files.read", 12),
        _spec("read_system_file", "System files", "Read a protected system file", "system_files.read", 90),
        _spec("read_env_var", "Environment & secrets", "Read an environment variable", "environment.read", 92),
        _spec("run_command", "Terminal", "Run a command in an isolated worker", "terminal.run", 70, approval=True),
        _spec("delete_file", "Local files", "Delete a file inside the workspace", "files.delete", 65, approval=True),
        _spec("browse_url", "Browser", "Fetch and inspect a web page", "browser.read", 35, egress=True),
        _spec("send_email", "Email", "Send an email through a controlled egress adapter", "email.send", 55, approval=True, egress=True),
        _spec("export_data", "Data loss prevention", "Export data to approved storage", "dlp.export", 45, approval=True, egress=True),
        _spec("download_file", "Downloads", "Download a file into quarantine first", "downloads.write", 40, egress=True),
        _spec("initiate_payment", "Payments", "Initiate a sandbox payment", "payments.execute", 60, approval=True, egress=True),
        _spec("call_external_api", "External APIs", "Call an allowlisted external API", "external_api.call", 50, approval=True, egress=True),
        _spec("mcp_call", "MCP", "Invoke an MCP tool", "mcp.call", 55, approval=True, egress=True),
    ]
}


DEFAULT_AGENT_PERMISSIONS = [
    "documents.read",
    "local_files.read",
    "browser.read",
    "dlp.export",
    "downloads.write",
    "email.send",
    "payments.execute",
]


def validate_tool_arguments(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if tool_name not in TOOL_INPUTS:
        raise ValueError("unknown tool")
    model = TOOL_INPUTS[tool_name].model_validate(arguments)
    return model.model_dump(mode="json", exclude_none=True)


def get_tool(tool_name: str) -> ToolSpec | None:
    return REGISTRY.get(tool_name)


def list_tools() -> list[ToolSpec]:
    return list(REGISTRY.values())
