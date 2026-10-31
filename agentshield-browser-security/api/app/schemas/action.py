from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from app.schemas.browser import InspectionResult, SESSION_ID_PATTERN

ActionName = Literal["click", "type", "scroll", "page_state", "submit_form"]
ScrollDirection = Literal["up", "down", "left", "right"]


class ActionTarget(BaseModel):
    selector: str | None = Field(default=None, min_length=1, max_length=500)
    role: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9-]{0,31}$"
    )
    name: str | None = Field(default=None, min_length=1, max_length=200)
    index: int | None = Field(default=None, ge=0, le=999)

    @model_validator(mode="after")
    def validate_target(self) -> "ActionTarget":
        if (self.selector is None) == (self.role is None):
            raise ValueError("target must contain either a selector or a role")
        if self.selector is not None and self.name is not None:
            raise ValueError("target name requires an accessible role")
        if self.selector is not None:
            selector = self.selector
            if selector.strip() == "":
                raise ValueError("target selector must be a non-empty string")
            if any(ord(char) < 32 or ord(char) == 127 for char in selector):
                raise ValueError("target selector contains control characters")
            if (
                ">>>" in selector
                or selector.startswith(("aria/", "text/", "xpath/", "pierce/"))
                or "::-p-" in selector
            ):
                raise ValueError("only plain CSS selectors are supported")
        return self


class BrowserActionRequest(BaseModel):
    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    action: ActionName
    target: ActionTarget | None = None
    # Flat selector/distance aliases keep the documented early API shape
    # working while the preferred shape remains the structured target object.
    selector: str | None = Field(default=None, min_length=1, max_length=500)
    index: int | None = Field(default=None, ge=0, le=999)
    text: str | None = None
    clear: bool = True
    direction: ScrollDirection | None = None
    amount: int | None = Field(default=None, ge=1, le=5000)
    distance: int | None = Field(default=None, ge=1, le=5000)
    confirm: bool = False
    timeout_ms: int = Field(default=10000, ge=1000, le=60000)

    def _effective_target(self) -> ActionTarget | None:
        if self.target is not None:
            return self.target
        if self.selector is not None:
            return ActionTarget(selector=self.selector, index=self.index)
        return None

    def _effective_amount(self) -> int | None:
        return self.amount if self.amount is not None else self.distance

    @model_validator(mode="after")
    def validate_action_fields(self) -> "BrowserActionRequest":
        if self.target is not None and (
            self.selector is not None or self.index is not None
        ):
            raise ValueError("target cannot be combined with selector or index")
        if self.amount is not None and self.distance is not None:
            raise ValueError("amount and distance cannot be combined")

        target = self._effective_target()
        if self.action in {"click", "submit_form"} and target is None:
            raise ValueError(f"{self.action} requires a target")
        if self.action == "type":
            if target is None:
                raise ValueError("type requires a target")
            if self.text is None or self.text == "":
                raise ValueError("type requires non-empty text")
        if self.action == "scroll":
            if self.direction is None:
                raise ValueError("scroll requires a direction")
            if self._effective_amount() is None:
                raise ValueError("scroll requires an amount")
        if self.action == "page_state" and target is not None:
            raise ValueError("page_state does not accept a target")
        return self

    def action_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"action": self.action}
        target = self._effective_target()
        if target is not None:
            payload["target"] = target.model_dump(exclude_none=True)
        if self.text is not None:
            payload["text"] = self.text
        if self.action == "type":
            payload["clear"] = self.clear
        if self.action == "scroll":
            payload["direction"] = self.direction
            payload["amount"] = self._effective_amount()
        if self.action == "submit_form":
            payload["confirm"] = self.confirm
        return payload


class WorkerActionResponse(BaseModel):
    request_id: str
    session_id: str
    action: ActionName
    success: bool
    target: dict[str, Any] | None = None
    final_url: str
    title: str = ""
    text: str = ""
    text_truncated: bool = False
    scroll: dict[str, Any] | None = None
    form: dict[str, Any] | None = None
    warnings: list[str] = Field(default_factory=list)
    hidden_content_excluded: bool = False
    hidden_element_count: int = 0
    elapsed_ms: int = 0
    redirect_count: int = 0
    blocked_request_count: int = 0
    blocked_target_count: int = 0


class ActionContent(BaseModel):
    text: str
    byte_length: int
    text_truncated: bool


class ActionSecurity(BaseModel):
    trust_label: str = "untrusted"
    content_classification: str = "untrusted"
    warnings: list[str] = Field(default_factory=list)
    hidden_content_excluded: bool = False
    hidden_element_count: int = 0


class ActionResponse(BaseModel):
    request_id: str
    session_id: str
    action: ActionName
    success: bool
    target: dict[str, Any] | None = None
    final_url: str
    title: str = ""
    content: ActionContent
    scroll: dict[str, Any] | None = None
    form: dict[str, Any] | None = None
    security: ActionSecurity
    inspection: InspectionResult
    elapsed_ms: int = 0
    redirect_count: int = 0
    blocked_request_count: int = 0
    blocked_target_count: int = 0
