from pydantic import BaseModel, Field, model_validator

from app.schemas.browser import SESSION_ID_PATTERN


class ScreenshotClip(BaseModel):
    x: int = Field(ge=0, le=100000)
    y: int = Field(ge=0, le=100000)
    width: int = Field(ge=1, le=100000)
    height: int = Field(ge=1, le=100000)


class ScreenshotRequest(BaseModel):
    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    full_page: bool = False
    clip: ScreenshotClip | None = None
    timeout_ms: int = Field(default=10000, ge=1000, le=60000)

    @model_validator(mode="after")
    def validate_options(self) -> "ScreenshotRequest":
        if self.full_page and self.clip is not None:
            raise ValueError("full_page and clip cannot be combined")
        return self
