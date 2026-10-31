"""Download-specific configuration with validated limits and fail-closed defaults."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.downloads.exceptions import DownloadSettingsError

PDF_MIME = "application/pdf"
V1_ALLOWED_MIME_TYPES = frozenset({PDF_MIME})
ARCHIVE_MIME_TYPES = frozenset(
    {
        "application/zip",
        "application/x-zip-compressed",
        "application/x-7z-compressed",
        "application/gzip",
        "application/x-tar",
        "application/x-rar-compressed",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }
)

_MAX_FILE_BYTES_CEILING = 100 * 1024 * 1024  # 100 MiB hard ceiling
_ZONE_MODE_REQUIRED = 0o700
_FILE_MODE_REQUIRED = 0o600
_UNSAFE_PRODUCTION_PREFIXES = ("/tmp", "/var/tmp", "/private/tmp", "/var/folders")
_WEB_ROOT_MARKERS = frozenset({"static", "public", "www", "htdocs", "webroot"})


class DownloadSettings(BaseSettings):
    """Safe defaults: PDF-only, archives rejected, isolated storage, no TLS downgrade.

    Fetching, DNS pinning, and ClamAV execution belong to later phases. The flags
    here are configuration only and stay fail-closed so production cannot disable
    required isolation.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_ENV: str = Field(default="development")

    DOWNLOAD_STORAGE_ROOT: str = Field(default="storage/downloads")
    DOWNLOAD_TEMP_DIR: str = Field(default="temp")
    DOWNLOAD_QUARANTINE_DIR: str = Field(default="quarantine")
    DOWNLOAD_APPROVED_DIR: str = Field(default="approved")

    DOWNLOAD_DIR_MODE: int = Field(default=_ZONE_MODE_REQUIRED)
    DOWNLOAD_FILE_MODE: int = Field(default=_FILE_MODE_REQUIRED)

    DOWNLOAD_MAX_BYTES: int = Field(default=25 * 1024 * 1024)
    DOWNLOAD_EXPIRATION_HOURS: int = Field(default=24)
    DOWNLOAD_TEMP_RETENTION_HOURS: int = Field(default=24)
    DOWNLOAD_QUARANTINE_RETENTION_DAYS: int = Field(default=90)
    DOWNLOAD_MAX_TEMP_STORAGE_BYTES: int = Field(default=250 * 1024 * 1024)
    DOWNLOAD_MAX_CONCURRENT: int = Field(default=3)

    DOWNLOAD_ALLOWED_MIME_TYPES: List[str] = Field(default_factory=lambda: [PDF_MIME])
    DOWNLOAD_REJECT_ARCHIVES: bool = Field(default=True)

    # Fail-closed operational limits reserved for later phases (config only).
    DOWNLOAD_MAX_DURATION_SECONDS: int = Field(default=60)
    DOWNLOAD_CONNECT_TIMEOUT_SECONDS: float = Field(default=5.0)
    DOWNLOAD_READ_TIMEOUT_SECONDS: float = Field(default=30.0)
    DOWNLOAD_MAX_REDIRECTS: int = Field(default=3)
    DOWNLOAD_ALLOW_HTTPS_DOWNGRADE: bool = Field(default=False)
    DOWNLOAD_PIN_DNS: bool = Field(default=True)
    DOWNLOAD_VERIFY_TLS: bool = Field(default=True)
    DOWNLOAD_MAX_ARCHIVE_RATIO: int = Field(default=10)
    DOWNLOAD_MAX_ARCHIVE_ENTRIES: int = Field(default=100)
    DOWNLOAD_MAX_ARCHIVE_DEPTH: int = Field(default=1)
    CLAMAV_HOST: str = Field(default="127.0.0.1")
    CLAMAV_PORT: int = Field(default=3310)
    CLAMAV_TIMEOUT_SECONDS: float = Field(default=30.0)
    CLAMAV_SOCKET_PATH: str = Field(default="")
    CLAMAV_FAIL_CLOSED: bool = Field(default=True)

    @field_validator("DOWNLOAD_MAX_BYTES")
    @classmethod
    def _validate_max_bytes(cls, v: int) -> int:
        if v <= 0:
            raise DownloadSettingsError("DOWNLOAD_MAX_BYTES must be positive")
        if v > _MAX_FILE_BYTES_CEILING:
            raise DownloadSettingsError(
                f"DOWNLOAD_MAX_BYTES exceeds hard ceiling of {_MAX_FILE_BYTES_CEILING}"
            )
        return v

    @field_validator(
        "DOWNLOAD_MAX_DURATION_SECONDS",
        "DOWNLOAD_MAX_REDIRECTS",
        "DOWNLOAD_MAX_CONCURRENT",
        "DOWNLOAD_MAX_TEMP_STORAGE_BYTES",
        "DOWNLOAD_TEMP_RETENTION_HOURS",
        "DOWNLOAD_QUARANTINE_RETENTION_DAYS",
        "DOWNLOAD_EXPIRATION_HOURS",
        "DOWNLOAD_MAX_ARCHIVE_RATIO",
        "DOWNLOAD_MAX_ARCHIVE_ENTRIES",
        "DOWNLOAD_MAX_ARCHIVE_DEPTH",
        "CLAMAV_PORT",
    )
    @classmethod
    def _positive_int(cls, v: int) -> int:
        if v <= 0:
            raise DownloadSettingsError("Numeric download limits must be positive")
        return v

    @field_validator(
        "DOWNLOAD_CONNECT_TIMEOUT_SECONDS",
        "DOWNLOAD_READ_TIMEOUT_SECONDS",
        "CLAMAV_TIMEOUT_SECONDS",
    )
    @classmethod
    def _positive_float(cls, v: float) -> float:
        if v <= 0:
            raise DownloadSettingsError("Timeouts must be positive")
        return v

    @field_validator("DOWNLOAD_DIR_MODE")
    @classmethod
    def _dir_mode(cls, v: int) -> int:
        mode = int(v)
        if mode != _ZONE_MODE_REQUIRED:
            raise DownloadSettingsError(
                "DOWNLOAD_DIR_MODE must be 0o700; weaker isolation is not permitted"
            )
        return mode

    @field_validator("DOWNLOAD_FILE_MODE")
    @classmethod
    def _file_mode(cls, v: int) -> int:
        mode = int(v)
        if mode != _FILE_MODE_REQUIRED:
            raise DownloadSettingsError(
                "DOWNLOAD_FILE_MODE must be 0o600; weaker isolation is not permitted"
            )
        return mode

    @field_validator("DOWNLOAD_ALLOWED_MIME_TYPES")
    @classmethod
    def _pdf_only(cls, v: List[str]) -> List[str]:
        normalized = [item.strip().lower() for item in v if item and item.strip()]
        if not normalized:
            raise DownloadSettingsError("DOWNLOAD_ALLOWED_MIME_TYPES must not be empty")
        disallowed = [m for m in normalized if m not in V1_ALLOWED_MIME_TYPES]
        if disallowed:
            raise DownloadSettingsError(
                f"v1 allows PDF only; rejected MIME types: {disallowed}"
            )
        archives = [m for m in normalized if m in ARCHIVE_MIME_TYPES]
        if archives:
            raise DownloadSettingsError(f"Archive MIME types are forbidden in v1: {archives}")
        return normalized

    @field_validator("DOWNLOAD_REJECT_ARCHIVES")
    @classmethod
    def _archives_rejected(cls, v: bool) -> bool:
        if v is not True:
            raise DownloadSettingsError("v1 must reject archives (DOWNLOAD_REJECT_ARCHIVES=true)")
        return True

    @field_validator("DOWNLOAD_ALLOW_HTTPS_DOWNGRADE")
    @classmethod
    def _no_tls_downgrade(cls, v: bool) -> bool:
        if v:
            raise DownloadSettingsError("HTTPS-to-HTTP downgrades are not permitted")
        return False

    @field_validator("DOWNLOAD_PIN_DNS", "DOWNLOAD_VERIFY_TLS", "CLAMAV_FAIL_CLOSED")
    @classmethod
    def _security_flags_on(cls, v: bool, info) -> bool:
        if v is not True:
            raise DownloadSettingsError(f"{info.field_name} must remain true (fail-closed)")
        return True

    @field_validator(
        "DOWNLOAD_STORAGE_ROOT",
        "DOWNLOAD_TEMP_DIR",
        "DOWNLOAD_QUARANTINE_DIR",
        "DOWNLOAD_APPROVED_DIR",
    )
    @classmethod
    def _nonempty_path_component(cls, v: str) -> str:
        if not v or not str(v).strip():
            raise DownloadSettingsError("Storage paths must be non-empty")
        return str(v).strip()

    @field_validator("DOWNLOAD_TEMP_DIR", "DOWNLOAD_QUARANTINE_DIR", "DOWNLOAD_APPROVED_DIR")
    @classmethod
    def _relative_zone_dir(cls, v: str) -> str:
        raw = v.strip()
        p = Path(raw)
        if p.is_absolute() or p.drive:
            raise DownloadSettingsError(
                "Zone directories must be relative names under DOWNLOAD_STORAGE_ROOT"
            )
        parts = p.parts
        if ".." in parts or not parts:
            raise DownloadSettingsError("Zone directories must not contain '..'")
        if len(parts) != 1:
            raise DownloadSettingsError("Zone directories must be a single path segment")
        return raw

    @model_validator(mode="after")
    def _isolated_storage_layout(self) -> "DownloadSettings":
        zone_dirs = {
            self.DOWNLOAD_TEMP_DIR,
            self.DOWNLOAD_QUARANTINE_DIR,
            self.DOWNLOAD_APPROVED_DIR,
        }
        if len(zone_dirs) != 3:
            raise DownloadSettingsError(
                "Temporary, quarantine, and approved directories must be distinct"
            )

        root = _absolute(self.DOWNLOAD_STORAGE_ROOT)
        parts = {part.lower() for part in root.parts}
        if parts & _WEB_ROOT_MARKERS:
            raise DownloadSettingsError(
                f"Download storage must not live under a public web root: {root}"
            )

        if self.APP_ENV == "production":
            configured = Path(self.DOWNLOAD_STORAGE_ROOT).expanduser()
            if not configured.is_absolute():
                raise DownloadSettingsError(
                    "Production DOWNLOAD_STORAGE_ROOT must be an absolute path"
                )
            posix = str(root)
            if any(posix == p or posix.startswith(p + "/") for p in _UNSAFE_PRODUCTION_PREFIXES):
                raise DownloadSettingsError(
                    "Production download storage must not use a shared temporary directory"
                )
            if root == Path("/"):
                raise DownloadSettingsError("Production storage root cannot be filesystem root")

        if self.DOWNLOAD_MAX_TEMP_STORAGE_BYTES < self.DOWNLOAD_MAX_BYTES:
            raise DownloadSettingsError(
                "DOWNLOAD_MAX_TEMP_STORAGE_BYTES must be >= DOWNLOAD_MAX_BYTES"
            )
        return self

    def resolved_storage_root(self) -> Path:
        return _absolute(self.DOWNLOAD_STORAGE_ROOT)

    def resolved_temp_root(self) -> Path:
        return self.resolved_storage_root() / self.DOWNLOAD_TEMP_DIR

    def resolved_quarantine_root(self) -> Path:
        return self.resolved_storage_root() / self.DOWNLOAD_QUARANTINE_DIR

    def resolved_approved_root(self) -> Path:
        return self.resolved_storage_root() / self.DOWNLOAD_APPROVED_DIR


def _absolute(path: str) -> Path:
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    return p.resolve(strict=False)


@lru_cache
def get_download_settings() -> DownloadSettings:
    return DownloadSettings()
