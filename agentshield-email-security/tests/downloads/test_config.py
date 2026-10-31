"""Download configuration validation tests."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.downloads.config import (
    PDF_MIME,
    DownloadSettings,
    get_download_settings,
)
from app.downloads.exceptions import DownloadSettingsError


def _settings(**overrides) -> DownloadSettings:
    return DownloadSettings(_env_file=None, **overrides)


class TestDownloadSettingsDefaults:
    def test_safe_defaults(self):
        s = _settings()
        assert s.DOWNLOAD_MAX_BYTES == 25 * 1024 * 1024
        assert s.DOWNLOAD_EXPIRATION_HOURS == 24
        assert s.DOWNLOAD_ALLOWED_MIME_TYPES == [PDF_MIME]
        assert s.DOWNLOAD_REJECT_ARCHIVES is True
        assert s.DOWNLOAD_ALLOW_HTTPS_DOWNGRADE is False
        assert s.DOWNLOAD_PIN_DNS is True
        assert s.DOWNLOAD_VERIFY_TLS is True
        assert s.CLAMAV_FAIL_CLOSED is True
        assert s.DOWNLOAD_DIR_MODE == 0o700
        assert s.DOWNLOAD_FILE_MODE == 0o600
        assert s.DOWNLOAD_STORAGE_ROOT == "storage/downloads"
        assert s.DOWNLOAD_TEMP_DIR == "temp"
        assert s.DOWNLOAD_QUARANTINE_DIR == "quarantine"
        assert s.DOWNLOAD_APPROVED_DIR == "approved"

    def test_default_roots_are_distinct(self):
        s = _settings()
        roots = {
            s.resolved_temp_root(),
            s.resolved_quarantine_root(),
            s.resolved_approved_root(),
        }
        assert len(roots) == 3
        for root in roots:
            assert root.parent == s.resolved_storage_root()


class TestDownloadSettingsValidation:
    def test_rejects_zero_max_bytes(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_MAX_BYTES=0)

    def test_rejects_oversize_ceiling(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_MAX_BYTES=200 * 1024 * 1024)

    def test_rejects_non_pdf_mime(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_ALLOWED_MIME_TYPES=["application/zip"])

    def test_rejects_docx_mime(self):
        with pytest.raises(ValidationError):
            _settings(
                DOWNLOAD_ALLOWED_MIME_TYPES=[
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                ]
            )

    def test_rejects_disabling_archive_rejection(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_REJECT_ARCHIVES=False)

    def test_rejects_https_downgrade(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_ALLOW_HTTPS_DOWNGRADE=True)

    def test_rejects_fail_open_clamav(self):
        with pytest.raises(ValidationError):
            _settings(CLAMAV_FAIL_CLOSED=False)

    def test_rejects_disabled_tls_verify(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_VERIFY_TLS=False)

    def test_rejects_disabled_dns_pin(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_PIN_DNS=False)

    def test_rejects_world_writable_dir_mode(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_DIR_MODE=0o777)

    def test_rejects_identical_zone_dirs(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_TEMP_DIR="same", DOWNLOAD_QUARANTINE_DIR="same")

    def test_rejects_absolute_zone_dir(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_TEMP_DIR="/tmp/temp")

    def test_rejects_traversal_zone_dir(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_APPROVED_DIR="../approved")

    def test_rejects_nested_path_segment(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_QUARANTINE_DIR="nested/quarantine")

    def test_temp_budget_must_cover_one_file(self):
        with pytest.raises(ValidationError):
            _settings(DOWNLOAD_MAX_BYTES=1000, DOWNLOAD_MAX_TEMP_STORAGE_BYTES=500)

    def test_production_rejects_relative_storage_root(self):
        with pytest.raises(ValidationError):
            _settings(APP_ENV="production", DOWNLOAD_STORAGE_ROOT="storage/downloads")

    def test_production_rejects_tmp_storage_root(self, tmp_path: Path):
        with pytest.raises(ValidationError):
            _settings(APP_ENV="production", DOWNLOAD_STORAGE_ROOT="/tmp/downloads")

    def test_production_accepts_absolute_isolated_root(self):
        s = _settings(
            APP_ENV="production",
            DOWNLOAD_STORAGE_ROOT="/opt/agentshield/downloads",
        )
        assert s.resolved_storage_root() == Path("/opt/agentshield/downloads")

    def test_download_settings_error_is_value_error(self):
        assert issubclass(DownloadSettingsError, ValueError)


def test_get_download_settings_cache_can_clear():
    get_download_settings.cache_clear()
    first = get_download_settings()
    second = get_download_settings()
    assert first is second
    get_download_settings.cache_clear()
