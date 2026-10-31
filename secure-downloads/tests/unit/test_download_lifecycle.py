"""Tests for the Download state machine (model layer)."""
from __future__ import annotations

import pytest

from models.download import Download, DownloadState, DownloadStateError


def make_download(state: DownloadState = DownloadState.PENDING) -> Download:
    d = Download()
    d.id = "test-id"
    d.tenant_id = "tenant-1"
    d.agent_id = "agent-1"
    d.original_url = "https://example.com/file.pdf"
    d.state = state
    return d


class TestValidTransitions:
    def test_pending_to_validating(self):
        d = make_download(DownloadState.PENDING)
        d.transition_to(DownloadState.VALIDATING)
        assert d.state == DownloadState.VALIDATING

    def test_validating_to_downloading(self):
        d = make_download(DownloadState.VALIDATING)
        d.transition_to(DownloadState.DOWNLOADING)
        assert d.state == DownloadState.DOWNLOADING

    def test_downloading_to_downloaded(self):
        d = make_download(DownloadState.DOWNLOADING)
        d.transition_to(DownloadState.DOWNLOADED)
        assert d.state == DownloadState.DOWNLOADED

    def test_downloaded_to_verifying(self):
        d = make_download(DownloadState.DOWNLOADED)
        d.transition_to(DownloadState.VERIFYING)
        assert d.state == DownloadState.VERIFYING

    def test_verifying_to_scanning(self):
        d = make_download(DownloadState.VERIFYING)
        d.transition_to(DownloadState.SCANNING)
        assert d.state == DownloadState.SCANNING

    def test_scanning_to_approved(self):
        d = make_download(DownloadState.SCANNING)
        d.transition_to(DownloadState.APPROVED)
        assert d.state == DownloadState.APPROVED

    def test_scanning_to_quarantined(self):
        d = make_download(DownloadState.SCANNING)
        d.transition_to(DownloadState.QUARANTINED, reason="FOUND: Eicar.Test.File")
        assert d.state == DownloadState.QUARANTINED
        assert "Eicar" in d.failure_reason

    def test_approved_to_expired(self):
        d = make_download(DownloadState.APPROVED)
        d.transition_to(DownloadState.EXPIRED)
        assert d.state == DownloadState.EXPIRED

    def test_pending_to_rejected(self):
        d = make_download(DownloadState.PENDING)
        d.transition_to(DownloadState.REJECTED, reason="URL blocked")
        assert d.state == DownloadState.REJECTED
        assert "URL blocked" in d.failure_reason

    def test_downloading_to_failed(self):
        d = make_download(DownloadState.DOWNLOADING)
        d.transition_to(DownloadState.FAILED, reason="timeout")
        assert d.state == DownloadState.FAILED
        assert "timeout" in d.failure_reason


class TestInvalidTransitions:
    @pytest.mark.parametrize(
        "from_state, to_state",
        [
            (DownloadState.PENDING, DownloadState.SCANNING),
            (DownloadState.PENDING, DownloadState.APPROVED),
            (DownloadState.DOWNLOADING, DownloadState.APPROVED),
            (DownloadState.DOWNLOADED, DownloadState.APPROVED),   # must go through VERIFYING → SCANNING
            (DownloadState.APPROVED, DownloadState.SCANNING),
            (DownloadState.QUARANTINED, DownloadState.APPROVED),  # quarantine is terminal
            (DownloadState.REJECTED, DownloadState.DOWNLOADING),
            (DownloadState.FAILED, DownloadState.APPROVED),
            (DownloadState.EXPIRED, DownloadState.APPROVED),
        ],
    )
    def test_invalid_transition(self, from_state, to_state):
        d = make_download(from_state)
        with pytest.raises(DownloadStateError):
            d.transition_to(to_state)

    def test_cannot_go_backwards(self):
        d = make_download(DownloadState.SCANNING)
        with pytest.raises(DownloadStateError):
            d.transition_to(DownloadState.DOWNLOADING)

    def test_quarantined_cannot_become_approved(self):
        d = make_download(DownloadState.QUARANTINED)
        with pytest.raises(DownloadStateError):
            d.transition_to(DownloadState.APPROVED)

    def test_approved_cannot_become_quarantined(self):
        d = make_download(DownloadState.APPROVED)
        with pytest.raises(DownloadStateError):
            d.transition_to(DownloadState.QUARANTINED)
