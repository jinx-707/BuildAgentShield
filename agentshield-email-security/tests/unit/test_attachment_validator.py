"""Unit tests for AttachmentValidator."""

import base64
from app.schemas.email import EmailAttachmentInput
from app.security.attachment_validator import AttachmentValidator


def test_valid_pdf_attachment():
    validator = AttachmentValidator()
    payload = base64.b64encode(b"%PDF-1.4 test content").decode("ascii")
    att = EmailAttachmentInput(
        filename="report.pdf",
        content_type="application/pdf",
        content_base64=payload,
    )
    result = validator.validate_attachments([att])
    assert result.is_valid is True
    assert len(result.rejected_attachments) == 0


def test_reject_executable_extension():
    validator = AttachmentValidator()
    payload = base64.b64encode(b"MZ executable content").decode("ascii")
    att = EmailAttachmentInput(
        filename="updater.exe",
        content_type="application/octet-stream",
        content_base64=payload,
    )
    result = validator.validate_attachments([att])
    assert result.is_valid is False
    assert "updater.exe" in result.rejected_attachments
    assert any("Prohibited" in r for r in result.reasons)


def test_reject_double_extension_spoofing():
    validator = AttachmentValidator()
    payload = base64.b64encode(b"malicious script").decode("ascii")
    att = EmailAttachmentInput(
        filename="invoice.pdf.vbs",
        content_type="text/plain",
        content_base64=payload,
    )
    result = validator.validate_attachments([att])
    assert result.is_valid is False
    assert "invoice.pdf.vbs" in result.rejected_attachments
    assert any("Double-extension" in r for r in result.reasons)


def test_reject_dangerous_mime_type():
    validator = AttachmentValidator()
    payload = base64.b64encode(b"content").decode("ascii")
    att = EmailAttachmentInput(
        filename="safe_name.dat",
        content_type="application/x-msdownload",
        content_base64=payload,
    )
    result = validator.validate_attachments([att])
    assert result.is_valid is False
    assert any("MIME type" in r for r in result.reasons)


def test_reject_attachment_exceeding_max_size():
    # Set limit to 100 bytes
    validator = AttachmentValidator(max_size_bytes=100)
    large_payload = base64.b64encode(b"A" * 200).decode("ascii")
    att = EmailAttachmentInput(
        filename="large.pdf",
        content_type="application/pdf",
        content_base64=large_payload,
    )
    result = validator.validate_attachments([att])
    assert result.is_valid is False
    assert any("exceeds limit" in r for r in result.reasons)

