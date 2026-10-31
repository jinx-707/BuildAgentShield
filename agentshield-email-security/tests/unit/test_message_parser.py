"""Unit tests for Gmail message parser."""

import base64
from app.providers.gmail.message_parser import GmailMessageParser


def test_parse_gmail_message_payload():
    body_content = "Hello from AgentShield Email Gateway!"
    encoded_body = base64.urlsafe_b64encode(body_content.encode("utf-8")).decode("ascii")

    raw_gmail_response = {
        "id": "msg-123456",
        "threadId": "th-987654",
        "snippet": "Hello from AgentShield...",
        "labelIds": ["INBOX", "UNREAD"],
        "payload": {
            "headers": [
                {"name": "From", "value": "Alice Sender <alice@example.com>"},
                {"name": "To", "value": "Bob Recipient <bob@example.com>, carol@example.com"},
                {"name": "Subject", "value": "Project Update"},
                {"name": "Date", "value": "Fri, 30 Oct 2026 14:00:00 +0000"},
            ],
            "mimeType": "multipart/alternative",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": encoded_body},
                }
            ],
        },
    }

    parsed = GmailMessageParser.to_email_message(raw_gmail_response)

    assert parsed.id == "msg-123456"
    assert parsed.thread_id == "th-987654"
    assert parsed.subject == "Project Update"
    assert parsed.sender.email == "alice@example.com"
    assert parsed.sender.name == "Alice Sender"
    assert len(parsed.to) == 2
    assert parsed.to[0].email == "bob@example.com"
    assert parsed.to[1].email == "carol@example.com"
    assert parsed.body_text == body_content
    assert "INBOX" in parsed.labels


def test_parse_message_with_attachment_metadata():
    raw_gmail_response = {
        "id": "msg-attachment",
        "payload": {
            "headers": [
                {"name": "From", "value": "sender@example.com"},
                {"name": "To", "value": "recipient@example.com"},
                {"name": "Subject", "value": "With Attachment"},
            ],
            "parts": [
                {
                    "mimeType": "application/pdf",
                    "filename": "specification.pdf",
                    "body": {"attachmentId": "att-id-999", "size": 102400},
                }
            ],
        },
    }

    parsed = GmailMessageParser.to_email_message(raw_gmail_response)
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "specification.pdf"
    assert att.content_type == "application/pdf"
    assert att.size_bytes == 102400
    assert att.attachment_id == "att-id-999"

