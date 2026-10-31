"""Parser and normalizer for raw Gmail API message payloads."""

import base64
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
import logging
from typing import Any, Dict, List, Optional, Tuple
from app.schemas.email import EmailAddress, EmailAttachmentMetadata, EmailMessage

logger = logging.getLogger("agentshield.gmail.parser")


class GmailMessageParser:
    """Extracts structured email data, decoded bodies, and attachment metadata from Gmail payloads."""

    @staticmethod
    def _parse_address_list(header_val: Optional[str]) -> List[EmailAddress]:
        if not header_val:
            return []
        recipients = []
        # Support multiple comma-separated addresses
        raw_list = header_val.split(",")
        for item in raw_list:
            name, email = parseaddr(item.strip())
            if email:
                recipients.append(EmailAddress(email=email, name=name if name else None))
        return recipients

    @classmethod
    def parse_headers(cls, headers: List[Dict[str, str]]) -> Dict[str, Any]:
        """Index headers by lowercase name."""
        res = {}
        for h in headers:
            name = h.get("name", "").lower()
            val = h.get("value", "")
            res[name] = val
        return res

    @classmethod
    def _decode_body_data(cls, data_str: Optional[str]) -> str:
        if not data_str:
            return ""
        try:
            # Gmail uses URL-safe base64 encoding without padding
            padded = data_str + "=" * (-len(data_str) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            return decoded.decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Failed to decode message part: {e}")
            return ""

    @classmethod
    def _extract_parts(
        cls, payload: Dict[str, Any]
    ) -> Tuple[str, str, List[EmailAttachmentMetadata]]:
        body_text = ""
        body_html = ""
        attachments: List[EmailAttachmentMetadata] = []

        def recurse_parts(part: Dict[str, Any]):
            nonlocal body_text, body_html
            mime_type = part.get("mimeType", "")
            filename = part.get("filename", "")
            body = part.get("body", {})

            # If it has a filename, it's an attachment
            if filename:
                att_id = body.get("attachmentId")
                size = body.get("size", 0)
                attachments.append(
                    EmailAttachmentMetadata(
                        attachment_id=att_id,
                        filename=filename,
                        content_type=mime_type,
                        size_bytes=size,
                    )
                )
                return

            if mime_type == "text/plain":
                data = body.get("data")
                if data:
                    body_text += cls._decode_body_data(data)
            elif mime_type == "text/html":
                data = body.get("data")
                if data:
                    body_html += cls._decode_body_data(data)

            subparts = part.get("parts", [])
            for sp in subparts:
                recurse_parts(sp)

        recurse_parts(payload)
        return body_text, body_html, attachments

    @classmethod
    def to_email_message(cls, raw: Dict[str, Any]) -> EmailMessage:
        """Convert raw Gmail API response dict into normalized EmailMessage."""
        msg_id = raw.get("id", "")
        thread_id = raw.get("threadId")
        snippet = raw.get("snippet", "")
        labels = raw.get("labelIds", [])

        payload = raw.get("payload", {})
        headers_list = payload.get("headers", [])
        headers = cls.parse_headers(headers_list)

        # Parse sender
        from_header = headers.get("from", "")
        from_name, from_email = parseaddr(from_header)
        sender = EmailAddress(email=from_email or "unknown@sender.invalid", name=from_name if from_name else None)

        # Parse recipients
        to_list = cls._parse_address_list(headers.get("to"))
        cc_list = cls._parse_address_list(headers.get("cc"))
        bcc_list = cls._parse_address_list(headers.get("bcc"))

        # Parse Date
        received_at = None
        date_header = headers.get("date")
        if date_header:
            try:
                received_at = parsedate_to_datetime(date_header)
            except Exception:
                pass

        if not received_at and "internalDate" in raw:
            try:
                ms = int(raw["internalDate"])
                received_at = datetime.utcfromtimestamp(ms / 1000.0)
            except Exception:
                pass

        subject = headers.get("subject", "")

        # Extract text, html, attachments
        body_text, body_html, attachments = cls._extract_parts(payload)

        return EmailMessage(
            id=msg_id,
            thread_id=thread_id,
            subject=subject,
            sender=sender,
            to=to_list,
            cc=cc_list,
            bcc=bcc_list,
            received_at=received_at,
            snippet=snippet,
            body_text=body_text if body_text else None,
            body_html=body_html if body_html else None,
            attachments=attachments,
            labels=labels,
        )

