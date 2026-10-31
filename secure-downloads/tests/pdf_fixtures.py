"""
Minimal, self-contained PDF builders for tests.

The documents are hand-assembled with correct xref offsets so they parse
with pypdf without relying on lenient repair.  No third-party PDF writer is
used, keeping the fixtures independent of the parser under test.
"""
from __future__ import annotations

import io


def _escape_pdf_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(
    page_texts: tuple[str, ...] = ("Hello AgentShield",),
    *,
    extra_content: bytes = b"",
    count_override: int | None = None,
) -> bytes:
    """Build a valid PDF whose pages contain the given text (possibly empty)."""
    n = len(page_texts)
    page_ids = [3 + 2 * i for i in range(n)]
    font_id = 3 + 2 * n
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    count = n if count_override is None else count_override

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {count} >>".encode(),
    ]

    for index, text in enumerate(page_texts):
        page_id = 3 + 2 * index
        content_id = page_id + 1
        escaped = _escape_pdf_string(text)
        stream = (
            f"BT /F1 12 Tf 20 250 Td ({escaped}) Tj ET".encode()
            + extra_content
        )
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] "
                f"/Contents {content_id} 0 R "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> >>"
            ).encode()
        )
        objects.append(
            b"<< /Length "
            + str(len(stream)).encode()
            + b" >>\nstream\n"
            + stream
            + b"\nendstream"
        )

    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"

    xref_offset = len(out)
    total = len(objects) + 1
    out += f"xref\n0 {total}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {total} /Root 1 0 R >>\n".encode()
    out += f"startxref\n{xref_offset}\n%%EOF\n".encode()
    return bytes(out)


def make_encrypted_pdf(password: str = "secret") -> bytes:
    """Encrypt a valid one-page PDF with pypdf's writer."""
    from pypdf import PdfReader, PdfWriter

    reader = PdfReader(io.BytesIO(make_pdf()))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(password)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()
