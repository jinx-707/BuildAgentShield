"""
Unit tests — Document parsers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.capabilities.offline.documents.parser import DocumentParser
from app.core.exceptions import DocumentParseError


@pytest.fixture
def parser():
    return DocumentParser()


class TestDocumentParser:
    @pytest.mark.asyncio
    async def test_parses_txt(self, parser, tmp_path):
        f = tmp_path / "doc.txt"
        f.write_text("Line one\nLine two\nLine three")
        result = await parser.parse(f, "txt")
        assert "Line one" in result.text
        assert result.format == "txt"

    @pytest.mark.asyncio
    async def test_parses_md(self, parser, tmp_path):
        f = tmp_path / "readme.md"
        f.write_text("# Title\n\nSome **bold** content.")
        result = await parser.parse(f, "md")
        assert "Title" in result.text

    @pytest.mark.asyncio
    async def test_parses_csv(self, parser, tmp_path):
        f = tmp_path / "data.csv"
        f.write_text("name,score\nAlice,95\nBob,87\n")
        result = await parser.parse(f, "csv")
        assert "Alice" in result.text
        assert "Bob" in result.text

    @pytest.mark.asyncio
    async def test_parses_json(self, parser, tmp_path):
        f = tmp_path / "data.json"
        data = {"users": [{"name": "Alice"}, {"name": "Bob"}]}
        f.write_text(json.dumps(data))
        result = await parser.parse(f, "json")
        assert "Alice" in result.text

    @pytest.mark.asyncio
    async def test_rejects_invalid_json(self, parser, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid json}")
        with pytest.raises(DocumentParseError, match="JSON"):
            await parser.parse(f, "json")

    @pytest.mark.asyncio
    async def test_parses_xml(self, parser, tmp_path):
        f = tmp_path / "data.xml"
        f.write_text("<?xml version='1.0'?><root><item>hello</item><item>world</item></root>")
        result = await parser.parse(f, "xml")
        assert "hello" in result.text
        assert "world" in result.text

    @pytest.mark.asyncio
    async def test_rejects_malformed_xml(self, parser, tmp_path):
        f = tmp_path / "bad.xml"
        f.write_text("<root><unclosed>")
        with pytest.raises(DocumentParseError, match="XML"):
            await parser.parse(f, "xml")

    @pytest.mark.asyncio
    async def test_truncates_large_text(self, parser, tmp_path, monkeypatch):
        """Text exceeding max length should be truncated, not raise."""
        f = tmp_path / "big.txt"
        f.write_text("A" * 100)
        # Monkeypatch the max text length to a tiny value
        import app.capabilities.offline.documents.parser as pm
        monkeypatch.setattr(
            pm.DocumentParser,
            "_parse_sync",
            staticmethod(
                lambda path, fmt, max_pages, max_text: pm._parse_text(path, 10)
            ),
        )
        result = await parser.parse(f, "txt")
        assert len(result.text) <= 10 + len("\n[TEXT TRUNCATED]")

    @pytest.mark.asyncio
    async def test_unknown_format_raises(self, parser, tmp_path):
        f = tmp_path / "file.xyz"
        f.write_text("content")
        with pytest.raises(DocumentParseError, match="No parser"):
            await parser.parse(f, "xyz")
