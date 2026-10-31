"""
Integration tests — Local Filesystem Gateway.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.contracts import (
    FileCreateRequest,
    FileDeleteRequest,
    FileListRequest,
    FileMoveRequest,
    FileReadRequest,
    FileSearchRequest,
    FileUpdateRequest,
    ResponseStatus,
    SecurityDecision,
)


class TestFilesystemGatewayIntegration:
    @pytest.mark.asyncio
    async def test_reads_permitted_file(self, filesystem_gateway, sample_txt_file, tmp_workspace):
        req = FileReadRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="read",
            file_path=str(sample_txt_file),
        )
        resp = await filesystem_gateway.read_file(req)
        assert resp.decision == SecurityDecision.ALLOW
        assert "Hello" in resp.result["content"]

    @pytest.mark.asyncio
    async def test_denies_read_outside_permitted(self, filesystem_gateway, tmp_workspace):
        outside_file = tmp_workspace / "projects" / "secret.txt"
        outside_file.write_text("secret project data")
        req = FileReadRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="read",
            file_path=str(outside_file),
        )
        resp = await filesystem_gateway.read_file(req)
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.asyncio
    async def test_creates_file_in_permitted_dir(self, filesystem_gateway, tmp_workspace):
        new_file = tmp_workspace / "output" / "result.txt"
        req = FileCreateRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="create",
            file_path=str(new_file),
            content="Result data here",
        )
        resp = await filesystem_gateway.create_file(req)
        assert resp.decision == SecurityDecision.ALLOW
        assert new_file.exists()
        assert new_file.read_text() == "Result data here"

    @pytest.mark.asyncio
    async def test_denies_create_in_read_only_dir(self, filesystem_gateway, tmp_workspace):
        new_file = tmp_workspace / "documents" / "new.txt"
        req = FileCreateRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="create",
            file_path=str(new_file),
            content="Unauthorized write",
        )
        resp = await filesystem_gateway.create_file(req)
        assert resp.decision == SecurityDecision.DENY

    @pytest.mark.asyncio
    async def test_updates_file_in_permitted_dir(self, filesystem_gateway, tmp_workspace):
        f = tmp_workspace / "output" / "update_me.txt"
        f.write_text("original")
        req = FileUpdateRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="update",
            file_path=str(f),
            content="updated content",
        )
        resp = await filesystem_gateway.update_file(req)
        assert resp.decision == SecurityDecision.ALLOW
        assert f.read_text() == "updated content"

    @pytest.mark.asyncio
    async def test_deletes_file_in_permitted_dir(self, filesystem_gateway, tmp_workspace):
        f = tmp_workspace / "output" / "delete_me.txt"
        f.write_text("to be deleted")
        req = FileDeleteRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="delete",
            file_path=str(f),
        )
        resp = await filesystem_gateway.delete_file(req)
        assert resp.decision == SecurityDecision.ALLOW
        assert not f.exists()

    @pytest.mark.asyncio
    async def test_denies_delete_in_no_delete_dir(self, filesystem_gateway, tmp_workspace):
        f = tmp_workspace / "documents" / "important.txt"
        f.write_text("important")
        req = FileDeleteRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="delete",
            file_path=str(f),
        )
        resp = await filesystem_gateway.delete_file(req)
        assert resp.decision == SecurityDecision.DENY
        assert f.exists()  # file must NOT be deleted

    @pytest.mark.asyncio
    async def test_lists_permitted_directory(self, filesystem_gateway, tmp_workspace, sample_txt_file):
        req = FileListRequest(
            agent_id="test-agent",
            tool_name="file_list",
            operation="list",
            directory=str(tmp_workspace / "documents"),
        )
        resp = await filesystem_gateway.list_directory(req)
        assert resp.decision == SecurityDecision.ALLOW
        names = [e["name"] for e in resp.result["entries"]]
        assert "sample.txt" in names

    @pytest.mark.asyncio
    async def test_searches_for_files(self, filesystem_gateway, tmp_workspace, sample_txt_file):
        req = FileSearchRequest(
            agent_id="test-agent",
            tool_name="file_search",
            operation="search",
            directory=str(tmp_workspace / "documents"),
            pattern="*.txt",
        )
        resp = await filesystem_gateway.search_files(req)
        assert resp.decision == SecurityDecision.ALLOW
        assert "sample.txt" in resp.result["matches"]

    @pytest.mark.asyncio
    async def test_move_file(self, filesystem_gateway, tmp_workspace):
        src = tmp_workspace / "output" / "move_src.txt"
        src.write_text("move content")
        dst = tmp_workspace / "output" / "move_dst.txt"
        req = FileMoveRequest(
            agent_id="test-agent",
            tool_name="file_move",
            operation="move",
            source_path=str(src),
            destination_path=str(dst),
        )
        resp = await filesystem_gateway.move_file(req)
        assert resp.decision == SecurityDecision.ALLOW
        assert not src.exists()
        assert dst.exists()
        assert dst.read_text() == "move content"

    @pytest.mark.asyncio
    async def test_rejects_traversal_attack(self, filesystem_gateway, tmp_workspace):
        traversal = str(tmp_workspace / "documents" / ".." / ".." / "etc" / "passwd")
        req = FileReadRequest(
            agent_id="test-agent",
            tool_name="file_access",
            operation="read",
            file_path=traversal,
        )
        resp = await filesystem_gateway.read_file(req)
        assert resp.decision == SecurityDecision.DENY
