"""
AgentShield Offline — Directory scope and permission model.

Each agent has a workspace root and a set of permitted directories per
operation type.  All access must be scoped strictly within the workspace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import structlog

from app.core.configuration import get_settings, load_yaml_config
from app.core.contracts import FileOperation

log = structlog.get_logger(__name__)


@dataclass
class AgentFilesystemConfig:
    agent_id: str
    workspace: str
    read_paths: list[str] = field(default_factory=list)
    write_paths: list[str] = field(default_factory=list)
    delete_paths: list[str] = field(default_factory=list)
    allowed_extensions: list[str] = field(default_factory=list)
    denied_extensions: list[str] = field(default_factory=list)
    max_file_size_bytes: int = 10 * 1024 * 1024  # 10 MB

    @property
    def workspace_path(self) -> Path:
        return Path(self.workspace).resolve()


class DirectoryScopeRegistry:
    """
    Loads and caches agent filesystem configurations.
    A default permissive-ish dev config is created when no config exists,
    but production deployments should configure each agent explicitly.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        settings = get_settings()
        cfg_path = config_path or settings.offline_policy_path
        cfg = load_yaml_config(cfg_path)
        self._agents: dict[str, AgentFilesystemConfig] = {}
        for entry in cfg.get("agents", []):
            aid = entry.get("agent_id", "")
            if not aid:
                continue
            perms = entry.get("permissions", {})
            self._agents[aid] = AgentFilesystemConfig(
                agent_id=aid,
                workspace=entry.get("workspace", settings.default_workspace),
                read_paths=perms.get("read", []),
                write_paths=perms.get("write", []),
                delete_paths=perms.get("delete", []),
                allowed_extensions=entry.get("allowed_extensions", []),
                denied_extensions=entry.get("denied_extensions", []),
                max_file_size_bytes=entry.get("max_file_size_bytes", 10 * 1024 * 1024),
            )
        log.info("directory_scope_registry_loaded", agents=list(self._agents.keys()))

    def get_config(self, agent_id: str) -> Optional[AgentFilesystemConfig]:
        return self._agents.get(agent_id)

    def get_permitted_dirs(
        self, agent_id: str, operation: FileOperation
    ) -> list[Path]:
        cfg = self.get_config(agent_id)
        if not cfg:
            return []
        if operation in (FileOperation.READ, FileOperation.SEARCH, FileOperation.LIST, FileOperation.COPY):
            return [Path(p).resolve() for p in cfg.read_paths]
        if operation in (FileOperation.WRITE, FileOperation.CREATE, FileOperation.MOVE):
            return [Path(p).resolve() for p in cfg.write_paths]
        if operation == FileOperation.DELETE:
            return [Path(p).resolve() for p in cfg.delete_paths]
        return []
