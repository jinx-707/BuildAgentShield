"""
AgentShield Offline — Protected Path Registry.

Maintains a configurable registry of operating-system paths and patterns
that must never be accessed by AI agents.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional

import structlog

from app.core.configuration import get_settings, load_yaml_config

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Default protected paths
# ---------------------------------------------------------------------------

_LINUX_PROTECTED_DIRS = [
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/boot",
    "/var/log",
    "/var/lib",
    "/var/run",
    "/var/spool",
    "/usr/lib",
    "/usr/share",
    "/lib",
    "/lib64",
    "/sbin",
    "/bin",
    "/usr/bin",
    "/usr/sbin",
]

_LINUX_SENSITIVE_PATTERNS = [
    r"\.ssh(/|$)",
    r"\.gnupg(/|$)",
    r"\.aws(/|$)",
    r"\.gcloud(/|$)",
    r"\.kube(/|$)",
    r"\.azure(/|$)",
    r"id_rsa",
    r"id_ed25519",
    r"id_ecdsa",
    r"authorized_keys",
    r"known_hosts",
    r"credentials$",
    r"config$",
    r"password",
    r"passwd$",
    r"shadow$",
    r"sudoers",
    r"\.env$",
    r"\.pem$",
    r"\.key$",
    r"\.pfx$",
    r"\.p12$",
]

_WINDOWS_PROTECTED_DIRS = [
    r"C:\Windows",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    r"C:\Users\Default",
]

_WINDOWS_SENSITIVE_PATTERNS = [
    r"SAM$",
    r"SYSTEM$",
    r"SECURITY$",
    r"ntds\.dit$",
    r"credentials$",
    r"vault$",
    r"\.rdp$",
    r"id_rsa",
    r"\.pem$",
    r"\.key$",
]


class ProtectedPathRegistry:
    """
    Registry of paths and patterns that agents must not access.
    Loaded from protected_paths.yaml with secure built-in defaults.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        settings = get_settings()
        cfg_path = config_path or settings.protected_paths_config
        cfg = load_yaml_config(cfg_path)

        is_windows = sys.platform.startswith("win")

        # Base protected directories
        builtin_dirs = _WINDOWS_PROTECTED_DIRS if is_windows else _LINUX_PROTECTED_DIRS
        extra_dirs = cfg.get("extra_protected_dirs", [])
        self._protected_dirs: list[Path] = [
            Path(d).resolve() for d in builtin_dirs + extra_dirs
        ]

        # Sensitive filename patterns
        builtin_patterns = (
            _WINDOWS_SENSITIVE_PATTERNS if is_windows else _LINUX_SENSITIVE_PATTERNS
        )
        extra_patterns = cfg.get("extra_sensitive_patterns", [])
        self._sensitive_patterns: list[re.Pattern] = [
            re.compile(p, re.IGNORECASE)
            for p in builtin_patterns + extra_patterns
        ]

        # Agent-specific exclusions (agent_id -> list of allowed paths)
        self._agent_exclusions: dict[str, list[Path]] = {}
        for exc in cfg.get("agent_exclusions", []):
            aid = exc.get("agent_id", "")
            paths = [Path(p).resolve() for p in exc.get("allowed_paths", [])]
            self._agent_exclusions[aid] = paths

        log.info(
            "protected_path_registry_loaded",
            protected_dirs=len(self._protected_dirs),
            sensitive_patterns=len(self._sensitive_patterns),
        )

    def is_protected(self, path: Path, agent_id: str = "") -> tuple[bool, str]:
        """
        Returns (is_protected, reason).
        A path is protected if it is under a protected directory OR
        matches a sensitive filename pattern, unless the agent has an
        explicit exclusion for it.
        """
        resolved = path.resolve()

        # Check agent exclusions first
        if agent_id and agent_id in self._agent_exclusions:
            for allowed in self._agent_exclusions[agent_id]:
                try:
                    resolved.relative_to(allowed)
                    return False, ""  # explicitly excluded
                except ValueError:
                    pass

        # Check protected directories
        for protected in self._protected_dirs:
            try:
                resolved.relative_to(protected)
                return True, f"Under protected directory: {protected}"
            except ValueError:
                pass

        # Check sensitive patterns against the full path string
        path_str = str(resolved)
        for pattern in self._sensitive_patterns:
            if pattern.search(path_str):
                return True, f"Matches sensitive pattern: {pattern.pattern}"

        return False, ""
