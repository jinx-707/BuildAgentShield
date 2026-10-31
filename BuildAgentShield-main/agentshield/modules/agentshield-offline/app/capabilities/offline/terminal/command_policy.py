"""
AgentShield Offline — Command Policy.

Determines whether a structured command request is allowed, restricted,
sandboxed-only, or denied.

Policy is configurable via configs/sandbox.yaml.
Default policy denies anything not explicitly listed.
"""

from __future__ import annotations

import re
import shlex
from enum import Enum
from pathlib import Path
from typing import Optional

import structlog
import yaml

from app.core.configuration import get_settings, load_yaml_config

log = structlog.get_logger(__name__)


class CommandDecision(str, Enum):
    ALLOW_RESTRICTED = "ALLOW_RESTRICTED"
    SANDBOX_ONLY = "SANDBOX_ONLY"
    DENY = "DENY"


_DEFAULT_POLICY: dict = {
    "allowed_restricted": [
        "pwd", "ls", "cat", "head", "tail", "grep", "find", "echo",
        "wc", "sort", "uniq", "cut", "awk", "sed", "diff", "date",
        "whoami", "env", "printenv",
    ],
    "sandbox_only": [
        "python", "python3", "node", "npm", "npx", "pip", "pip3",
        "git", "curl", "wget", "java", "mvn", "gradle", "go",
        "cargo", "ruby", "php", "perl", "bash", "sh",
    ],
    "denied": [
        "rm", "rmdir", "dd", "mkfs", "shred", "kill", "killall",
        "shutdown", "reboot", "halt", "poweroff",
        "sudo", "su", "doas", "pkexec",
        "chmod", "chown", "chattr",
        "iptables", "ip6tables", "nft",
        "mount", "umount",
        "docker", "podman", "kubectl", "helm",
        "ssh", "scp", "sftp", "rsync",
        "nc", "netcat", "ncat", "socat",
        "tcpdump", "wireshark", "tshark",
        "passwd", "useradd", "usermod", "userdel",
        "crontab", "at",
        "insmod", "rmmod", "modprobe",
    ],
    "argument_blocklist_patterns": [
        r"--privileged",
        r"--cap-add",
        r"/etc/",
        r"/root/",
        r"/proc/",
        r"/sys/",
        r"/dev/",
    ],
    "shell_injection_patterns": [
        r"[;&|`$]",
        r"\$\(",
        r"`",
        r"\beval\b",
        r"\bexec\b",
        r"\\n",
        r"\\r",
    ],
}


class CommandPolicy:
    """
    Evaluates structured command requests against a configurable policy.
    Deny by default.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        settings = get_settings()
        cfg = load_yaml_config(config_path or settings.sandbox_config)
        policy = cfg.get("command_policy", _DEFAULT_POLICY)

        self._allowed_restricted: set[str] = set(policy.get("allowed_restricted", []))
        self._sandbox_only: set[str] = set(policy.get("sandbox_only", []))
        self._denied: set[str] = set(policy.get("denied", []))
        self._arg_blocklist: list[re.Pattern] = [
            re.compile(p, re.IGNORECASE)
            for p in policy.get("argument_blocklist_patterns", [])
        ]
        self._injection_patterns: list[re.Pattern] = [
            re.compile(p)
            for p in policy.get("shell_injection_patterns", [])
        ]

        log.info(
            "command_policy_loaded",
            allowed=len(self._allowed_restricted),
            sandbox_only=len(self._sandbox_only),
            denied=len(self._denied),
        )

    def evaluate(
        self,
        executable: str,
        arguments: list[str],
    ) -> tuple[CommandDecision, str]:
        """
        Returns (decision, reason).
        """
        exe_lower = executable.lower().strip()
        exe_name = Path(exe_lower).name  # strip any path prefix

        # 1. Check for shell injection in executable
        for p in self._injection_patterns:
            if p.search(executable):
                return CommandDecision.DENY, f"Shell metacharacter in executable: {p.pattern}"

        # 2. Check for shell injection in arguments
        for arg in arguments:
            for p in self._injection_patterns:
                if p.search(arg):
                    return CommandDecision.DENY, f"Shell metacharacter in argument: {p.pattern}"

        # 3. Check argument blocklist
        for arg in arguments:
            for p in self._arg_blocklist:
                if p.search(arg):
                    return CommandDecision.DENY, f"Blocked argument pattern: {p.pattern}"

        # 4. Denied executables
        if exe_name in self._denied:
            return CommandDecision.DENY, f"Executable '{exe_name}' is in the denylist"

        # 5. Sandbox-only executables
        if exe_name in self._sandbox_only:
            return CommandDecision.SANDBOX_ONLY, f"Executable '{exe_name}' requires sandbox"

        # 6. Restricted-allow executables
        if exe_name in self._allowed_restricted:
            return CommandDecision.ALLOW_RESTRICTED, f"Executable '{exe_name}' is in restricted-allow list"

        # 7. Deny by default
        return CommandDecision.DENY, f"Executable '{exe_name}' is not in any allowlist"
