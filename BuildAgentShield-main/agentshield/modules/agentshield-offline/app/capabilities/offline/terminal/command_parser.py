"""
AgentShield Offline — Command Parser.

Validates and normalises structured command requests before execution.
Shell string parsing is NOT performed — commands must already be structured.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import structlog

from app.core.exceptions import CommandDeniedError
from app.utils.validation import contains_null_byte, contains_suspicious_unicode

log = structlog.get_logger(__name__)

# Absolute max argument count
_MAX_ARGS = 64
_MAX_ARG_LEN = 4096
_MAX_WORKING_DIR_LEN = 512


class CommandParser:
    """
    Validates a structured command request for obvious injection attempts.
    Does NOT perform allowlist enforcement — that is CommandPolicy's job.
    """

    def validate(
        self,
        executable: str,
        arguments: list[str],
        working_directory: str,
    ) -> None:
        """Raises CommandDeniedError if validation fails."""

        # --- Executable ---
        if not executable or not executable.strip():
            raise CommandDeniedError("Executable is empty", executable=executable)
        if len(executable) > _MAX_ARG_LEN:
            raise CommandDeniedError("Executable name too long", executable=executable)
        if contains_null_byte(executable):
            raise CommandDeniedError("Null byte in executable", executable=executable)
        if contains_suspicious_unicode(executable):
            raise CommandDeniedError("Suspicious Unicode in executable", executable=executable)

        # --- Arguments ---
        if len(arguments) > _MAX_ARGS:
            raise CommandDeniedError(
                f"Too many arguments ({len(arguments)} > {_MAX_ARGS})",
                executable=executable,
            )
        for arg in arguments:
            if len(arg) > _MAX_ARG_LEN:
                raise CommandDeniedError(
                    "Argument too long", executable=executable
                )
            if contains_null_byte(arg):
                raise CommandDeniedError("Null byte in argument", executable=executable)
            if contains_suspicious_unicode(arg):
                raise CommandDeniedError("Suspicious Unicode in argument", executable=executable)

        # --- Working directory ---
        if len(working_directory) > _MAX_WORKING_DIR_LEN:
            raise CommandDeniedError("Working directory path too long", executable=executable)
        if contains_null_byte(working_directory):
            raise CommandDeniedError("Null byte in working directory", executable=executable)
