"""Tests for container_exec module."""

from unittest.mock import MagicMock, patch

import pytest

from roustabout.container_exec import (
    DENIED_BINARIES,
    DENIED_PATTERNS,
    DeniedCommand,
    ExecCommand,
    ExecResult,
    MAX_OUTPUT_BYTES,
    _check_denylist,
    _process_output,
    execute,
)
from roustabout.session import DockerSession


# --- Denylist tests ---


class TestDenylist:
    def test_empty_command_denied(self):
        with pytest.raises(DeniedCommand, match="empty command"):
            _check_denylist(())

    @pytest.mark.parametrize("binary", sorted(DENIED_BINARIES))
    def test_denied_binaries(self, binary):
        with pytest.raises(DeniedCommand, match="denylist"):
            _check_denylist((binary,))

    def test_denied_binary_with_path(self):
        with pytest.raises(DeniedCommand, match="denylist"):
            _check_denylist(("/usr/bin/nsenter", "--target", "1"))

    @pytest.mark.parametrize("pattern", DENIED_PATTERNS)
    def test_denied_patterns(self, pattern):
        with pytest.raises(DeniedCommand, match="denied pattern"):
            _check_denylist(("cat", pattern))

    def test_shell_wrapper_passes_denylist(self):
        # Known limitation: shell wrappers bypass binary check
        _check_denylist(("bash", "-c", "nsenter --target 1"))

    @pytest.mark.parametrize(
        "cmd",
        [
            ("ls", "-la"),
            ("cat", "/etc/hosts"),
            ("getent", "hosts", "tandoor"),
            ("ps", "aux"),
            ("nslookup", "example.com"),
        ],
    )
    def test_allowed_commands(self, cmd):
        _check_denylist(cmd)  # Should not raise


# --- Output processing ---


class TestProcessOutput:
    def test_none_returns_empty(self):
        text, truncated = _process_output(None)
        assert text == ""
        assert truncated is False

    def test_normal_output(self):
        text, truncated = _process_output(b"hello world\n")
        assert text == "hello world\n"
        assert truncated is False

    def test_non_utf8_replaced(self):
        text, truncated = _process_output(b"hello \xff world")
        assert "\ufffd" in text or "?" in text  # replacement char
        assert truncated is False

    def test_truncation(self):
        data = b"x" * (MAX_OUTPUT_BYTES + 1000)
        text, truncated = _process_output(data)
        assert truncated is True
        assert len(text) <= MAX_OUTPUT_BYTES

    def test_ansi_escapes_stripped(self):
        text, truncated = _process_output(b"\x1b[31mred\x1b[0m")
        assert "\x1b" not in text
        assert "red" in text


# --- Execute tests ---


def _make_session(client=None):
    if client is None:
        client = MagicMock()
    return DockerSession(client=client, host="localhost")


class TestExecute:
    def test_container_not_found(self):
        import docker.errors

        client = MagicMock()
        client.containers.get.side_effect = docker.errors.NotFound("not found")
        session = _make_session(client)

        result = execute(session, ExecCommand(target="missing", command=("ls",)))
        assert result.success is False
        assert "not found" in result.error

    def test_container_not_running(self):
        container = MagicMock()
        container.status = "exited"
        client = MagicMock()
        client.containers.get.return_value = container
        session = _make_session(client)

        result = execute(session, ExecCommand(target="stopped", command=("ls",)))
        assert result.success is False
        assert "exited" in result.error

    def test_successful_exec(self):
        container = MagicMock()
        container.status = "running"
        container.exec_run.return_value = (0, (b"output\n", b""))
        client = MagicMock()
        client.containers.get.return_value = container
        session = _make_session(client)

        result = execute(session, ExecCommand(target="app", command=("echo", "hello")))
        assert result.success is True
        assert result.exit_code == 0
        assert "output" in result.stdout

    def test_failed_exec_nonzero_exit(self):
        container = MagicMock()
        container.status = "running"
        container.exec_run.return_value = (1, (b"", b"error msg\n"))
        client = MagicMock()
        client.containers.get.return_value = container
        session = _make_session(client)

        result = execute(session, ExecCommand(target="app", command=("false",)))
        assert result.success is False
        assert result.exit_code == 1

    def test_exec_with_none_output(self):
        container = MagicMock()
        container.status = "running"
        container.exec_run.return_value = (0, (None, None))
        client = MagicMock()
        client.containers.get.return_value = container
        session = _make_session(client)

        result = execute(session, ExecCommand(target="app", command=("true",)))
        assert result.success is True
        assert result.stdout == ""
        assert result.stderr == ""

    def test_exec_with_user_and_workdir(self):
        container = MagicMock()
        container.status = "running"
        container.exec_run.return_value = (0, (b"ok", b""))
        client = MagicMock()
        client.containers.get.return_value = container
        session = _make_session(client)

        cmd = ExecCommand(
            target="app",
            command=("whoami",),
            user="root",
            workdir="/tmp",
        )
        execute(session, cmd)
        kwargs = container.exec_run.call_args
        assert kwargs[1]["user"] == "root" or kwargs.kwargs.get("user") == "root"

    def test_denied_command_raises(self):
        session = _make_session()
        with pytest.raises(DeniedCommand):
            execute(session, ExecCommand(target="app", command=("nsenter",)))

    def test_timeout(self):
        container = MagicMock()
        container.status = "running"

        import time

        def slow_exec(**kwargs):
            time.sleep(5)
            return (0, (b"done", b""))

        container.exec_run.side_effect = slow_exec
        client = MagicMock()
        client.containers.get.return_value = container
        session = _make_session(client)

        result = execute(session, ExecCommand(target="app", command=("sleep", "100"), timeout=1))
        assert result.timed_out is True
        assert result.success is False

    def test_api_error_handled(self):
        import docker.errors

        container = MagicMock()
        container.status = "running"
        container.exec_run.side_effect = docker.errors.APIError("exec failed")
        client = MagicMock()
        client.containers.get.return_value = container
        session = _make_session(client)

        result = execute(session, ExecCommand(target="app", command=("ls",)))
        assert result.success is False
        assert result.error is not None
