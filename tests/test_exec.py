"""Tests for container exec — command safety, execution, output handling.

Covers LLD-025: exec.py — denylist, allowlist, timeout, output sanitization.
All Docker operations are mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from roustabout.permissions import FrictionMechanism

# --- Dataclass tests ---


class TestExecCommand:
    def test_frozen(self):
        from roustabout.exec import ExecCommand

        cmd = ExecCommand(target="app", command=("ls",))
        with pytest.raises(AttributeError):
            cmd.target = "other"

    def test_defaults(self):
        from roustabout.exec import ExecCommand

        cmd = ExecCommand(target="app", command=("ls", "-la"))
        assert cmd.user is None
        assert cmd.workdir is None
        assert cmd.timeout == 30

    def test_custom_fields(self):
        from roustabout.exec import ExecCommand

        cmd = ExecCommand(
            target="db",
            command=("pg_isready",),
            user="postgres",
            workdir="/tmp",
            timeout=60,
        )
        assert cmd.user == "postgres"
        assert cmd.workdir == "/tmp"
        assert cmd.timeout == 60


class TestExecResult:
    def test_success_result(self):
        from roustabout.exec import ExecResult

        result = ExecResult(
            success=True,
            target="app",
            command=("ls",),
            exit_code=0,
            stdout="file.txt\n",
            stderr="",
            truncated=False,
        )
        assert result.success is True
        assert result.exit_code == 0

    def test_failure_result(self):
        from roustabout.exec import ExecResult

        result = ExecResult(
            success=False,
            target="app",
            command=("bad",),
            exit_code=None,
            stdout="",
            stderr="",
            truncated=False,
            error="not found",
            timed_out=True,
        )
        assert result.timed_out is True
        assert result.exit_code is None

    def test_frozen(self):
        from roustabout.exec import ExecResult

        result = ExecResult(
            success=True,
            target="app",
            command=("ls",),
            exit_code=0,
            stdout="",
            stderr="",
            truncated=False,
        )
        with pytest.raises(AttributeError):
            result.success = False


class TestExecConfig:
    def test_defaults(self):
        from roustabout.exec import ExecConfig

        config = ExecConfig()
        assert config.allowed == ()
        assert config.pre_mutation is None
        assert config.timeout == 30

    def test_custom(self):
        from roustabout.exec import ExecConfig

        config = ExecConfig(
            allowed=("pg_isready", "pg_dump --schema-only"),
            pre_mutation="pg_dump -f /backup.sql",
            timeout=60,
        )
        assert len(config.allowed) == 2


# --- Denylist tests ---


class TestDenylist:
    def test_denied_shell_interpreters(self):
        from roustabout.exec import DeniedCommand, _check_denylist

        for shell in (
            "sh",
            "bash",
            "zsh",
            "dash",
            "ash",
            "fish",
            "python",
            "python3",
            "perl",
            "ruby",
            "node",
        ):
            with pytest.raises(DeniedCommand, match="denylist"):
                _check_denylist((shell,))

    def test_denied_namespace_escape(self):
        from roustabout.exec import DeniedCommand, _check_denylist

        for binary in ("nsenter", "unshare", "chroot", "mount", "umount"):
            with pytest.raises(DeniedCommand, match="denylist"):
                _check_denylist((binary,))

    def test_denied_host_affecting(self):
        from roustabout.exec import DeniedCommand, _check_denylist

        for binary in ("reboot", "shutdown", "iptables", "nft"):
            with pytest.raises(DeniedCommand, match="denylist"):
                _check_denylist((binary,))

    def test_denied_patterns(self):
        from roustabout.exec import DeniedCommand, _check_denylist

        with pytest.raises(DeniedCommand, match="denied pattern"):
            _check_denylist(("cat", "/proc/sysrq-trigger"))
        with pytest.raises(DeniedCommand, match="denied pattern"):
            _check_denylist(("dd", "if=/dev/sda"))
        with pytest.raises(DeniedCommand, match="denied pattern"):
            _check_denylist(("ls", "/run/docker.sock"))

    def test_path_stripped_binary(self):
        from roustabout.exec import DeniedCommand, _check_denylist

        with pytest.raises(DeniedCommand):
            _check_denylist(("/usr/bin/nsenter", "--target", "1"))
        with pytest.raises(DeniedCommand):
            _check_denylist(("/bin/bash", "-c", "echo hi"))

    def test_normal_commands_pass(self):
        from roustabout.exec import _check_denylist

        for cmd in [
            ("ls", "-la"),
            ("cat", "/etc/hosts"),
            ("getent", "hosts", "tandoor"),
            ("ps", "aux"),
            ("pg_isready",),
            ("nginx", "-t"),
        ]:
            _check_denylist(cmd)  # should not raise

    def test_empty_command_denied(self):
        from roustabout.exec import DeniedCommand, _check_denylist

        with pytest.raises(DeniedCommand, match="empty"):
            _check_denylist(())


# --- Allowlist tests ---


class TestAllowlist:
    def test_exact_match(self):
        from roustabout.exec import ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("pg_isready",))
        _check_allowlist(("pg_isready",), config)  # should not raise

    def test_prefix_match(self):
        from roustabout.exec import ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("pg_dump --schema-only",))
        _check_allowlist(("pg_dump", "--schema-only", "-f", "/out.sql"), config)

    def test_prefix_no_match_different_args(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("pg_dump --schema-only",))
        with pytest.raises(DeniedCommand):
            _check_allowlist(("pg_dump", "--all-databases"), config)

    def test_prefix_no_match_different_path(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("cat /config/app.log",))
        with pytest.raises(DeniedCommand):
            _check_allowlist(("cat", "/etc/shadow"), config)

    def test_no_config(self):
        from roustabout.exec import DeniedCommand, _check_allowlist

        with pytest.raises(DeniedCommand, match="no exec allowlist"):
            _check_allowlist(("ls",), None)

    def test_empty_allowlist(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=())
        with pytest.raises(DeniedCommand, match="no exec allowlist"):
            _check_allowlist(("ls",), config)

    def test_empty_command(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("ls",))
        with pytest.raises(DeniedCommand, match="empty"):
            _check_allowlist((), config)


# --- Execute tests ---


class TestExecute:
    def _make_docker(self):
        return MagicMock()

    def test_container_not_found(self):
        import docker.errors

        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.side_effect = docker.errors.NotFound("nope")
        cmd = ExecCommand(target="ghost", command=("ls",))
        result = execute(ds, cmd)

        assert result.success is False
        assert "not found" in (result.error or "").lower()

    def test_container_not_running(self):
        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "exited"
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container
        cmd = ExecCommand(target="stopped", command=("ls",))
        result = execute(ds, cmd)

        assert result.success is False
        assert "not running" in (result.error or "").lower()

    def test_successful_exec(self):
        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.return_value = (0, (b"hello\n", b""))
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container
        cmd = ExecCommand(target="app", command=("echo", "hello"))
        result = execute(ds, cmd)

        assert result.success is True
        assert result.exit_code == 0
        assert "hello" in result.stdout

    def test_nonzero_exit(self):
        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.return_value = (1, (b"", b"error msg\n"))
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container
        cmd = ExecCommand(target="app", command=("false",))
        result = execute(ds, cmd)

        assert result.success is False
        assert result.exit_code == 1
        assert "error msg" in result.stderr

    def test_none_output_handled(self):
        """demux returning None for stdout/stderr."""
        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.return_value = (0, (None, None))
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container
        cmd = ExecCommand(target="app", command=("true",))
        result = execute(ds, cmd)

        assert result.success is True
        assert result.stdout == ""
        assert result.stderr == ""

    def test_output_sanitized(self):
        """Output passes through redactor.sanitize()."""
        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        # ANSI escape in output
        mock_container.exec_run.return_value = (
            0,
            (b"\x1b[31mred\x1b[0m\n", b""),
        )
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container
        cmd = ExecCommand(target="app", command=("ls",))
        result = execute(ds, cmd)

        assert "\x1b" not in result.stdout

    def test_output_truncation(self):
        from roustabout.exec import MAX_OUTPUT_BYTES, ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        big_output = b"x" * (MAX_OUTPUT_BYTES + 1000)
        mock_container.exec_run.return_value = (0, (big_output, b""))
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container
        cmd = ExecCommand(target="app", command=("dump",))
        result = execute(ds, cmd)

        assert result.truncated is True
        assert len(result.stdout) <= MAX_OUTPUT_BYTES

    def test_binary_output_decoded(self):
        """Non-UTF-8 bytes use replacement characters."""
        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.return_value = (
            0,
            (b"\xff\xfe binary\n", b""),
        )
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container
        cmd = ExecCommand(target="app", command=("cat", "/bin/ls"))
        result = execute(ds, cmd)

        assert result.success is True
        assert "\ufffd" in result.stdout  # replacement char

    def test_api_error_handled(self):
        import docker.errors

        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.side_effect = docker.errors.APIError("boom")
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container
        cmd = ExecCommand(target="app", command=("ls",))
        result = execute(ds, cmd)

        assert result.success is False
        assert result.error is not None

    def test_connection_error_handled(self):
        import requests.exceptions

        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.side_effect = requests.exceptions.ConnectionError("lost")
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container
        cmd = ExecCommand(target="app", command=("ls",))
        result = execute(ds, cmd)

        assert result.success is False
        assert result.error is not None

    def test_allowlist_friction_enforced(self):
        """ALLOWLIST friction loads config and checks allowlist."""
        from roustabout.exec import DeniedCommand, ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container

        cmd = ExecCommand(target="app", command=("rm", "-rf", "/"))

        # No config → denied
        with patch("roustabout.exec.load_exec_config", return_value=None):
            with pytest.raises(DeniedCommand):
                execute(ds, cmd, friction=FrictionMechanism.ALLOWLIST)

    def test_denylist_friction_blocks_shell(self):
        from roustabout.exec import DeniedCommand, ExecCommand, execute
        from roustabout.session import DockerSession

        ds = DockerSession(client=MagicMock(), host="localhost")
        cmd = ExecCommand(target="app", command=("bash", "-c", "echo hi"))

        with pytest.raises(DeniedCommand):
            execute(ds, cmd, friction=FrictionMechanism.DENYLIST)

    def test_user_and_workdir_passed(self):
        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.exec_run.return_value = (0, (b"ok\n", b""))
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container

        cmd = ExecCommand(
            target="app",
            command=("whoami",),
            user="root",
            workdir="/tmp",
        )
        execute(ds, cmd)

        call_kwargs = mock_container.exec_run.call_args
        assert call_kwargs.kwargs.get("user") == "root"
        assert call_kwargs.kwargs.get("workdir") == "/tmp"


# --- Timeout tests ---


class TestTimeout:
    def test_timeout_returns_timed_out(self):
        """Exec that exceeds timeout returns timed_out=True."""
        import time

        from roustabout.exec import ExecCommand, execute
        from roustabout.session import DockerSession

        mock_container = MagicMock()
        mock_container.status = "running"

        def slow_exec(**kwargs):
            time.sleep(5)
            return (0, (b"done", b""))

        mock_container.exec_run.side_effect = slow_exec
        ds = DockerSession(client=MagicMock(), host="localhost")
        ds.client.containers.get.return_value = mock_container

        cmd = ExecCommand(target="app", command=("sleep", "10"), timeout=1)
        result = execute(ds, cmd)

        assert result.success is False
        assert result.timed_out is True
        assert result.exit_code is None
