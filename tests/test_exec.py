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

        config = ExecConfig(allowed=("pg_dump --schema-only *",))
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


# --- Allowlist matches whole argv elements, not a string prefix ---


class TestAllowlistArgvMatching:
    def test_argument_sharing_a_string_prefix_is_denied(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("airflow dags trigger my_dag",))
        with pytest.raises(DeniedCommand, match="does not match"):
            _check_allowlist(("airflow", "dags", "trigger", "my_dag_v2"), config)

    def test_binary_sharing_a_string_prefix_is_denied(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("cat",))
        with pytest.raises(DeniedCommand, match="does not match"):
            _check_allowlist(("catastrophe",), config)

    def test_path_prefix_is_denied(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("cat /etc/nginx",))
        with pytest.raises(DeniedCommand, match="does not match"):
            _check_allowlist(("cat", "/etc/nginx/../shadow"), config)

    def test_trailing_arguments_are_denied_without_a_wildcard(self):
        """`cat /config/app.log` must not also permit a second file."""
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("cat /config/app.log",))
        with pytest.raises(DeniedCommand, match="does not match"):
            _check_allowlist(("cat", "/config/app.log", "/etc/shadow"), config)

    def test_trailing_wildcard_allows_extra_arguments(self):
        from roustabout.exec import ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("airflow dags trigger *",))
        _check_allowlist(("airflow", "dags", "trigger", "my_dag", "--conf", "{}"), config)

    def test_trailing_wildcard_allows_no_extra_arguments(self):
        from roustabout.exec import ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("nginx -t *",))
        _check_allowlist(("nginx", "-t"), config)

    def test_wildcard_does_not_loosen_the_fixed_arguments(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("airflow dags trigger *",))
        with pytest.raises(DeniedCommand, match="does not match"):
            _check_allowlist(("airflow", "db", "reset"), config)

    def test_wildcard_is_literal_unless_last(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("ls * /tmp",))
        with pytest.raises(DeniedCommand, match="does not match"):
            _check_allowlist(("ls", "-la", "/tmp"), config)
        _check_allowlist(("ls", "*", "/tmp"), config)

    def test_bare_wildcard_matches_nothing(self):
        """`*` alone would turn the allowlist into allow-everything."""
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("*",))
        with pytest.raises(DeniedCommand):
            _check_allowlist(("ls",), config)

    def test_one_element_holding_the_whole_entry_is_denied(self):
        """A single argv element that merely spells the entry is not the entry."""
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("airflow dags trigger *",))
        with pytest.raises(DeniedCommand, match="does not match"):
            _check_allowlist(("airflow dags trigger",), config)

    def test_quoted_entry_is_one_element(self):
        from roustabout.exec import ExecConfig, _check_allowlist

        config = ExecConfig(allowed=('psql -c "select 1"',))
        _check_allowlist(("psql", "-c", "select 1"), config)

    def test_blank_entry_matches_nothing(self):
        from roustabout.exec import DeniedCommand, ExecConfig, _check_allowlist

        config = ExecConfig(allowed=("  ",))
        with pytest.raises(DeniedCommand):
            _check_allowlist(("ls",), config)


# --- Config loading fails closed ---


class TestLoadExecConfig:
    def _cfg(self, raw):
        from roustabout.config import Config

        return Config(raw=raw)

    def test_no_section_returns_none(self):
        from roustabout.exec import load_exec_config

        with patch("roustabout.config.load_config", return_value=self._cfg({})):
            assert load_exec_config("app") is None

    def test_section_is_loaded(self):
        from roustabout.exec import ExecConfig, load_exec_config

        raw = {"exec": {"app": {"allowed": ["nginx -t"], "user": "nobody", "timeout": 10}}}
        with patch("roustabout.config.load_config", return_value=self._cfg(raw)):
            assert load_exec_config("app") == ExecConfig(
                allowed=("nginx -t",), user="nobody", timeout=10
            )

    def test_unreadable_config_raises_instead_of_returning_none(self):
        """None means "no allowlist", which unlocks denylist mode. A config
        that cannot be read must not look like that."""
        from roustabout.exec import ExecConfigError, load_exec_config

        with patch("roustabout.config.load_config", side_effect=ValueError("bad toml")):
            with pytest.raises(ExecConfigError):
                load_exec_config("app")

    @pytest.mark.parametrize(
        "section",
        [
            "nginx -t",
            {"allowed": "nginx -t"},
            {"allowed": ["nginx -t", 5]},
            {"allowed": ["nginx -t"], "user": 0},
            {"allowed": ["nginx -t"], "timeout": "10"},
        ],
    )
    def test_malformed_section_raises(self, section):
        from roustabout.exec import ExecConfigError, load_exec_config

        raw = {"exec": {"app": section}}
        with patch("roustabout.config.load_config", return_value=self._cfg(raw)):
            with pytest.raises(ExecConfigError):
                load_exec_config("app")

    def test_exec_table_that_is_not_a_table_raises(self):
        from roustabout.exec import ExecConfigError, load_exec_config

        with patch("roustabout.config.load_config", return_value=self._cfg({"exec": []})):
            with pytest.raises(ExecConfigError):
                load_exec_config("app")


# --- Who may exec, and under which safety model ---


class TestAuthorizeExec:
    def _cmd(self, **kw):
        from roustabout.exec import ExecCommand

        return ExecCommand(target="airflow", command=("airflow", "dags", "trigger", "d"), **kw)

    def _config(self, **kw):
        from roustabout.exec import ExecConfig

        return ExecConfig(allowed=("airflow dags trigger *",), **kw)

    def test_observe_without_grant_is_refused(self):
        from roustabout.exec import ExecNotPermitted, authorize_exec

        with pytest.raises(ExecNotPermitted):
            authorize_exec(tier="observe", exec_grants=(), cmd=self._cmd(), config=self._config())

    def test_grant_for_another_container_is_refused(self):
        from roustabout.exec import ExecNotPermitted, authorize_exec

        with pytest.raises(ExecNotPermitted):
            authorize_exec(
                tier="observe", exec_grants=("postgres",), cmd=self._cmd(), config=self._config()
            )

    def test_unknown_tier_is_refused(self):
        from roustabout.exec import ExecNotPermitted, authorize_exec

        with pytest.raises(ExecNotPermitted):
            authorize_exec(tier="root", exec_grants=(), cmd=self._cmd(), config=self._config())

    def test_observe_with_grant_gets_allowlist(self):
        from roustabout.exec import authorize_exec

        _, friction = authorize_exec(
            tier="observe", exec_grants=("airflow",), cmd=self._cmd(), config=self._config()
        )
        assert friction is FrictionMechanism.ALLOWLIST

    def test_grant_never_unlocks_denylist_mode(self):
        """A granted container with no allowlist stays in allowlist mode,
        where execute() refuses everything."""
        from roustabout.exec import authorize_exec

        _, friction = authorize_exec(
            tier="observe", exec_grants=("airflow",), cmd=self._cmd(), config=None
        )
        assert friction is FrictionMechanism.ALLOWLIST

    def test_operate_without_grant_is_refused(self):
        """An allowlist alone grants nothing: the key must name the container."""
        from roustabout.exec import ExecNotPermitted, authorize_exec

        with pytest.raises(ExecNotPermitted):
            authorize_exec(tier="operate", exec_grants=(), cmd=self._cmd(), config=self._config())

    def test_operate_with_grant_gets_allowlist(self):
        from roustabout.exec import authorize_exec

        _, friction = authorize_exec(
            tier="operate", exec_grants=("airflow",), cmd=self._cmd(), config=self._config()
        )
        assert friction is FrictionMechanism.ALLOWLIST

    def test_restricted_caller_gets_the_configured_timeout(self):
        from roustabout.exec import authorize_exec

        cmd, _ = authorize_exec(
            tier="observe",
            exec_grants=("airflow",),
            cmd=self._cmd(timeout=3600),
            config=self._config(timeout=10),
        )
        assert cmd.timeout == 10

    def test_elevate_without_allowlist_gets_denylist(self):
        from roustabout.exec import authorize_exec

        _, friction = authorize_exec(tier="elevate", exec_grants=(), cmd=self._cmd(), config=None)
        assert friction is FrictionMechanism.DENYLIST

    def test_elevate_is_bound_by_a_configured_allowlist(self):
        from roustabout.exec import authorize_exec

        _, friction = authorize_exec(
            tier="elevate", exec_grants=(), cmd=self._cmd(), config=self._config()
        )
        assert friction is FrictionMechanism.ALLOWLIST

    @pytest.mark.parametrize("override", [{"user": "root"}, {"workdir": "/"}])
    def test_restricted_caller_cannot_choose_user_or_workdir(self, override):
        from roustabout.exec import DeniedCommand, authorize_exec

        with pytest.raises(DeniedCommand, match="user and workdir"):
            authorize_exec(
                tier="observe",
                exec_grants=("airflow",),
                cmd=self._cmd(**override),
                config=self._config(),
            )

    def test_restricted_caller_runs_as_the_configured_user(self):
        from roustabout.exec import authorize_exec

        cmd, _ = authorize_exec(
            tier="operate",
            exec_grants=("airflow",),
            cmd=self._cmd(),
            config=self._config(user="airflow"),
        )
        assert cmd.user == "airflow"

    def test_elevate_keeps_its_own_user_and_workdir(self):
        from roustabout.exec import authorize_exec

        cmd, _ = authorize_exec(
            tier="elevate",
            exec_grants=(),
            cmd=self._cmd(user="root", workdir="/tmp"),
            config=self._config(user="airflow"),
        )
        assert (cmd.user, cmd.workdir) == ("root", "/tmp")
