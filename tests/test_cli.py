"""Tests for the CLI entry point."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from roustabout.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_docker_env(sample_environment):
    """Patch connection.connect + collect to return sample_environment."""
    mock_client = MagicMock()

    with (
        patch("roustabout.cli.main.connect", return_value=mock_client) as mock_connect,
        patch("roustabout.cli.main.collect", return_value=sample_environment) as mock_collect,
    ):
        yield {
            "client": mock_client,
            "connect": mock_connect,
            "collect": mock_collect,
        }


class TestSnapshotCommand:
    def test_snapshot_outputs_markdown(self, runner, mock_docker_env):
        result = runner.invoke(main, ["snapshot"])
        assert result.exit_code == 0
        assert "# Docker Environment" in result.output
        assert "nginx-proxy" in result.output

    def test_snapshot_with_show_env(self, runner, mock_docker_env):
        result = runner.invoke(main, ["snapshot", "--show-env"])
        assert result.exit_code == 0
        assert "Environment" in result.output

    def test_snapshot_with_no_labels(self, runner, mock_docker_env):
        result = runner.invoke(main, ["snapshot", "--no-labels"])
        assert result.exit_code == 0
        assert "#### Labels" not in result.output

    def test_snapshot_with_output_file(self, runner, mock_docker_env, tmp_path):
        out_file = tmp_path / "output.md"
        result = runner.invoke(main, ["snapshot", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        content = out_file.read_text()
        assert "# Docker Environment" in content
        assert f"Snapshot written to {out_file}" in result.output

    def test_snapshot_with_config_file(self, runner, mock_docker_env, tmp_path):
        config_file = tmp_path / "custom.toml"
        config_file.write_text("show_env = true\n")
        result = runner.invoke(main, ["snapshot", "--config", str(config_file)])
        assert result.exit_code == 0
        assert "Environment" in result.output

    def test_snapshot_with_docker_host(self, runner, mock_docker_env):
        result = runner.invoke(main, ["snapshot", "--docker-host", "tcp://myhost:2375"])
        assert result.exit_code == 0
        mock_docker_env["connect"].assert_called_once_with("tcp://myhost:2375")

    def test_snapshot_default_no_docker_host(self, runner, mock_docker_env):
        result = runner.invoke(main, ["snapshot"])
        assert result.exit_code == 0
        mock_docker_env["connect"].assert_called_once_with(None)

    def test_snapshot_redacts_secrets(self, runner, mock_docker_env):
        result = runner.invoke(main, ["snapshot", "--show-env"])
        assert result.exit_code == 0
        assert "hunter2" not in result.output
        assert "[REDACTED]" in result.output


class TestSnapshotErrors:
    def test_docker_connection_failure(self, runner):
        with patch(
            "roustabout.cli.main.connect",
            side_effect=Exception("Connection refused"),
        ):
            result = runner.invoke(main, ["snapshot"])
            assert result.exit_code != 0
            assert "Cannot connect to Docker" in result.output

    def test_missing_config_file(self, runner):
        result = runner.invoke(main, ["snapshot", "--config", "/nonexistent/config.toml"])
        assert result.exit_code != 0

    def test_invalid_config_file(self, runner, tmp_path):
        bad_config = tmp_path / "bad.toml"
        bad_config.write_text('show_env = "not a bool"\n')
        result = runner.invoke(main, ["snapshot", "--config", str(bad_config)])
        assert result.exit_code != 0
        assert "show_env must be a boolean" in result.output


class TestCLIFlags:
    def test_cli_flags_override_config(self, runner, mock_docker_env, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text("show_env = false\nshow_labels = true\n")
        result = runner.invoke(
            main, ["snapshot", "--config", str(config_file), "--show-env", "--no-labels"]
        )
        assert result.exit_code == 0
        assert "Environment" in result.output
        assert "#### Labels" not in result.output

    def test_config_redact_patterns_extend_defaults(self, runner, mock_docker_env, tmp_path):
        """Custom patterns extend defaults, not replace them."""
        config_file = tmp_path / "config.toml"
        config_file.write_text('redact_patterns = ["custom_field"]\nshow_env = true\n')
        result = runner.invoke(main, ["snapshot", "--config", str(config_file)])
        assert result.exit_code == 0
        # Default patterns still apply (SECRET_KEY should be redacted)
        assert "[REDACTED]" in result.output


class TestVersionFlag:
    def test_version(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        import re

        assert re.search(r"\d+\.\d+\.\d+", result.output)


class TestHelpText:
    def test_main_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Roustabout" in result.output

    def test_snapshot_help(self, runner):
        result = runner.invoke(main, ["snapshot", "--help"])
        assert result.exit_code == 0
        assert "--show-env" in result.output
        assert "--no-labels" in result.output
        assert "--output" in result.output
        assert "--config" in result.output
        assert "--docker-host" in result.output

    def test_audit_help(self, runner):
        result = runner.invoke(main, ["audit", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output
        assert "--docker-host" in result.output


class TestAuditCommand:
    def test_audit_outputs_findings(self, runner, mock_docker_env):
        result = runner.invoke(main, ["audit"])
        assert result.exit_code == 0
        assert "# Security Audit" in result.output

    def test_audit_with_output_file(self, runner, mock_docker_env, tmp_path):
        out_file = tmp_path / "audit.md"
        result = runner.invoke(main, ["audit", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        assert "Audit written to" in result.output

    def test_audit_docker_failure(self, runner):
        with patch(
            "roustabout.cli.main.connect",
            side_effect=Exception("Connection refused"),
        ):
            result = runner.invoke(main, ["audit"])
            assert result.exit_code != 0
            assert "Cannot connect to Docker" in result.output


class TestGenerateCommand:
    def test_generate_outputs_yaml(self, runner, mock_docker_env):
        result = runner.invoke(main, ["generate"])
        assert result.exit_code == 0
        assert "services:" in result.output
        assert "nginx" in result.output

    def test_generate_with_output_file(self, runner, mock_docker_env, tmp_path):
        out_file = tmp_path / "compose.yml"
        result = runner.invoke(main, ["generate", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        assert "services:" in out_file.read_text()
        assert "Compose file written to" in result.output

    def test_generate_default_redacts_secrets(self, runner, mock_docker_env):
        result = runner.invoke(main, ["generate"])
        assert result.exit_code == 0
        assert "hunter2" not in result.output
        assert "[REDACTED]" in result.output

    def test_generate_no_redact_includes_secrets(self, runner, mock_docker_env):
        result = runner.invoke(main, ["generate", "--no-redact"])
        assert result.exit_code == 0
        assert "hunter2" in result.output

    def test_generate_docker_failure(self, runner):
        with patch(
            "roustabout.cli.main.connect",
            side_effect=Exception("Connection refused"),
        ):
            result = runner.invoke(main, ["generate"])
            assert result.exit_code != 0
            assert "Cannot connect to Docker" in result.output

    def test_generate_help(self, runner):
        result = runner.invoke(main, ["generate", "--help"])
        assert result.exit_code == 0
        assert "--redact" in result.output
        assert "--include-stopped" in result.output


class TestRemoteMode:
    """When ROUSTABOUT_URL is set, commands route through HTTPBackend."""

    def test_snapshot_uses_backend_when_url_set(self, runner):
        mock_backend = MagicMock()
        mock_backend.snapshot.return_value = {"containers": [{"name": "nginx"}]}

        with patch.dict("os.environ", {"ROUSTABOUT_URL": "http://localhost:8077"}):
            with patch("roustabout.cli.main.get_backend", return_value=mock_backend) as mock_get:
                result = runner.invoke(main, ["snapshot"])

        assert result.exit_code == 0
        mock_get.assert_called_once_with(command_is_mutation=False)
        mock_backend.snapshot.assert_called_once()
        assert "nginx" in result.output

    def test_audit_uses_backend_when_url_set(self, runner):
        mock_backend = MagicMock()
        mock_backend.audit.return_value = {"findings": []}

        with patch.dict("os.environ", {"ROUSTABOUT_URL": "http://localhost:8077"}):
            with patch("roustabout.cli.main.get_backend", return_value=mock_backend):
                result = runner.invoke(main, ["audit"])

        assert result.exit_code == 0
        mock_backend.audit.assert_called_once()

    def test_logs_uses_backend_when_url_set(self, runner):
        mock_backend = MagicMock()
        mock_backend.logs.return_value = {"container": "nginx", "lines": "log line 1"}

        with patch.dict("os.environ", {"ROUSTABOUT_URL": "http://localhost:8077"}):
            with patch("roustabout.cli.main.get_backend", return_value=mock_backend):
                result = runner.invoke(main, ["logs", "nginx", "--tail", "50"])

        assert result.exit_code == 0
        mock_backend.logs.assert_called_once_with(name="nginx", tail=50, since=None, grep=None)
        assert "log line 1" in result.output

    def test_health_uses_backend_when_url_set(self, runner):
        mock_backend = MagicMock()
        mock_backend.health.return_value = {"entries": [{"name": "nginx", "health": "healthy"}]}

        with patch.dict("os.environ", {"ROUSTABOUT_URL": "http://localhost:8077"}):
            with patch("roustabout.cli.main.get_backend", return_value=mock_backend):
                result = runner.invoke(main, ["health"])

        assert result.exit_code == 0
        mock_backend.health.assert_called_once_with(name=None)

    def test_dr_plan_uses_backend_when_url_set(self, runner):
        mock_backend = MagicMock()
        mock_backend.dr_plan.return_value = {"plan": "# Recovery Plan\nStep 1..."}

        with patch.dict("os.environ", {"ROUSTABOUT_URL": "http://localhost:8077"}):
            with patch("roustabout.cli.main.get_backend", return_value=mock_backend):
                result = runner.invoke(main, ["dr-plan"])

        assert result.exit_code == 0
        assert "# Recovery Plan" in result.output

    def test_snapshot_without_url_uses_direct(self, runner, mock_docker_env):
        """Without ROUSTABOUT_URL, snapshot uses direct core calls."""
        with patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("ROUSTABOUT_URL", None)
            result = runner.invoke(main, ["snapshot"])

        assert result.exit_code == 0
        # Direct mode produces markdown
        assert "# Docker Environment" in result.output

    def test_remote_backend_error_shows_message(self, runner):
        mock_backend = MagicMock()
        mock_backend.snapshot.side_effect = RuntimeError("Server unavailable: connection refused")

        with patch.dict("os.environ", {"ROUSTABOUT_URL": "http://localhost:8077"}):
            with patch("roustabout.cli.main.get_backend", return_value=mock_backend):
                result = runner.invoke(main, ["snapshot"])

        assert result.exit_code != 0
        assert "Server unavailable" in result.output


class TestMutationBackend:
    """Mutation commands route through backend when available."""

    def test_mutation_uses_backend(self, runner):
        mock_backend = MagicMock()
        mock_backend.mutate.return_value = {
            "result": "success",
            "container": "nginx",
            "action": "restart",
        }

        with patch("roustabout.cli.main.get_backend", return_value=mock_backend):
            result = runner.invoke(main, ["restart", "nginx"])

        assert result.exit_code == 0
        mock_backend.mutate.assert_called_once_with("nginx", "restart", dry_run=False)
        assert "Restarted nginx" in result.output

    def test_mutation_dry_run_via_backend(self, runner):
        mock_backend = MagicMock()
        mock_backend.mutate.return_value = {"result": "dry-run"}

        with patch("roustabout.cli.main.get_backend", return_value=mock_backend):
            result = runner.invoke(main, ["stop", "nginx", "--dry-run"])

        assert result.exit_code == 0
        assert "[dry-run]" in result.output

    def test_mutation_backend_error_shows_message(self, runner):
        mock_backend = MagicMock()
        mock_backend.mutate.side_effect = RuntimeError("Permission denied: insufficient tier")

        with patch("roustabout.cli.main.get_backend", return_value=mock_backend):
            result = runner.invoke(main, ["restart", "nginx"])

        assert result.exit_code != 0
        assert "Permission denied" in result.output

    def test_mutation_errors_when_no_server(self, runner):
        """When get_backend raises (no server), mutation fails — no direct fallback."""
        with patch(
            "roustabout.cli.main.get_backend",
            side_effect=RuntimeError("No roustabout server found"),
        ):
            result = runner.invoke(main, ["restart", "nginx"])

        assert result.exit_code != 0
        assert "No roustabout server found" in result.output

    def test_mutation_gateway_failure_shows_error(self, runner):
        mock_backend = MagicMock()
        mock_backend.mutate.return_value = {
            "result": "denied",
            "error": "container not found",
        }

        with patch("roustabout.cli.main.get_backend", return_value=mock_backend):
            result = runner.invoke(main, ["restart", "ghost"])

        assert result.exit_code != 0
        assert "container not found" in result.output

    def test_mutation_non_server_error_does_not_fallback(self, runner):
        """RuntimeError other than 'no server' should surface, not fall back."""
        with patch(
            "roustabout.cli.main.get_backend",
            side_effect=RuntimeError("httpx not installed"),
        ):
            result = runner.invoke(main, ["restart", "nginx"])

        assert result.exit_code != 0
        assert "httpx not installed" in result.output
