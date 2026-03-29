"""Tests for the CLI entry point.

All commands go through HTTPBackend — tests mock get_backend().
"""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from roustabout.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_backend():
    """Provide a MagicMock HTTPBackend via get_backend."""
    backend = MagicMock()
    with patch("roustabout.cli.main.get_backend", return_value=backend):
        yield backend


class TestSnapshotCommand:
    def test_snapshot_outputs_json(self, runner, mock_backend):
        mock_backend.snapshot.return_value = {"containers": [{"name": "nginx"}]}
        result = runner.invoke(main, ["snapshot"])
        assert result.exit_code == 0
        mock_backend.snapshot.assert_called_once_with(fmt="markdown")

    def test_snapshot_json_format(self, runner, mock_backend):
        mock_backend.snapshot.return_value = {"containers": [{"name": "nginx"}]}
        result = runner.invoke(main, ["snapshot", "--format", "json"])
        assert result.exit_code == 0
        mock_backend.snapshot.assert_called_once_with(fmt="json")
        assert "nginx" in result.output

    def test_snapshot_markdown_format(self, runner, mock_backend):
        mock_backend.snapshot.return_value = "# Docker Environment\n\n## nginx"
        result = runner.invoke(main, ["snapshot", "--format", "markdown"])
        assert result.exit_code == 0
        assert "# Docker Environment" in result.output

    def test_snapshot_with_output_file(self, runner, mock_backend, tmp_path):
        mock_backend.snapshot.return_value = "# Docker Environment"
        out_file = tmp_path / "output.md"
        result = runner.invoke(main, ["snapshot", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        assert "# Docker Environment" in out_file.read_text()

    def test_snapshot_backend_error(self, runner, mock_backend):
        mock_backend.snapshot.side_effect = RuntimeError("Server unavailable")
        result = runner.invoke(main, ["snapshot"])
        assert result.exit_code != 0
        assert "Server unavailable" in result.output


class TestSnapshotErrors:
    def test_no_server_available(self, runner):
        with patch(
            "roustabout.cli.main.get_backend",
            side_effect=RuntimeError("No roustabout server found"),
        ):
            result = runner.invoke(main, ["snapshot"])
            assert result.exit_code != 0
            assert "No roustabout server found" in result.output


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
        assert "--output" in result.output
        assert "--format" in result.output

    def test_audit_help(self, runner):
        result = runner.invoke(main, ["audit", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output


class TestAuditCommand:
    def test_audit_outputs_markdown(self, runner, mock_backend):
        mock_backend.audit.return_value = "# Security Audit\n\n## Findings"
        result = runner.invoke(main, ["audit"])
        assert result.exit_code == 0
        assert "# Security Audit" in result.output

    def test_audit_json_format(self, runner, mock_backend):
        mock_backend.audit.return_value = {"findings": []}
        result = runner.invoke(main, ["audit", "--format", "json"])
        assert result.exit_code == 0
        assert "findings" in result.output

    def test_audit_with_output_file(self, runner, mock_backend, tmp_path):
        mock_backend.audit.return_value = "# Security Audit"
        out_file = tmp_path / "audit.md"
        result = runner.invoke(main, ["audit", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()

    def test_audit_backend_error(self, runner, mock_backend):
        mock_backend.audit.side_effect = RuntimeError("Connection refused")
        result = runner.invoke(main, ["audit"])
        assert result.exit_code != 0


class TestGenerateCommand:
    def test_generate_outputs_yaml(self, runner, mock_backend):
        mock_backend.generate.return_value = "services:\n  nginx:\n    image: nginx:latest"
        result = runner.invoke(main, ["generate"])
        assert result.exit_code == 0
        assert "services:" in result.output

    def test_generate_with_output_file(self, runner, mock_backend, tmp_path):
        mock_backend.generate.return_value = "services:\n  nginx:\n    image: nginx:latest"
        out_file = tmp_path / "compose.yml"
        result = runner.invoke(main, ["generate", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        assert "services:" in out_file.read_text()

    def test_generate_with_options(self, runner, mock_backend):
        mock_backend.generate.return_value = "services:\n  nginx:\n    image: nginx"
        result = runner.invoke(
            main, ["generate", "--project", "mystack", "--include-stopped", "--services", "a,b"]
        )
        assert result.exit_code == 0
        mock_backend.generate.assert_called_once_with(
            project="mystack", include_stopped=True, services="a,b"
        )

    def test_generate_help(self, runner):
        result = runner.invoke(main, ["generate", "--help"])
        assert result.exit_code == 0
        assert "--include-stopped" in result.output


class TestDrPlanCommand:
    def test_dr_plan_outputs_text(self, runner, mock_backend):
        mock_backend.dr_plan.return_value = {"plan": "# Recovery Plan\nStep 1..."}
        result = runner.invoke(main, ["dr-plan"])
        assert result.exit_code == 0
        assert "# Recovery Plan" in result.output

    def test_dr_plan_with_output_file(self, runner, mock_backend, tmp_path):
        mock_backend.dr_plan.return_value = {"plan": "# Recovery Plan"}
        out_file = tmp_path / "dr.md"
        result = runner.invoke(main, ["dr-plan", "--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()


class TestHealthCommand:
    def test_health_basic(self, runner, mock_backend):
        mock_backend.health.return_value = {
            "entries": [{"name": "nginx", "health": "healthy"}]
        }
        result = runner.invoke(main, ["health"])
        assert result.exit_code == 0
        mock_backend.health.assert_called_once_with(name=None)

    def test_health_with_container(self, runner, mock_backend):
        mock_backend.health.return_value = {
            "entries": [{"name": "nginx", "health": "healthy"}]
        }
        result = runner.invoke(main, ["health", "--container", "nginx"])
        assert result.exit_code == 0
        mock_backend.health.assert_called_once_with(name="nginx")

    def test_health_deep(self, runner, mock_backend):
        mock_backend.deep_health.return_value = {
            "results": [
                {
                    "container_name": "nginx",
                    "profile": "web",
                    "docker_health": "healthy",
                    "port_open": True,
                    "service_healthy": True,
                    "overall": "healthy",
                    "checks_performed": ["docker", "port", "http"],
                }
            ]
        }
        result = runner.invoke(main, ["health", "--deep"])
        assert result.exit_code == 0
        assert "nginx" in result.output
        assert "healthy" in result.output
        mock_backend.deep_health.assert_called_once_with(name=None)

    def test_health_deep_json(self, runner, mock_backend):
        mock_backend.deep_health.return_value = {
            "results": [{"container_name": "nginx", "overall": "healthy", "profile": "web"}]
        }
        result = runner.invoke(main, ["health", "--deep", "--json"])
        assert result.exit_code == 0
        assert "nginx" in result.output


class TestLogsCommand:
    def test_logs_basic(self, runner, mock_backend):
        mock_backend.logs.return_value = {"container": "nginx", "lines": "log line 1\nlog line 2"}
        result = runner.invoke(main, ["logs", "nginx"])
        assert result.exit_code == 0
        mock_backend.logs.assert_called_once_with(name="nginx", tail=100, since=None, grep=None)
        assert "log line 1" in result.output

    def test_logs_with_options(self, runner, mock_backend):
        mock_backend.logs.return_value = {"lines": "error log"}
        result = runner.invoke(
            main, ["logs", "nginx", "--tail", "50", "--since", "1h", "--grep", "error"]
        )
        assert result.exit_code == 0
        mock_backend.logs.assert_called_once_with(
            name="nginx", tail=50, since="1h", grep="error"
        )


class TestMutationCommands:
    def test_restart_uses_backend(self, runner, mock_backend):
        mock_backend.mutate.return_value = {"result": "success"}
        result = runner.invoke(main, ["restart", "nginx"])
        assert result.exit_code == 0
        mock_backend.mutate.assert_called_once_with("nginx", "restart", dry_run=False)
        assert "Restarted nginx" in result.output

    def test_stop_command(self, runner, mock_backend):
        mock_backend.mutate.return_value = {"result": "success"}
        result = runner.invoke(main, ["stop", "nginx"])
        assert result.exit_code == 0
        mock_backend.mutate.assert_called_once_with("nginx", "stop", dry_run=False)

    def test_start_command(self, runner, mock_backend):
        mock_backend.mutate.return_value = {"result": "success"}
        result = runner.invoke(main, ["start", "nginx"])
        assert result.exit_code == 0

    def test_recreate_command(self, runner, mock_backend):
        mock_backend.mutate.return_value = {"result": "success"}
        result = runner.invoke(main, ["recreate", "nginx"])
        assert result.exit_code == 0

    def test_mutation_dry_run(self, runner, mock_backend):
        mock_backend.mutate.return_value = {"result": "dry-run"}
        result = runner.invoke(main, ["stop", "nginx", "--dry-run"])
        assert result.exit_code == 0
        assert "[dry-run]" in result.output

    def test_mutation_backend_error(self, runner, mock_backend):
        mock_backend.mutate.side_effect = RuntimeError("Permission denied: insufficient tier")
        result = runner.invoke(main, ["restart", "nginx"])
        assert result.exit_code != 0
        assert "Permission denied" in result.output

    def test_mutation_errors_when_no_server(self, runner):
        with patch(
            "roustabout.cli.main.get_backend",
            side_effect=RuntimeError("No roustabout server found"),
        ):
            result = runner.invoke(main, ["restart", "nginx"])
        assert result.exit_code != 0
        assert "No roustabout server found" in result.output

    def test_mutation_gateway_failure(self, runner, mock_backend):
        mock_backend.mutate.return_value = {"result": "denied", "error": "container not found"}
        result = runner.invoke(main, ["restart", "ghost"])
        assert result.exit_code != 0
        assert "container not found" in result.output


class TestNetCheckCommand:
    def test_net_check_all_pairs(self, runner, mock_backend):
        mock_backend.net_check.return_value = {
            "connectivity": [
                {"source": "app", "target": "db", "reachable": True, "reason": "shared network"}
            ]
        }
        result = runner.invoke(main, ["net-check"])
        assert result.exit_code == 0
        assert "app" in result.output
        assert "db" in result.output
        mock_backend.net_check.assert_called_once_with(source=None, target=None)

    def test_net_check_specific_pair(self, runner, mock_backend):
        mock_backend.net_check.return_value = {
            "connectivity": [
                {"source": "app", "target": "db", "reachable": True, "reason": "shared network"}
            ]
        }
        result = runner.invoke(main, ["net-check", "app", "db"])
        assert result.exit_code == 0
        mock_backend.net_check.assert_called_once_with(source="app", target="db")

    def test_net_check_json(self, runner, mock_backend):
        mock_backend.net_check.return_value = {
            "connectivity": [
                {"source": "app", "target": "db", "reachable": True, "reason": "shared"}
            ]
        }
        result = runner.invoke(main, ["net-check", "--json"])
        assert result.exit_code == 0
        assert "reachable" in result.output

    def test_net_check_one_arg_fails(self, runner, mock_backend):
        result = runner.invoke(main, ["net-check", "app"])
        assert result.exit_code != 0
        assert "both SOURCE and TARGET" in result.output


class TestNetworkCommand:
    def test_network_inspect(self, runner, mock_backend):
        mock_backend.inspect_network.return_value = {
            "name": "bridge",
            "driver": "bridge",
            "subnet": "172.17.0.0/16",
            "gateway": "172.17.0.1",
            "internal": False,
            "containers": [{"container_name": "nginx", "ipv4_address": "172.17.0.2"}],
        }
        result = runner.invoke(main, ["network", "--inspect-network", "bridge"])
        assert result.exit_code == 0
        assert "bridge" in result.output
        assert "172.17.0.0/16" in result.output

    def test_network_container_view(self, runner, mock_backend):
        mock_backend.container_network.return_value = {
            "container_name": "nginx",
            "network_mode": "bridge",
            "networks": [{"name": "bridge", "ip_address": "172.17.0.2", "aliases": []}],
            "published_ports": [],
            "dns_servers": [],
            "network_details": [],
        }
        result = runner.invoke(main, ["network", "nginx"])
        assert result.exit_code == 0
        assert "nginx" in result.output

    def test_network_probe_dns(self, runner, mock_backend):
        mock_backend.probe_dns.return_value = {
            "source": "app",
            "query": "db",
            "resolved": True,
            "addresses": ["172.17.0.3"],
            "error": None,
        }
        result = runner.invoke(main, ["network", "app", "--probe-dns", "db"])
        assert result.exit_code == 0
        assert "172.17.0.3" in result.output

    def test_network_probe_connect(self, runner, mock_backend):
        mock_backend.probe_connect.return_value = {
            "source": "app",
            "target": "db",
            "port": 5432,
            "reachable": True,
            "error": None,
        }
        result = runner.invoke(main, ["network", "app", "--probe-connect", "db:5432"])
        assert result.exit_code == 0
        assert "reachable" in result.output

    def test_network_no_container_no_network(self, runner, mock_backend):
        result = runner.invoke(main, ["network"])
        assert result.exit_code != 0
        assert "container name" in result.output


class TestPortsCommand:
    def test_ports_basic(self, runner, mock_backend):
        mock_backend.ports.return_value = {
            "ports": [
                {
                    "container_port": 80,
                    "protocol": "tcp",
                    "host_ip": "0.0.0.0",
                    "host_port": 8080,
                    "exposed": True,
                    "published": True,
                }
            ]
        }
        result = runner.invoke(main, ["ports", "nginx"])
        assert result.exit_code == 0
        assert "80/tcp" in result.output

    def test_ports_json(self, runner, mock_backend):
        mock_backend.ports.return_value = {
            "ports": [
                {
                    "container_port": 80,
                    "protocol": "tcp",
                    "host_ip": "0.0.0.0",
                    "host_port": 8080,
                    "exposed": True,
                    "published": True,
                }
            ]
        }
        result = runner.invoke(main, ["ports", "nginx", "--json"])
        assert result.exit_code == 0
        assert "container_port" in result.output


class TestExecCommand:
    def test_exec_basic(self, runner, mock_backend):
        mock_backend.exec.return_value = {
            "success": True,
            "stdout": "hello world",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "error": None,
        }
        result = runner.invoke(main, ["exec", "nginx", "--", "echo", "hello"])
        assert result.exit_code == 0
        assert "hello world" in result.output
        mock_backend.exec.assert_called_once_with(
            "nginx", ["echo", "hello"], user=None, workdir=None, timeout=30
        )

    def test_exec_denied(self, runner, mock_backend):
        mock_backend.exec.return_value = {
            "success": False,
            "denied": True,
            "error": "Command blocked: sh is in denylist",
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "truncated": False,
        }
        result = runner.invoke(main, ["exec", "nginx", "--", "sh"])
        assert result.exit_code != 0
        assert "denied" in result.output.lower() or "blocked" in result.output.lower()

    def test_exec_with_options(self, runner, mock_backend):
        mock_backend.exec.return_value = {
            "success": True,
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "error": None,
        }
        runner.invoke(
            main, ["exec", "nginx", "--user", "nobody", "--timeout", "10", "--", "ls"]
        )
        mock_backend.exec.assert_called_once_with(
            "nginx", ["ls"], user="nobody", workdir=None, timeout=10
        )


class TestFileReadCommand:
    def test_file_read_basic(self, runner, mock_backend):
        mock_backend.file_read.return_value = {
            "success": True,
            "path": "/etc/hosts",
            "content": "127.0.0.1 localhost",
            "size": 19,
            "truncated": False,
        }
        result = runner.invoke(main, ["file-read", "/etc/hosts"])
        assert result.exit_code == 0
        assert "127.0.0.1" in result.output

    def test_file_read_error(self, runner, mock_backend):
        mock_backend.file_read.return_value = {
            "success": False,
            "error": "path outside read root",
        }
        result = runner.invoke(main, ["file-read", "/etc/shadow"])
        assert result.exit_code != 0
        assert "outside" in result.output


class TestFileWriteCommand:
    def test_file_write_staged(self, runner, mock_backend, tmp_path):
        content_file = tmp_path / "new.yml"
        content_file.write_text("services:\n  app:\n    image: nginx")
        mock_backend.file_write.return_value = {
            "success": True,
            "staged": True,
            "staging_path": "/staging/abc123",
            "diff": "--- old\n+++ new",
            "apply_command": "roustabout apply abc123",
            "path": "/opt/compose.yml",
        }
        result = runner.invoke(main, ["file-write", "/opt/compose.yml", str(content_file)])
        assert result.exit_code == 0
        assert "Staged" in result.output

    def test_file_write_direct(self, runner, mock_backend, tmp_path):
        content_file = tmp_path / "new.yml"
        content_file.write_text("content")
        mock_backend.file_write.return_value = {
            "success": True,
            "staged": False,
            "path": "/opt/config.yml",
            "backup_path": "/opt/config.yml.bak",
        }
        result = runner.invoke(
            main, ["file-write", "/opt/config.yml", str(content_file), "--direct"]
        )
        assert result.exit_code == 0
        assert "Written to" in result.output


class TestStatsCommand:
    def test_stats_basic(self, runner, mock_backend):
        mock_backend.stats.return_value = {
            "stats": [
                {
                    "name": "nginx",
                    "cpu_percent": 1.5,
                    "memory_usage_bytes": 50_000_000,
                    "memory_limit_bytes": 500_000_000,
                    "memory_percent": 10.0,
                    "network_rx_bytes": 1_000_000,
                    "network_tx_bytes": 500_000,
                    "block_read_bytes": None,
                    "block_write_bytes": None,
                }
            ]
        }
        result = runner.invoke(main, ["stats"])
        assert result.exit_code == 0
        assert "nginx" in result.output

    def test_stats_json(self, runner, mock_backend):
        mock_backend.stats.return_value = {
            "stats": [{"name": "nginx", "cpu_percent": 1.5, "memory_percent": 10.0}]
        }
        result = runner.invoke(main, ["stats", "--json"])
        assert result.exit_code == 0
        assert "cpu_percent" in result.output

    def test_stats_with_container(self, runner, mock_backend):
        mock_backend.stats.return_value = {"stats": []}
        runner.invoke(main, ["stats", "--container", "nginx"])
        mock_backend.stats.assert_called_once_with(container="nginx")


class TestMigrateCommand:
    def test_migrate_basic(self, runner, mock_backend):
        mock_backend.migrate.return_value = {
            "services": ["nginx", "redis"],
            "secrets_extracted": 5,
            "compose_path": "/out/compose.yml",
            "env_file_path": "/out/.env",
            "dry_run": True,
            "warnings": [],
        }
        result = runner.invoke(main, ["migrate", "-o", "/out"])
        assert result.exit_code == 0
        assert "nginx" in result.output
        assert "dry run" in result.output
        mock_backend.migrate.assert_called_once_with(
            "/out", services=None, include_stopped=False, dry_run=False
        )

    def test_migrate_with_options(self, runner, mock_backend):
        mock_backend.migrate.return_value = {
            "services": ["app"],
            "secrets_extracted": 0,
            "compose_path": "/out/compose.yml",
            "env_file_path": "/out/.env",
            "dry_run": False,
            "warnings": ["no secrets found"],
        }
        result = runner.invoke(
            main, ["migrate", "-o", "/out", "--services", "app", "--include-stopped"]
        )
        assert result.exit_code == 0


class TestConnectionManagement:
    def test_connect_help(self, runner):
        result = runner.invoke(main, ["connect", "--help"])
        assert result.exit_code == 0
        assert "Save a server connection" in result.output

    def test_disconnect_no_config(self, runner, tmp_path):
        with patch("roustabout.cli.main._CONNECTION_CONFIG", tmp_path / "nonexistent.toml"):
            result = runner.invoke(main, ["disconnect"])
        assert result.exit_code == 0
        assert "No saved connection" in result.output


class TestDiffCommand:
    def test_diff_help(self, runner):
        result = runner.invoke(main, ["diff", "--help"])
        assert result.exit_code == 0
        assert "Compare two JSON snapshots" in result.output
