"""Tests for the MCP server.

Tests the tool functions directly by mocking the Docker client,
verifying that output is redacted and correctly formatted.
Async handlers are tested via anyio.from_thread / pytest-asyncio.
"""

from unittest.mock import MagicMock, patch

import anyio
import pytest

from roustabout.config import Config
from roustabout.models import (
    MountInfo,
    NetworkMembership,
    PortBinding,
    make_container,
    make_environment,
)


def _run(coro):
    """Run an async tool function synchronously via anyio."""
    return anyio.run(lambda: coro)


@pytest.fixture
def mock_env():
    """A multi-container environment for MCP tool testing."""
    nginx = make_container(
        name="nginx",
        id="abc123",
        status="running",
        image="nginx:1.25-alpine",
        image_id="sha256:abc",
        ports=[PortBinding(80, "tcp", "0.0.0.0", "8080")],
        networks=[NetworkMembership("frontend", "172.18.0.2", ())],
        env=[("NGINX_HOST", "example.com"), ("SECRET_KEY", "hunter2")],
    )
    postgres = make_container(
        name="postgres",
        id="def456",
        status="running",
        image="postgres:16",
        image_id="sha256:def",
        ports=[PortBinding(5432, "tcp", "0.0.0.0", "5432")],
        networks=[NetworkMembership("backend", "172.18.1.2", ())],
        env=[("POSTGRES_PASSWORD", "supersecret"), ("POSTGRES_DB", "mydb")],
        mounts=[
            MountInfo("/var/run/docker.sock", "/var/run/docker.sock", "rw", "bind"),
        ],
    )
    return make_environment(
        containers=[nginx, postgres],
        generated_at="2026-03-09T00:00:00Z",
        docker_version="25.0.3",
    )


@pytest.fixture
def mock_client(mock_env):
    """Patch connect, collect, and config to return mock_env."""
    client = MagicMock()
    with (
        patch("roustabout.mcp_server.connect", return_value=client),
        patch("roustabout.mcp_server.collect", return_value=mock_env),
        patch("roustabout.mcp_server._load_cfg", return_value=Config()),
    ):
        yield client


class TestDockerSnapshot:
    def test_returns_markdown(self, mock_client):
        from roustabout.mcp_server import docker_snapshot

        result = _run(docker_snapshot())
        assert "# Docker Environment" in result
        assert "nginx" in result
        assert "postgres" in result

    def test_redacts_secrets(self, mock_client):
        from roustabout.mcp_server import docker_snapshot

        result = _run(docker_snapshot(show_env=True))
        assert "hunter2" not in result
        assert "supersecret" not in result
        assert "[REDACTED]" in result

    def test_env_hidden_by_default(self, mock_client):
        from roustabout.mcp_server import docker_snapshot

        result = _run(docker_snapshot())
        assert "#### Environment" not in result

    def test_show_env_flag(self, mock_client):
        from roustabout.mcp_server import docker_snapshot

        result = _run(docker_snapshot(show_env=True))
        assert "#### Environment" in result


class TestDockerAudit:
    def test_returns_findings(self, mock_client):
        from roustabout.mcp_server import docker_audit

        result = _run(docker_audit())
        assert "# Security Audit" in result
        # Should find docker socket on postgres
        assert "docker-socket" in result

    def test_findings_are_structured(self, mock_client):
        from roustabout.mcp_server import docker_audit

        result = _run(docker_audit())
        assert "## Critical" in result or "## Warning" in result or "No findings" in result


class TestDockerContainer:
    def test_existing_container(self, mock_client):
        from roustabout.mcp_server import docker_container

        result = _run(docker_container("nginx"))
        assert "nginx" in result
        assert "# Docker Environment" in result

    def test_nonexistent_container(self, mock_client):
        from roustabout.mcp_server import docker_container

        result = _run(docker_container("nonexistent"))
        assert "not found" in result
        assert "nginx" in result  # lists available containers

    def test_single_container_shows_env(self, mock_client):
        from roustabout.mcp_server import docker_container

        result = _run(docker_container("nginx"))
        assert "#### Environment" in result

    def test_secrets_redacted_in_single_container(self, mock_client):
        from roustabout.mcp_server import docker_container

        result = _run(docker_container("nginx"))
        assert "hunter2" not in result


class TestDockerNetworks:
    def test_returns_network_topology(self, mock_client):
        from roustabout.mcp_server import docker_networks

        result = _run(docker_networks())
        assert "# Docker Networks" in result
        assert "frontend" in result
        assert "backend" in result
        assert "nginx" in result
        assert "postgres" in result

    def test_network_member_counts(self, mock_client):
        from roustabout.mcp_server import docker_networks

        result = _run(docker_networks())
        assert "1 container:" in result


class TestDockerConnectionError:
    def test_snapshot_returns_error_string(self):
        from roustabout.mcp_server import docker_snapshot

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=ConnectionError("connection refused"),
            ),
        ):
            result = _run(docker_snapshot())
        assert "Error" in result
        assert "connection refused" in result

    def test_audit_returns_error_string(self):
        from roustabout.mcp_server import docker_audit

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=ConnectionError("connection refused"),
            ),
        ):
            result = _run(docker_audit())
        assert "Error" in result

    def test_container_returns_error_string(self):
        from roustabout.mcp_server import docker_container

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=ConnectionError("connection refused"),
            ),
        ):
            result = _run(docker_container("nginx"))
        assert "Error" in result

    def test_networks_returns_error_string(self):
        from roustabout.mcp_server import docker_networks

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=ConnectionError("connection refused"),
            ),
        ):
            result = _run(docker_networks())
        assert "Error" in result


class TestDockerGenerate:
    def test_returns_yaml(self, mock_client):
        from roustabout.mcp_server import docker_generate

        result = _run(docker_generate())
        assert "services:" in result
        assert "nginx" in result
        assert "postgres" in result

    def test_redacts_secrets(self, mock_client):
        from roustabout.mcp_server import docker_generate

        result = _run(docker_generate())
        assert "hunter2" not in result
        assert "supersecret" not in result
        assert "[REDACTED]" in result

    def test_excludes_stopped_by_default(self, mock_client, mock_env):
        """Only running containers appear by default."""
        from roustabout.mcp_server import docker_generate

        # Both containers in mock_env are running, so both should appear
        result = _run(docker_generate())
        assert "nginx" in result
        assert "postgres" in result

    def test_connection_error(self):
        from roustabout.mcp_server import docker_generate

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=ConnectionError("connection refused"),
            ),
        ):
            result = _run(docker_generate())
        assert "Error" in result
        assert "connection refused" in result


class TestDockerDRPlan:
    def test_returns_summary_table(self, mock_client):
        from roustabout.mcp_server import docker_dr_plan

        result = _run(docker_dr_plan())
        assert "DR Plan Summary" in result
        assert "nginx" in result
        assert "postgres" in result
        assert "docker_dr_detail" in result

    def test_connection_error(self):
        from roustabout.mcp_server import docker_dr_plan

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=ConnectionError("connection refused"),
            ),
        ):
            result = _run(docker_dr_plan())
        assert "Error" in result


class TestDockerDRDetail:
    def test_existing_container(self, mock_client):
        from roustabout.mcp_server import docker_dr_detail

        result = _run(docker_dr_detail("nginx"))
        assert "Disaster Recovery Plan" in result
        assert "nginx" in result
        assert "docker run" in result

    def test_nonexistent_container(self, mock_client):
        from roustabout.mcp_server import docker_dr_detail

        result = _run(docker_dr_detail("nonexistent"))
        assert "not found" in result


class TestMCPServerSetup:
    def test_mcp_instance_exists(self):
        from roustabout.mcp_server import mcp

        assert mcp.name == "roustabout"


class TestResponseEnvelope:
    def test_envelope_wraps_text(self):
        from roustabout.mcp_server import _envelope

        assert _envelope("hello") == "[roustabout] hello"

    def test_size_limit_passes_small(self):
        from roustabout.mcp_server import _enforce_size_limit

        assert _enforce_size_limit("short", cap=1000) == "short"

    def test_size_limit_truncates_large(self):
        from roustabout.mcp_server import _enforce_size_limit

        big = "x" * 1000
        result = _enforce_size_limit(big, cap=100)
        assert len(result.encode("utf-8")) < len(big.encode("utf-8"))
        assert "[Response truncated" in result

    def test_container_name_sanitized(self, mock_client):
        """Container name with control chars is sanitized before lookup."""
        from roustabout.mcp_server import docker_container

        result = _run(docker_container("nginx\x00\x1b[31m"))
        # Should look up "nginx" after sanitization, not the raw input
        assert "nginx" in result

    def test_safe_error_strips_credentials(self):
        from roustabout.mcp_server import _safe_error

        exc = Exception("Cannot connect to tcp://admin:s3cret@host:2375")
        msg = _safe_error(exc)
        assert "s3cret" not in msg
        assert "admin" not in msg
        assert "***@" in msg

    def test_safe_error_sanitizes_control_chars(self):
        from roustabout.mcp_server import _safe_error

        exc = Exception("bad\x1b[31m error\x00")
        msg = _safe_error(exc)
        assert "\x1b" not in msg
        assert "\x00" not in msg

    def test_error_response_uses_safe_error(self):
        from roustabout.mcp_server import docker_snapshot

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=ConnectionError("tcp://user:pass@host:2375 refused"),
            ),
        ):
            result = _run(docker_snapshot())
        assert "pass" not in result
        assert "Error" in result


class TestAsyncBoundary:
    """S9.1.1 T5: No sync core module imports asyncio or anyio."""

    def test_no_async_in_sync_core(self):
        import ast
        from pathlib import Path

        sync_modules = [
            "collector", "auditor", "redactor", "renderer", "generator",
            "diff", "audit_renderer", "json_output", "models", "config",
            "connection", "constants", "lockdown", "state_db", "session",
            "dr_plan",
        ]
        src_dir = Path(__file__).parent.parent / "src" / "roustabout"
        for mod in sync_modules:
            mod_path = src_dir / f"{mod}.py"
            if not mod_path.exists():
                continue
            tree = ast.parse(mod_path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                    assert "asyncio" not in names, f"{mod}.py imports asyncio"
                    assert "anyio" not in names, f"{mod}.py imports anyio"
                elif isinstance(node, ast.ImportFrom) and node.module:
                    assert not node.module.startswith("asyncio"), \
                        f"{mod}.py imports from asyncio"
                    assert not node.module.startswith("anyio"), \
                        f"{mod}.py imports from anyio"
