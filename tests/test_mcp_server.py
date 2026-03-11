"""Tests for the MCP server.

Tests the tool functions directly by mocking the Docker client,
verifying that output is redacted and correctly formatted.
"""

from unittest.mock import MagicMock, patch

import pytest

from roustabout.config import Config
from roustabout.models import (
    MountInfo,
    NetworkMembership,
    PortBinding,
    make_container,
    make_environment,
)


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

        result = docker_snapshot()
        assert "# Docker Environment" in result
        assert "nginx" in result
        assert "postgres" in result

    def test_redacts_secrets(self, mock_client):
        from roustabout.mcp_server import docker_snapshot

        result = docker_snapshot(show_env=True)
        assert "hunter2" not in result
        assert "supersecret" not in result
        assert "[REDACTED]" in result

    def test_env_hidden_by_default(self, mock_client):
        from roustabout.mcp_server import docker_snapshot

        result = docker_snapshot()
        assert "#### Environment" not in result

    def test_show_env_flag(self, mock_client):
        from roustabout.mcp_server import docker_snapshot

        result = docker_snapshot(show_env=True)
        assert "#### Environment" in result


class TestDockerAudit:
    def test_returns_findings(self, mock_client):
        from roustabout.mcp_server import docker_audit

        result = docker_audit()
        assert "# Security Audit" in result
        # Should find docker socket on postgres
        assert "docker-socket" in result

    def test_findings_are_structured(self, mock_client):
        from roustabout.mcp_server import docker_audit

        result = docker_audit()
        assert "## Critical" in result or "## Warning" in result or "No findings" in result


class TestDockerContainer:
    def test_existing_container(self, mock_client):
        from roustabout.mcp_server import docker_container

        result = docker_container("nginx")
        assert "nginx" in result
        assert "# Docker Environment" in result

    def test_nonexistent_container(self, mock_client):
        from roustabout.mcp_server import docker_container

        result = docker_container("nonexistent")
        assert "not found" in result
        assert "nginx" in result  # lists available containers

    def test_single_container_shows_env(self, mock_client):
        from roustabout.mcp_server import docker_container

        result = docker_container("nginx")
        assert "#### Environment" in result

    def test_secrets_redacted_in_single_container(self, mock_client):
        from roustabout.mcp_server import docker_container

        result = docker_container("nginx")
        assert "hunter2" not in result


class TestDockerNetworks:
    def test_returns_network_topology(self, mock_client):
        from roustabout.mcp_server import docker_networks

        result = docker_networks()
        assert "# Docker Networks" in result
        assert "frontend" in result
        assert "backend" in result
        assert "nginx" in result
        assert "postgres" in result

    def test_network_member_counts(self, mock_client):
        from roustabout.mcp_server import docker_networks

        result = docker_networks()
        assert "1 container:" in result


class TestDockerConnectionError:
    def test_snapshot_returns_error_string(self):
        from roustabout.mcp_server import docker_snapshot

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=Exception("connection refused"),
            ),
        ):
            result = docker_snapshot()
        assert "Error" in result
        assert "connection refused" in result

    def test_audit_returns_error_string(self):
        from roustabout.mcp_server import docker_audit

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=Exception("connection refused"),
            ),
        ):
            result = docker_audit()
        assert "Error" in result

    def test_container_returns_error_string(self):
        from roustabout.mcp_server import docker_container

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=Exception("connection refused"),
            ),
        ):
            result = docker_container("nginx")
        assert "Error" in result

    def test_networks_returns_error_string(self):
        from roustabout.mcp_server import docker_networks

        with (
            patch("roustabout.mcp_server._load_cfg", return_value=Config()),
            patch(
                "roustabout.mcp_server.connect",
                side_effect=Exception("connection refused"),
            ),
        ):
            result = docker_networks()
        assert "Error" in result


class TestMCPServerSetup:
    def test_mcp_instance_exists(self):
        from roustabout.mcp_server import mcp

        assert mcp.name == "roustabout"
