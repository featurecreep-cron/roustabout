"""Tests for mutations — container lifecycle operations.

Covers E2 S2.4.1: mutation operations with pre/post state.
All Docker operations are mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import docker.errors as _docker_errors

from roustabout.mutations import MutationResult, execute

# Helpers


def _make_docker_session():
    """Create a mock DockerSession."""
    from roustabout.session import DockerSession

    return DockerSession(client=MagicMock(), host="localhost")


def _mock_container(**overrides):
    """Create a mock container with sensible defaults."""
    container = MagicMock()
    container.name = overrides.get("name", "nginx")
    container.status = overrides.get("status", "running")
    container.short_id = overrides.get("short_id", "abc123")
    container.attrs = overrides.get(
        "attrs",
        {
            "State": {"Status": "running"},
            "Config": {"Image": "nginx:latest"},
        },
    )
    return container


# MutationResult dataclass


class TestMutationResult:
    def test_success(self):
        r = MutationResult(success=True, action="restart", target="nginx")
        assert r.success is True
        assert r.error is None

    def test_failure(self):
        r = MutationResult(
            success=False,
            action="stop",
            target="nginx",
            error="connection refused",
        )
        assert r.success is False
        assert "connection" in r.error


# stop


class TestStop:
    def test_stop_running_container(self):
        docker = _make_docker_session()
        container = _mock_container(status="running")
        docker.client.containers.get.return_value = container

        result = execute(docker, "stop", "nginx")

        assert result.success is True
        assert result.action == "stop"
        container.stop.assert_called_once()

    def test_stop_not_found(self):
        docker = _make_docker_session()
        docker.client.containers.get.side_effect = _docker_errors.NotFound("not found")

        result = execute(docker, "stop", "ghost")

        assert result.success is False
        assert "ghost" in (result.error or "")

    def test_stop_api_error(self):
        docker = _make_docker_session()
        container = _mock_container()
        docker.client.containers.get.return_value = container
        container.stop.side_effect = _docker_errors.APIError("server error")

        result = execute(docker, "stop", "nginx")

        assert result.success is False


# start


class TestStart:
    def test_start_stopped_container(self):
        docker = _make_docker_session()
        container = _mock_container(status="exited")
        docker.client.containers.get.return_value = container

        result = execute(docker, "start", "nginx")

        assert result.success is True
        container.start.assert_called_once()

    def test_start_not_found(self):
        docker = _make_docker_session()
        docker.client.containers.get.side_effect = _docker_errors.NotFound("not found")

        result = execute(docker, "start", "ghost")

        assert result.success is False


# restart


class TestRestart:
    def test_restart_container(self):
        docker = _make_docker_session()
        container = _mock_container()
        docker.client.containers.get.return_value = container

        result = execute(docker, "restart", "nginx")

        assert result.success is True
        container.restart.assert_called_once()

    def test_restart_not_found(self):
        docker = _make_docker_session()
        docker.client.containers.get.side_effect = _docker_errors.NotFound("not found")

        result = execute(docker, "restart", "ghost")

        assert result.success is False


# recreate


def _mock_container_for_recreate(**overrides):
    """Create a mock container with full attrs for recreate."""
    container = MagicMock()
    container.name = overrides.get("name", "nginx")
    container.status = "running"
    container.attrs = {
        "Name": "/nginx",
        "Config": {
            "Image": "nginx:latest",
            "Env": ["FOO=bar"],
            "Labels": {"app": "web"},
        },
        "HostConfig": {
            "Binds": ["/data:/data:rw"],
            "PortBindings": {
                "80/tcp": [{"HostIp": "", "HostPort": "8080"}],
            },
            "RestartPolicy": {"Name": "unless-stopped"},
            "NetworkMode": "my-network",
        },
        "NetworkSettings": {
            "Networks": {
                "my-network": {"Aliases": ["web"]},
                "monitoring": {"Aliases": []},
            },
        },
    }
    return container


class TestRecreate:
    def test_recreate_stops_removes_creates_starts(self):
        docker = _make_docker_session()
        old_container = _mock_container_for_recreate()
        new_container = MagicMock()
        docker.client.containers.get.return_value = old_container
        docker.client.containers.create.return_value = new_container

        result = execute(docker, "recreate", "nginx")

        assert result.success is True
        assert result.action == "recreate"
        old_container.stop.assert_called_once()
        old_container.remove.assert_called_once()
        docker.client.containers.create.assert_called_once()
        new_container.start.assert_called_once()

    def test_recreate_preserves_config(self):
        docker = _make_docker_session()
        old_container = _mock_container_for_recreate()
        new_container = MagicMock()
        docker.client.containers.get.return_value = old_container
        docker.client.containers.create.return_value = new_container

        execute(docker, "recreate", "nginx")

        kwargs = docker.client.containers.create.call_args[1]
        assert kwargs["image"] == "nginx:latest"
        assert kwargs["name"] == "nginx"
        assert kwargs["environment"] == ["FOO=bar"]
        assert kwargs["labels"] == {"app": "web"}
        assert kwargs["volumes"] == ["/data:/data:rw"]
        assert kwargs["restart_policy"] == {"Name": "unless-stopped"}

    def test_recreate_reconnects_networks(self):
        docker = _make_docker_session()
        old_container = _mock_container_for_recreate()
        new_container = MagicMock()
        network_mock = MagicMock()
        docker.client.containers.get.return_value = old_container
        docker.client.containers.create.return_value = new_container
        docker.client.networks.get.return_value = network_mock

        execute(docker, "recreate", "nginx")

        # monitoring network should be reconnected (my-network is via network_mode)
        docker.client.networks.get.assert_called_with("monitoring")
        network_mock.connect.assert_called_once()

    def test_recreate_not_found(self):
        docker = _make_docker_session()
        docker.client.containers.get.side_effect = _docker_errors.NotFound("not found")

        result = execute(docker, "recreate", "ghost")

        assert result.success is False
        assert result.error_type == "not_found"

    def test_recreate_api_error_on_remove(self):
        docker = _make_docker_session()
        container = _mock_container_for_recreate()
        docker.client.containers.get.return_value = container
        container.remove.side_effect = _docker_errors.APIError("in use")

        result = execute(docker, "recreate", "nginx")

        assert result.success is False
        assert result.error_type == "mutation_error"


# execute dispatch


class TestExecuteDispatch:
    def test_unknown_action(self):
        docker = _make_docker_session()
        result = execute(docker, "explode", "nginx")
        assert result.success is False
        assert "Unknown" in (result.error or "")

    def test_dispatch_routes_to_correct_method(self):
        docker = _make_docker_session()
        container = _mock_container()
        docker.client.containers.get.return_value = container

        for action in ("start", "stop", "restart"):
            result = execute(docker, action, "nginx")
            assert result.success is True
            assert result.action == action

    def test_dispatch_includes_recreate(self):
        docker = _make_docker_session()
        container = _mock_container_for_recreate()
        new_container = MagicMock()
        docker.client.containers.get.return_value = container
        docker.client.containers.create.return_value = new_container

        result = execute(docker, "recreate", "nginx")
        assert result.success is True
        assert result.action == "recreate"


# Error classification


class TestErrorClassification:
    def test_connection_error_classified(self):
        docker = _make_docker_session()
        docker.client.containers.get.side_effect = ConnectionError("connection refused")

        result = execute(docker, "restart", "nginx")

        assert result.success is False
        assert result.error_type == "connection_error"

    def test_not_found_classified(self):
        docker = _make_docker_session()
        docker.client.containers.get.side_effect = _docker_errors.NotFound("not found")

        result = execute(docker, "restart", "nginx")

        assert result.success is False
        assert result.error_type == "not_found"

    def test_api_error_classified(self):
        docker = _make_docker_session()
        container = _mock_container()
        docker.client.containers.get.return_value = container
        container.restart.side_effect = _docker_errors.APIError("fail")

        result = execute(docker, "restart", "nginx")

        assert result.success is False
        assert result.error_type == "mutation_error"

    def test_error_strings_are_sanitized(self):
        """Docker API errors must be sanitized before storage."""
        docker = _make_docker_session()
        container = _mock_container()
        docker.client.containers.get.return_value = container
        # Inject ANSI escape + control chars in error message
        container.restart.side_effect = _docker_errors.APIError("\x1b[31mred\x1b[0m error\x00null")

        result = execute(docker, "restart", "nginx")

        assert result.success is False
        assert "\x1b" not in (result.error or "")
        assert "\x00" not in (result.error or "")
