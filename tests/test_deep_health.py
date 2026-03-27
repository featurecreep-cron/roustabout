"""Tests for deep_health module."""

from unittest.mock import MagicMock, patch

import pytest

from roustabout.deep_health import (
    DeepHealthResult,
    EnvironmentHealth,
    HealthProfile,
    _check_port,
    _determine_overall,
    check_container_health,
    check_environment_health,
    resolve_profile,
)
from roustabout.session import DockerSession


# --- Overall determination ---


class TestDetermineOverall:
    def test_all_healthy(self):
        assert _determine_overall("healthy", True, True) == "healthy"

    def test_all_unhealthy(self):
        assert _determine_overall("unhealthy", False, False) == "unhealthy"

    def test_mixed_degraded(self):
        assert _determine_overall("healthy", False, None) == "degraded"

    def test_no_checks(self):
        assert _determine_overall(None, None, None) == "unknown"

    def test_docker_only_healthy(self):
        assert _determine_overall("healthy", None, None) == "healthy"

    def test_docker_only_unhealthy(self):
        assert _determine_overall("unhealthy", None, None) == "unhealthy"

    def test_port_only(self):
        assert _determine_overall(None, True, None) == "healthy"
        assert _determine_overall(None, False, None) == "unhealthy"


# --- Profile resolution ---


class TestResolveProfile:
    def test_label_match(self):
        profiles = {"web": HealthProfile(name="web", port_check=8080)}
        result = resolve_profile(
            "app",
            {"roustabout.health-profile": "web"},
            "custom-image:latest",
            profiles,
        )
        assert result is not None
        assert result.name == "web"

    def test_image_heuristic(self):
        profiles = {"database": HealthProfile(name="database", port_check=5432)}
        result = resolve_profile(
            "db",
            {},
            "postgres:16-alpine",
            profiles,
        )
        assert result is not None
        assert result.name == "database"

    def test_no_match(self):
        profiles = {"web": HealthProfile(name="web")}
        result = resolve_profile("custom", {}, "my-app:latest", profiles)
        assert result is None

    def test_label_takes_priority(self):
        profiles = {
            "web": HealthProfile(name="web"),
            "database": HealthProfile(name="database"),
        }
        result = resolve_profile(
            "db",
            {"roustabout.health-profile": "web"},
            "postgres:16",
            profiles,
        )
        assert result.name == "web"

    def test_unknown_label_falls_through(self):
        profiles = {"database": HealthProfile(name="database")}
        result = resolve_profile(
            "db",
            {"roustabout.health-profile": "nonexistent"},
            "postgres:16",
            profiles,
        )
        assert result.name == "database"


# --- Port check ---


class TestCheckPort:
    @patch("roustabout.deep_health.socket.create_connection")
    def test_port_open(self, mock_conn):
        mock_conn.return_value.__enter__ = MagicMock()
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        assert _check_port("localhost", 8080) is True

    @patch("roustabout.deep_health.socket.create_connection")
    def test_port_closed(self, mock_conn):
        mock_conn.side_effect = ConnectionRefusedError()
        assert _check_port("localhost", 8080) is False

    @patch("roustabout.deep_health.socket.create_connection")
    def test_port_timeout(self, mock_conn):
        mock_conn.side_effect = TimeoutError()
        assert _check_port("localhost", 8080) is False


# --- Container health check ---


class TestCheckContainerHealth:
    def test_observe_only(self):
        container = MagicMock()
        container.attrs = {
            "State": {"Health": {"Status": "healthy"}},
            "NetworkSettings": {"Ports": {}},
            "Config": {},
        }
        client = MagicMock()
        client.containers.get.return_value = container

        result = check_container_health(client, "app")
        assert result.docker_health == "healthy"
        assert result.service_healthy is None
        assert "docker_health" in result.checks_performed

    def test_with_port_check(self):
        container = MagicMock()
        container.attrs = {
            "State": {"Health": {"Status": "healthy"}},
            "NetworkSettings": {
                "Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
            },
            "Config": {},
        }
        client = MagicMock()
        client.containers.get.return_value = container

        profile = HealthProfile(name="web", port_check=8080)

        with patch("roustabout.deep_health._check_port", return_value=True):
            result = check_container_health(client, "app", profile=profile)
            assert result.port_open is True
            assert "port_check" in result.checks_performed

    def test_no_healthcheck(self):
        container = MagicMock()
        container.attrs = {
            "State": {},
            "NetworkSettings": {"Ports": {}},
            "Config": {},
        }
        client = MagicMock()
        client.containers.get.return_value = container

        result = check_container_health(client, "app")
        assert result.docker_health is None


# --- Environment health ---


class TestCheckEnvironmentHealth:
    def test_aggregation(self):
        c1 = MagicMock()
        c1.name = "app1"
        c1.attrs = {
            "State": {"Health": {"Status": "healthy"}},
            "NetworkSettings": {"Ports": {}},
            "Config": {"Labels": {}, "Image": "nginx:latest"},
        }
        c2 = MagicMock()
        c2.name = "app2"
        c2.attrs = {
            "State": {"Health": {"Status": "unhealthy"}},
            "NetworkSettings": {"Ports": {}},
            "Config": {"Labels": {}, "Image": "custom:latest"},
        }

        client = MagicMock()
        client.containers.list.return_value = [c1, c2]
        client.containers.get.side_effect = lambda name: c1 if name == "app1" else c2

        result = check_environment_health(client)
        assert result.total == 2
        assert result.healthy == 1
        assert result.unhealthy == 1
