"""Tests for compose_gitops module."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from roustabout.compose_gitops import (
    ComposeProject,
    _normalize_env,
    _normalize_field,
    detect_drift,
    semantic_diff,
)

# --- Normalize helpers ---


class TestNormalizeEnv:
    def test_dict_input(self):
        result = _normalize_env({"FOO": "bar", "BAZ": 123})
        assert result == {"FOO": "bar", "BAZ": "123"}

    def test_list_input(self):
        result = _normalize_env(["FOO=bar", "BAZ=qux"])
        assert result == {"FOO": "bar", "BAZ": "qux"}

    def test_none_input(self):
        assert _normalize_env(None) == {}


class TestNormalizeField:
    def test_environment_list_to_dict(self):
        result = _normalize_field("environment", ["FOO=bar", "BAZ=qux"])
        assert result == {"BAZ": "qux", "FOO": "bar"}

    def test_environment_reorder_no_diff(self):
        a = _normalize_field("environment", ["B=2", "A=1"])
        b = _normalize_field("environment", ["A=1", "B=2"])
        assert a == b

    def test_ports_sorted(self):
        result = _normalize_field("ports", ["8080:80", "443:443"])
        assert result == ["443:443", "8080:80"]

    def test_volumes_sorted(self):
        result = _normalize_field("volumes", ["/data:/data", "/config:/config"])
        assert result == ["/config:/config", "/data:/data"]

    def test_non_special_passthrough(self):
        assert _normalize_field("image", "nginx:latest") == "nginx:latest"

    def test_none_passthrough(self):
        assert _normalize_field("anything", None) is None


# --- Drift detection ---


class TestDetectDrift:
    def _make_project(self, compose_content, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text(compose_content)
        return ComposeProject(
            name="test",
            path=compose_file,
            git_root=None,
            services=("web",),
        )

    def test_no_drift(self, tmp_path):
        project = self._make_project(
            "services:\n  web:\n    image: nginx:latest\n",
            tmp_path,
        )
        container = MagicMock()
        container.attrs = {
            "Config": {"Image": "nginx:latest", "Env": [], "Labels": {}},
            "HostConfig": {"RestartPolicy": {"Name": ""}, "Privileged": False, "NetworkMode": ""},
        }
        client = MagicMock()
        client.containers.get.return_value = container

        reports = detect_drift(client, project)
        assert len(reports) == 0

    def test_image_drift(self, tmp_path):
        project = self._make_project(
            "services:\n  web:\n    image: nginx:1.25\n",
            tmp_path,
        )
        container = MagicMock()
        container.attrs = {
            "Config": {"Image": "nginx:1.24", "Env": [], "Labels": {}},
            "HostConfig": {"RestartPolicy": {"Name": ""}, "Privileged": False, "NetworkMode": ""},
        }
        client = MagicMock()
        client.containers.get.return_value = container

        reports = detect_drift(client, project)
        assert len(reports) == 1
        assert reports[0].drifts[0].field == "image"
        assert reports[0].drifts[0].severity == "critical"

    def test_container_not_running(self, tmp_path):
        import docker.errors

        project = self._make_project(
            "services:\n  web:\n    image: nginx:latest\n",
            tmp_path,
        )
        client = MagicMock()
        client.containers.get.side_effect = docker.errors.NotFound("not found")

        reports = detect_drift(client, project)
        assert len(reports) == 1
        assert reports[0].drifts[0].field == "status"
        assert reports[0].drifts[0].running_value == "not running"

    def test_privileged_drift(self, tmp_path):
        project = self._make_project(
            "services:\n  web:\n    image: nginx:latest\n    privileged: true\n",
            tmp_path,
        )
        container = MagicMock()
        container.attrs = {
            "Config": {"Image": "nginx:latest", "Env": [], "Labels": {}},
            "HostConfig": {"RestartPolicy": {"Name": ""}, "Privileged": False, "NetworkMode": ""},
        }
        client = MagicMock()
        client.containers.get.return_value = container

        reports = detect_drift(client, project)
        assert any(d.field == "privileged" for d in reports[0].drifts)


# --- Semantic diff ---


class TestSemanticDiff:
    def test_no_changes(self):
        content = "services:\n  web:\n    image: nginx:latest\n"
        result = semantic_diff(content, content)
        assert len(result) == 0

    def test_image_change(self):
        old = "services:\n  web:\n    image: nginx:1.24\n"
        new = "services:\n  web:\n    image: nginx:1.25\n"
        result = semantic_diff(old, new)
        assert len(result) == 1
        assert result[0].service == "web"
        assert result[0].changes[0].field == "image"
        assert result[0].changes[0].change_type == "modified"

    def test_service_added(self):
        old = "services:\n  web:\n    image: nginx:latest\n"
        new = "services:\n  web:\n    image: nginx:latest\n  db:\n    image: postgres:16\n"
        result = semantic_diff(old, new)
        db_diff = [d for d in result if d.service == "db"]
        assert len(db_diff) == 1
        assert db_diff[0].changes[0].change_type == "added"

    def test_service_removed(self):
        old = "services:\n  web:\n    image: nginx:latest\n  db:\n    image: postgres:16\n"
        new = "services:\n  web:\n    image: nginx:latest\n"
        result = semantic_diff(old, new)
        db_diff = [d for d in result if d.service == "db"]
        assert len(db_diff) == 1
        assert db_diff[0].changes[0].change_type == "removed"

    def test_env_reorder_no_change(self):
        old = "services:\n  web:\n    image: nginx\n    environment:\n      - B=2\n      - A=1\n"
        new = "services:\n  web:\n    image: nginx\n    environment:\n      - A=1\n      - B=2\n"
        result = semantic_diff(old, new)
        assert len(result) == 0

    def test_security_field_flagged(self):
        old = "services:\n  web:\n    image: nginx\n"
        new = "services:\n  web:\n    image: nginx\n    privileged: true\n"
        result = semantic_diff(old, new)
        assert len(result) == 1
        assert result[0].changes[0].security_relevant is True


