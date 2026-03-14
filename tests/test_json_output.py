"""Tests for JSON output."""

import json

from roustabout.auditor import Finding, Severity
from roustabout.json_output import environment_to_json, findings_to_json
from roustabout.models import MountInfo, PortBinding, make_container, make_environment


def _env(**kwargs):
    """Build a minimal DockerEnvironment with one container."""
    defaults = dict(
        name="test-container",
        id="abc123",
        status="running",
        image="nginx:1.25",
        image_id="sha256:abc",
    )
    defaults.update(kwargs)
    container = make_container(**defaults)
    return make_environment(
        containers=[container],
        generated_at="2026-03-13T00:00:00Z",
        docker_version="25.0.3",
    )


class TestEnvironmentToJson:
    def test_basic_serialization(self):
        env = _env()
        result = json.loads(environment_to_json(env))
        assert result["docker_version"] == "25.0.3"
        assert len(result["containers"]) == 1
        assert result["containers"][0]["name"] == "test-container"

    def test_env_as_dict(self):
        env = _env(env=[("FOO", "bar"), ("BAZ", "qux")])
        result = json.loads(environment_to_json(env))
        container = result["containers"][0]
        assert container["env"]["BAZ"] == "qux"
        assert container["env"]["FOO"] == "bar"

    def test_ports_serialized(self):
        env = _env(
            ports=[
                PortBinding(container_port=80, protocol="tcp", host_ip="0.0.0.0", host_port="80")
            ]
        )
        result = json.loads(environment_to_json(env))
        assert len(result["containers"][0]["ports"]) == 1

    def test_roundtrip_valid_json(self):
        env = _env(
            env=[("KEY", "value")],
            mounts=[MountInfo(source="/data", destination="/data", mode="rw", type="bind")],
        )
        json_str = environment_to_json(env)
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)


class TestFindingsToJson:
    def test_basic_findings(self):
        findings = [
            Finding(Severity.CRITICAL, "docker-socket", "web", "Socket mounted.", "Fix it."),
            Finding(Severity.WARNING, "secrets-in-env", "db", "Password in env.", "Use secrets."),
        ]
        result = json.loads(findings_to_json(findings))
        assert len(result["findings"]) == 2
        assert result["summary"]["critical"] == 1
        assert result["summary"]["warning"] == 1
        assert result["summary"]["total"] == 2

    def test_finding_fields(self):
        findings = [
            Finding(
                Severity.WARNING,
                "secrets-in-env",
                "db",
                "Password in env.",
                "Use secrets.",
                detail="DB_PASSWORD",
            ),
        ]
        result = json.loads(findings_to_json(findings))
        f = result["findings"][0]
        assert f["severity"] == "warning"
        assert f["category"] == "secrets-in-env"
        assert f["container"] == "db"
        assert f["detail"] == "DB_PASSWORD"
        assert f["key"] == "db|secrets-in-env|DB_PASSWORD"

    def test_empty_findings(self):
        result = json.loads(findings_to_json([]))
        assert result["findings"] == []
        assert result["summary"]["total"] == 0
