"""Tests for roustabout redactor."""

import dataclasses

import pytest

from roustabout.models import (
    MountInfo,
    NetworkMembership,
    PortBinding,
    make_container,
    make_environment,
)
from roustabout.redactor import REDACTED, redact


def _env_container(env_pairs, name="test"):
    """Helper: build a minimal container with given env pairs."""
    return make_container(
        name=name,
        id="abc123",
        status="running",
        image="img:latest",
        image_id="sha256:123",
        env=env_pairs,
    )


def _env_environment(env_pairs):
    """Helper: build a minimal environment with one container."""
    return make_environment(
        containers=[_env_container(env_pairs)],
        generated_at="2026-01-01T00:00:00Z",
        docker_version="25.0",
    )


class TestDefaultPatternMatching:
    """Default patterns all hit the same branch: substring match in key, not a _url key."""

    @pytest.mark.parametrize(
        "key",
        [
            "DB_PASSWORD",
            "APP_SECRET",
            "AUTH_TOKEN",
            "STRIPE_API_KEY",
            "SMTP_CREDENTIAL",
            "SSH_PRIVATE_KEY",
            "AWS_ACCESS_KEY",
            "BASIC_AUTH",
            # case variations — same branch, just verifies .lower() works
            "My_Password_Here",
            "db_password",
        ],
    )
    def test_redacts_sensitive_keys(self, key):
        env = _env_environment([(key, "sensitive_value")])
        result = redact(env)
        assert dict(result.containers[0].env)[key] == REDACTED


class TestUrlHandling:
    """URL handling has three distinct branches."""

    def test_redacts_database_url_with_credentials(self):
        """Pattern match (database_url) + _url suffix + credentials present → redact."""
        env = _env_environment([
            ("DATABASE_URL", "postgresql://user:pass@localhost:5432/db"),
        ])
        result = redact(env)
        assert dict(result.containers[0].env)["DATABASE_URL"] == REDACTED

    def test_preserves_url_matching_pattern_without_credentials(self):
        """Pattern match (auth) + _url suffix + no credentials → preserve."""
        env = _env_environment([
            ("AUTH_CALLBACK_URL", "https://example.com/callback"),
        ])
        result = redact(env)
        assert (
            dict(result.containers[0].env)["AUTH_CALLBACK_URL"]
            == "https://example.com/callback"
        )

    def test_catch_all_redacts_any_url_with_embedded_creds(self):
        """No pattern match, but _url suffix + credentials → redact (catch-all)."""
        env = _env_environment([
            ("REDIS_URL", "redis://default:mypassword@redis:6379/0"),
        ])
        result = redact(env)
        assert dict(result.containers[0].env)["REDIS_URL"] == REDACTED

    def test_preserves_safe_url_with_no_pattern_match(self):
        """No pattern match + _url suffix + no credentials → preserve."""
        env = _env_environment([
            ("DOCS_URL", "https://docs.example.com/api"),
        ])
        result = redact(env)
        assert dict(result.containers[0].env)["DOCS_URL"] == "https://docs.example.com/api"


class TestNoFalsePositives:
    @pytest.mark.parametrize(
        "key,value",
        [
            ("NGINX_HOST", "example.com"),
            ("NODE_ENV", "production"),
            ("TZ", "America/New_York"),
            ("PORT", "8080"),
            ("PATH", "/usr/local/bin:/usr/bin"),
        ],
    )
    def test_preserves_non_sensitive_keys(self, key, value):
        env = _env_environment([(key, value)])
        result = redact(env)
        assert dict(result.containers[0].env)[key] == value


class TestCustomPatterns:
    def test_custom_patterns_replace_defaults(self):
        env = _env_environment([
            ("MY_CUSTOM_FIELD", "sensitive"),
            ("DB_PASSWORD", "also_sensitive"),
        ])
        result = redact(env, patterns=("custom_field",))
        env_dict = dict(result.containers[0].env)
        assert env_dict["MY_CUSTOM_FIELD"] == REDACTED
        assert env_dict["DB_PASSWORD"] == "also_sensitive"

    def test_empty_patterns_redacts_nothing(self):
        env = _env_environment([("DB_PASSWORD", "secret")])
        result = redact(env, patterns=())
        assert dict(result.containers[0].env)["DB_PASSWORD"] == "secret"


class TestMultipleContainers:
    def test_redacts_across_all_containers(self):
        c1 = _env_container([("API_KEY", "key1")], name="app1")
        c2 = _env_container([("API_KEY", "key2")], name="app2")
        env = make_environment(
            containers=[c1, c2],
            generated_at="2026-01-01T00:00:00Z",
            docker_version="25.0",
        )
        result = redact(env)
        for c in result.containers:
            assert dict(c.env)["API_KEY"] == REDACTED


class TestFieldPreservation:
    """S1: Verify redaction preserves all ContainerInfo fields (not just env)."""

    def test_all_fields_preserved_after_redaction(self):
        container = make_container(
            name="full-test",
            id="abc123",
            status="running",
            image="nginx:1.25",
            image_id="sha256:abcdef",
            image_digest="nginx@sha256:deadbeef",
            ports=[PortBinding(container_port=80, protocol="tcp", host_ip="0.0.0.0", host_port="8080")],
            mounts=[MountInfo(source="/host", destination="/container", mode="rw", type="bind")],
            networks=[NetworkMembership(name="frontend", ip_address="10.0.0.1", aliases=("web",))],
            env=[("SECRET_KEY", "hunter2"), ("SAFE_VAR", "hello")],
            labels=[("app.version", "1.0")],
            health="healthy",
            compose_project="myproject",
            compose_service="web",
            compose_config_files="/opt/docker-compose.yml",
            restart_count=3,
            created="2026-01-01T00:00:00Z",
            started_at="2026-01-01T00:00:05Z",
            command="nginx -g daemon off",
            entrypoint="/docker-entrypoint.sh",
            oom_killed=True,
        )
        env = make_environment(
            containers=[container],
            generated_at="2026-01-01T00:00:00Z",
            docker_version="25.0",
        )
        result = redact(env)
        redacted = result.containers[0]

        # Every field except env should be identical
        for field in dataclasses.fields(container):
            if field.name == "env":
                continue
            assert getattr(redacted, field.name) == getattr(container, field.name), (
                f"Field '{field.name}' changed during redaction"
            )

        # Env should be redacted for SECRET_KEY, preserved for SAFE_VAR
        env_dict = dict(redacted.env)
        assert env_dict["SECRET_KEY"] == REDACTED
        assert env_dict["SAFE_VAR"] == "hello"


class TestImmutability:
    def test_original_unchanged_after_redaction(self):
        env = _env_environment([("DB_PASSWORD", "secret")])
        result = redact(env)
        assert dict(env.containers[0].env)["DB_PASSWORD"] == "secret"
        assert dict(result.containers[0].env)["DB_PASSWORD"] == REDACTED
