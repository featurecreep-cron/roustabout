"""Tests for roustabout redactor."""

import pytest

from roustabout.models import make_container, make_environment
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


class TestImmutability:
    def test_original_unchanged_after_redaction(self):
        env = _env_environment([("DB_PASSWORD", "secret")])
        result = redact(env)
        assert dict(env.containers[0].env)["DB_PASSWORD"] == "secret"
        assert dict(result.containers[0].env)["DB_PASSWORD"] == REDACTED
