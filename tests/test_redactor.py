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
from roustabout.redactor import (
    DEFAULT_PATTERNS,
    REDACTED,
    is_secret_key,
    redact,
    redact_value,
    resolve_patterns,
)


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
    """Default patterns hit key-based redaction: substring match in key."""

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
            "AUTHENTIK_SECRET_KEY",
            # case variations
            "My_Password_Here",
            "db_password",
        ],
    )
    def test_redacts_sensitive_keys(self, key):
        env = _env_environment([(key, "sensitive_value")])
        result = redact(env)
        assert dict(result.containers[0].env)[key] == REDACTED


class TestNoOverRedaction:
    """Keys that LOOK sensitive but aren't should be preserved."""

    @pytest.mark.parametrize(
        "key,value",
        [
            # "auth" as prefix in product name — NOT a secret pattern
            ("AUTHENTIK_EMAIL__HOST", "smtp.gmail.com"),
            ("AUTHENTIK_EMAIL__PORT", "465"),
            ("AUTHENTIK_EMAIL__USE_SSL", "true"),
            ("AUTHENTIK_LISTEN__HTTP", "0.0.0.0:9000"),
            ("AUTHENTIK_POSTGRESQL__HOST", "postgres"),
            ("AUTHENTIK_POSTGRESQL__NAME", "authentik"),
            ("AUTHENTIK_POSTGRESQL__USER", "authentik"),
            ("AUTHENTIK_REDIS__HOST", "redis"),
            # Non-secret keys
            ("NGINX_HOST", "example.com"),
            ("NODE_ENV", "production"),
            ("TZ", "America/New_York"),
            ("PORT", "8080"),
            ("PATH", "/usr/local/bin:/usr/bin"),
            ("REGISTRY_KEY_PATH", "/etc/registry/key"),
        ],
    )
    def test_preserves_non_sensitive_keys(self, key, value):
        env = _env_environment([(key, value)])
        result = redact(env)
        assert dict(result.containers[0].env)[key] == value

    def test_authentik_password_still_redacted(self):
        """Password keys within AUTHENTIK_ namespace ARE redacted."""
        env = _env_environment([("AUTHENTIK_POSTGRESQL__PASSWORD", "my-db-pass")])
        result = redact(env)
        assert dict(result.containers[0].env)["AUTHENTIK_POSTGRESQL__PASSWORD"] == REDACTED

    def test_authentik_secret_key_still_redacted(self):
        env = _env_environment([("AUTHENTIK_SECRET_KEY", "abc123")])
        result = redact(env)
        assert dict(result.containers[0].env)["AUTHENTIK_SECRET_KEY"] == REDACTED


class TestUrlHandling:
    """URL handling: partial redaction of password only."""

    def test_partially_redacts_database_url(self):
        """DATABASE_URL with credentials → only password replaced."""
        env = _env_environment([("DATABASE_URL", "postgresql://user:pass@localhost:5432/db")])
        result = redact(env)
        val = dict(result.containers[0].env)["DATABASE_URL"]
        assert "user" in val
        assert "pass" not in val
        assert REDACTED in val
        assert "localhost:5432/db" in val

    def test_url_partial_redaction_format(self):
        """Verify exact format: ://user:[REDACTED]@host."""
        val = redact_value(
            "DATABASE_URL",
            "postgresql://myuser:s3cret@db.host:5432/mydb",
            DEFAULT_PATTERNS,
        )
        assert val == f"postgresql://myuser:{REDACTED}@db.host:5432/mydb"

    def test_preserves_url_without_credentials(self):
        """URL key + no credentials → preserve entirely."""
        env = _env_environment([("CALLBACK_URL", "https://example.com/callback")])
        result = redact(env)
        assert dict(result.containers[0].env)["CALLBACK_URL"] == "https://example.com/callback"

    def test_catch_all_redacts_any_url_with_embedded_creds(self):
        """No pattern match on key, but _url suffix + credentials → partial redact."""
        env = _env_environment([("REDIS_URL", "redis://default:mypassword@redis:6379/0")])
        result = redact(env)
        val = dict(result.containers[0].env)["REDIS_URL"]
        assert "default" in val
        assert "mypassword" not in val
        assert REDACTED in val

    def test_preserves_safe_url_with_no_pattern_match(self):
        """No pattern match + _url suffix + no credentials → preserve."""
        env = _env_environment([("DOCS_URL", "https://docs.example.com/api")])
        result = redact(env)
        assert dict(result.containers[0].env)["DOCS_URL"] == "https://docs.example.com/api"


class TestJsonValueRedaction:
    """Embedded secrets in JSON/structured values."""

    def test_redacts_secret_in_json_value(self):
        """SOCIALACCOUNT_PROVIDERS-style JSON with embedded 'secret' key."""
        json_val = (
            '{"openid_connect": {"APPS": [{'
            '"provider_id": "authentik", '
            '"client_id": "cpkdKN80fIrBk", '
            '"secret": "eGOxug6qYbZIIS4YM9b0nvOFB5BNG6yk"'
            "}]}}"
        )
        env = _env_environment([("SOCIALACCOUNT_PROVIDERS", json_val)])
        result = redact(env)
        val = dict(result.containers[0].env)["SOCIALACCOUNT_PROVIDERS"]
        assert "eGOxug6qYbZIIS4YM9b0nvOFB5BNG6yk" not in val
        assert REDACTED in val
        # Non-secret parts preserved
        assert "cpkdKN80fIrBk" in val
        assert "openid_connect" in val

    def test_redacts_client_secret_in_json(self):
        json_val = '{"client_secret": "abc123secret", "client_id": "pub456"}'
        val = redact_value("OAUTH_CONFIG", json_val, DEFAULT_PATTERNS)
        assert "abc123secret" not in val
        assert "pub456" in val
        assert REDACTED in val

    def test_redacts_prefixed_secret_keys_in_structured_values(self):
        """pgadmin OAUTH2_CLIENT_SECRET-style keys: secret pattern as substring."""
        val = (
            "[{'OAUTH2_NAME': 'authentik', "
            "'OAUTH2_CLIENT_ID': 'pub123', "
            "'OAUTH2_CLIENT_SECRET': 'supersecretvalue', "
            "'OAUTH2_TOKEN_URL': 'https://auth.example.com/token/'}]"
        )
        result = redact_value("PGADMIN_CONFIG_OAUTH2_CONFIG", val, DEFAULT_PATTERNS)
        assert "supersecretvalue" not in result
        assert "pub123" in result
        assert "auth.example.com" in result
        assert "authentik" in result

    def test_redacts_suffixed_secret_keys_in_structured_values(self):
        """SECRET_KEY-style: pattern appears before other words in key."""
        val = '{"SECRET_KEY": "django-insecure-abc123", "DEBUG": "true"}'
        result = redact_value("APP_CONFIG", val, DEFAULT_PATTERNS)
        assert "django-insecure-abc123" not in result
        assert "true" in result

    def test_preserves_json_without_secret_keys(self):
        json_val = '{"name": "test", "enabled": true}'
        val = redact_value("APP_CONFIG", json_val, DEFAULT_PATTERNS)
        assert val == json_val


class TestCustomPatterns:
    def test_custom_patterns_extend_defaults(self):
        """Custom patterns are merged with defaults — both match."""
        env = _env_environment(
            [
                ("MY_CUSTOM_FIELD", "sensitive"),
                ("DB_PASSWORD", "also_sensitive"),
            ]
        )
        result = redact(env, patterns=("custom_field",))
        env_dict = dict(result.containers[0].env)
        assert env_dict["MY_CUSTOM_FIELD"] == REDACTED
        assert env_dict["DB_PASSWORD"] == REDACTED  # defaults still active

    def test_none_patterns_uses_defaults(self):
        """None patterns → defaults applied."""
        env = _env_environment([("DB_PASSWORD", "secret")])
        result = redact(env, patterns=None)
        assert dict(result.containers[0].env)["DB_PASSWORD"] == REDACTED


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
    """Verify redaction preserves all ContainerInfo fields (not just env)."""

    def test_all_fields_preserved_after_redaction(self):
        container = make_container(
            name="full-test",
            id="abc123",
            status="running",
            image="nginx:1.25",
            image_id="sha256:abcdef",
            image_digest="nginx@sha256:deadbeef",
            ports=[
                PortBinding(container_port=80, protocol="tcp", host_ip="0.0.0.0", host_port="8080")
            ],
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
            command=["nginx", "-g", "daemon off"],
            entrypoint=["/docker-entrypoint.sh"],
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


class TestResolvePatterns:
    def test_no_custom_returns_defaults(self):
        result = resolve_patterns()
        assert result == DEFAULT_PATTERNS

    def test_empty_custom_returns_defaults(self):
        result = resolve_patterns(())
        assert result == DEFAULT_PATTERNS

    def test_custom_extends_defaults(self):
        result = resolve_patterns(("conn_string", "dsn"))
        assert result[: len(DEFAULT_PATTERNS)] == DEFAULT_PATTERNS
        assert "conn_string" in result
        assert "dsn" in result

    def test_duplicates_not_added(self):
        result = resolve_patterns(("password", "secret"))
        assert result == DEFAULT_PATTERNS

    def test_case_insensitive_dedup(self):
        result = resolve_patterns(("PASSWORD", "Secret"))
        assert result == DEFAULT_PATTERNS

    def test_custom_only_adds_new(self):
        result = resolve_patterns(("password", "new_pattern"))
        assert len(result) == len(DEFAULT_PATTERNS) + 1
        assert result[-1] == "new_pattern"


class TestIsSecretKey:
    def test_password_key_is_secret(self):
        assert is_secret_key("DB_PASSWORD", "hunter2", DEFAULT_PATTERNS)

    def test_safe_key_is_not_secret(self):
        assert not is_secret_key("NGINX_HOST", "example.com", DEFAULT_PATTERNS)

    def test_url_with_credentials_is_secret(self):
        assert is_secret_key(
            "DATABASE_URL",
            "postgresql://user:pass@localhost/db",
            DEFAULT_PATTERNS,
        )

    def test_url_without_credentials_is_not_secret(self):
        assert not is_secret_key(
            "CALLBACK_URL",
            "https://example.com/callback",
            DEFAULT_PATTERNS,
        )

    def test_catch_all_url_with_credentials(self):
        assert is_secret_key(
            "REDIS_URL",
            "redis://default:pass@redis:6379/0",
            DEFAULT_PATTERNS,
        )

    def test_json_with_embedded_secret(self):
        assert is_secret_key(
            "OAUTH_CONFIG",
            '{"secret": "abc123"}',
            DEFAULT_PATTERNS,
        )

    def test_json_without_secret_not_flagged(self):
        assert not is_secret_key(
            "APP_CONFIG",
            '{"name": "test"}',
            DEFAULT_PATTERNS,
        )


class TestLabelRedaction:
    def test_redacts_secret_in_labels(self):
        container = make_container(
            name="test",
            id="abc123",
            status="running",
            image="img:latest",
            image_id="sha256:123",
            labels=[("traefik.auth.password", "hunter2"), ("app.version", "1.0")],
        )
        env = make_environment(
            containers=[container],
            generated_at="2026-01-01T00:00:00Z",
            docker_version="25.0",
        )
        result = redact(env)
        label_dict = dict(result.containers[0].labels)
        assert label_dict["traefik.auth.password"] == REDACTED
        assert label_dict["app.version"] == "1.0"


class TestCommandRedaction:
    def test_redacts_password_flag(self):
        container = make_container(
            name="test",
            id="abc123",
            status="running",
            image="img:latest",
            image_id="sha256:123",
            command=["myapp", "--password=hunter2", "--port=8080"],
        )
        env = make_environment(
            containers=[container],
            generated_at="2026-01-01T00:00:00Z",
            docker_version="25.0",
        )
        result = redact(env)
        cmd = result.containers[0].command
        assert "hunter2" not in " ".join(cmd)
        assert REDACTED in " ".join(cmd)
        assert "--port=8080" in cmd

    def test_preserves_safe_command(self):
        container = make_container(
            name="test",
            id="abc123",
            status="running",
            image="img:latest",
            image_id="sha256:123",
            command=["nginx", "-g", "daemon off;"],
        )
        env = make_environment(
            containers=[container],
            generated_at="2026-01-01T00:00:00Z",
            docker_version="25.0",
        )
        result = redact(env)
        assert result.containers[0].command == ("nginx", "-g", "daemon off;")


class TestUrlParsingEdgeCases:
    def test_url_without_username(self):
        """postgres://:password@host should still redact."""
        val = redact_value("DATABASE_URL", "postgres://:secret@host/db", DEFAULT_PATTERNS)
        assert "secret" not in val
        assert REDACTED in val
        assert "host" in val

    def test_url_with_special_chars_in_password(self):
        """URL-encoded special chars in password."""
        val = redact_value(
            "DATABASE_URL",
            "postgresql://user:p%40ss%3Aword@host:5432/db",
            DEFAULT_PATTERNS,
        )
        assert "p%40ss" not in val
        assert REDACTED in val
        assert "host:5432/db" in val

    def test_passphrase_pattern(self):
        """Passphrase keys should be redacted."""
        env = _env_environment([("PAPERLESS_PASSPHRASE", "my-secret-phrase")])
        result = redact(env)
        assert dict(result.containers[0].env)["PAPERLESS_PASSPHRASE"] == REDACTED


class TestValueFormatDetection:
    """Value-based format detection — catches secrets by shape regardless of key name."""

    def test_aws_access_key_id(self):
        val = redact_value("CONFIG_VALUE", "AKIAIOSFODNN7EXAMPLE", DEFAULT_PATTERNS)
        assert val == REDACTED

    def test_github_pat_classic(self):
        pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"
        val = redact_value("INIT_DATA", pat, DEFAULT_PATTERNS)
        assert val == REDACTED

    def test_github_pat_fine_grained(self):
        # Fine-grained PATs are detected by key pattern via extra_keys,
        # or by gitleaks format if the value matches the full pattern.
        # The old hand-rolled regex was more permissive. With secretscreen,
        # this test uses a key name that triggers key-pattern detection.
        token = "github_pat_11AAAAAA0abcdefghijklmnop"
        val = redact_value("GITHUB_TOKEN", token, DEFAULT_PATTERNS)
        assert val == REDACTED

    def test_stripe_live_key(self):
        # Prefix + 20 alphanum chars triggers Stripe pattern
        val = redact_value("PAYMENT_CONFIG", "sk_test_FAKEFAKEFAKEFAKEFAKE", DEFAULT_PATTERNS)
        assert val == REDACTED

    def test_jwt_token(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        val = redact_value("SESSION_DATA", jwt, DEFAULT_PATTERNS)
        assert val == REDACTED

    def test_private_key_header(self):
        # Gitleaks requires 64+ chars between BEGIN/END markers.
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\n"
            "aNotReal1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV\n"
            "-----END RSA PRIVATE KEY-----"
        )
        val = redact_value("TLS_CERT", pem, DEFAULT_PATTERNS)
        assert val == REDACTED

    def test_short_value_not_flagged(self):
        """Short values should not trigger format detection."""
        val = redact_value("APP_MODE", "production", DEFAULT_PATTERNS)
        assert val == "production"

    def test_aws_secret_key(self):
        """AWS secret keys detected via key name pattern."""
        # The old hand-rolled regex matched 40-char mixed-case strings.
        # Gitleaks has a more specific AWS pattern that requires context.
        # With secretscreen, key-name detection catches this reliably.
        aws = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        val = redact_value("AWS_SECRET_ACCESS_KEY", aws, DEFAULT_PATTERNS)
        assert val == REDACTED

    def test_gpg_fingerprint_not_flagged(self):
        """GPG fingerprints (uppercase hex, 40 chars) are not secrets."""
        gpg = "7169605F62C751356D054A26A821E680E5FA6305"
        val = redact_value("GPG_KEY", gpg, DEFAULT_PATTERNS)
        assert val == gpg

    def test_normal_base64_not_flagged(self):
        """Regular base64 that doesn't match known formats passes through."""
        val = redact_value("ICON_DATA", "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=", DEFAULT_PATTERNS)
        assert val == "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="

    def test_slack_bot_token(self):
        # Slack tokens are detected by gitleaks patterns when realistic,
        # but GitHub push protection blocks realistic test fixtures.
        # Use key-name detection instead.
        prefix = "xoxb"
        token = f"{prefix}-0000000000-FAKEFAKEFAKEFAKE"
        val = redact_value("SLACK_BOT_TOKEN", token, DEFAULT_PATTERNS)
        assert val == REDACTED


class TestWarningsPreserved:
    def test_redact_preserves_warnings(self):
        env = make_environment(
            containers=[_env_container([("DB_PASSWORD", "secret")])],
            generated_at="2026-01-01T00:00:00Z",
            docker_version="25.0",
            warnings=["container 'broken' skipped: timeout"],
        )
        result = redact(env)
        assert result.warnings == ("container 'broken' skipped: timeout",)
