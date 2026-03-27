"""Tests for supply_chain module."""

import pytest

from roustabout.models import make_container, make_environment
from roustabout.supply_chain import (
    ComposeAudit,
    DigestInfo,
    ImageReference,
    _parse_image,
    _validate_output_dir,
    audit_compose,
    classify_tag,
    extract_secrets,
    generate_and_extract,
    generate_renovate_config,
    pin_compose_digests,
)

# Image parsing


class TestParseImage:
    def test_simple_image(self):
        name, tag, digest, registry = _parse_image("postgres:18-alpine")
        assert name == "postgres"
        assert tag == "18-alpine"
        assert digest is None
        assert registry == "docker.io"

    def test_image_no_tag(self):
        name, tag, digest, registry = _parse_image("postgres")
        assert name == "postgres"
        assert tag is None
        assert digest is None
        assert registry == "docker.io"

    def test_image_with_digest(self):
        name, tag, digest, registry = _parse_image("postgres:18-alpine@sha256:abc123")
        assert name == "postgres"
        assert tag == "18-alpine"
        assert digest == "sha256:abc123"
        assert registry == "docker.io"

    def test_ghcr_image(self):
        name, tag, digest, registry = _parse_image("ghcr.io/featurecreep-cron/morsl:latest")
        assert name == "ghcr.io/featurecreep-cron/morsl"
        assert tag == "latest"
        assert registry == "ghcr.io"

    def test_ghcr_image_with_digest(self):
        name, tag, digest, registry = _parse_image("ghcr.io/foo/bar:v1@sha256:def456")
        assert name == "ghcr.io/foo/bar"
        assert tag == "v1"
        assert digest == "sha256:def456"
        assert registry == "ghcr.io"

    def test_docker_hub_namespaced(self):
        name, tag, digest, registry = _parse_image("linuxserver/swag:latest")
        assert name == "linuxserver/swag"
        assert tag == "latest"
        assert registry == "docker.io"

    def test_digest_only(self):
        name, tag, digest, registry = _parse_image("postgres@sha256:abc")
        assert name == "postgres"
        assert tag is None
        assert digest == "sha256:abc"


class TestClassifyTag:
    def test_none_is_latest(self):
        assert classify_tag(None) == "latest"

    def test_latest(self):
        assert classify_tag("latest") == "latest"

    def test_semver(self):
        assert classify_tag("18") == "semver"
        assert classify_tag("18.3") == "semver"
        assert classify_tag("18.3.0") == "semver"
        assert classify_tag("v1.2.3") == "semver"

    def test_semver_os(self):
        assert classify_tag("18-alpine") == "semver-os"
        assert classify_tag("3.13-slim") == "semver-os"
        assert classify_tag("3.13-bookworm") == "semver-os"

    def test_custom(self):
        assert classify_tag("nightly") == "custom"
        assert classify_tag("main") == "custom"

    def test_digest(self):
        assert classify_tag("sha256:abc123") == "digest"


# Compose audit


class TestAuditCompose:
    def test_basic_audit(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25-alpine\n"
            "    environment:\n"
            "      APP_NAME: myapp\n"
            "  db:\n"
            "    image: postgres:18-alpine\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: supersecret\n"
            "    volumes:\n"
            "      - pgdata:/var/lib/postgresql/data\n"
            "volumes:\n"
            "  pgdata:\n"
        )
        result = audit_compose(compose)
        assert isinstance(result, ComposeAudit)
        assert result.service_count == 2
        assert len(result.images) == 2
        assert "db" in result.stateful_services
        assert "web" in result.stateless_services

    def test_detects_inline_secrets(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  db:\n"
            "    image: postgres:18\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: mysecret\n"
            "      POSTGRES_USER: admin\n"
        )
        result = audit_compose(compose)
        inline = [s for s in result.secrets if not s.is_reference]
        assert len(inline) == 1
        assert inline[0].field == "environment.POSTGRES_PASSWORD"
        assert "PASSWORD" in inline[0].pattern_matched
        assert not result.migration_ready

    def test_variable_reference_not_inline(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  db:\n"
            "    image: postgres:18\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: ${DB_PASSWORD}\n"
        )
        result = audit_compose(compose)
        assert len(result.secrets) == 1
        assert result.secrets[0].is_reference
        assert result.migration_ready

    def test_floating_tag_warning(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  web:\n    image: nginx\n")
        result = audit_compose(compose)
        assert result.images[0].is_floating
        assert any("floating" in issue for issue in result.issues)

    def test_already_pinned(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  web:\n    image: nginx:1.25-alpine@sha256:abc123\n")
        result = audit_compose(compose)
        assert result.images[0].is_pinned
        assert result.images[0].digest == "sha256:abc123"

    def test_list_style_environment(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: myapp:1.0\n"
            "    environment:\n"
            "      - SECRET_KEY=reallysecret\n"
            "      - DEBUG=false\n"
        )
        result = audit_compose(compose)
        inline = [s for s in result.secrets if not s.is_reference]
        assert len(inline) == 1
        assert inline[0].field == "environment.SECRET_KEY"

    def test_database_image_detected_as_stateful(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  cache:\n"
            "    image: redis:7-alpine\n"
            "  search:\n"
            "    image: meilisearch:v1.6\n"
            "  web:\n"
            "    image: nginx:latest\n"
        )
        result = audit_compose(compose)
        assert "cache" in result.stateful_services
        assert "search" in result.stateful_services
        assert "web" not in result.stateful_services

    def test_detects_uri_credentials(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: myapp:1.0\n"
            "    environment:\n"
            "      DATABASE_URL: postgresql://admin:hunter2@db/myapp\n"
            "      REDIS_URL: redis://localhost:6379\n"
            "      APP_NAME: myapp\n"
        )
        result = audit_compose(compose)
        inline = [s for s in result.secrets if not s.is_reference]
        assert len(inline) == 1
        assert inline[0].field == "environment.DATABASE_URL"
        assert inline[0].pattern_matched == "URI_CREDENTIAL"
        assert not result.migration_ready

    def test_uri_credentials_not_false_positive(self, tmp_path):
        """URLs without embedded passwords should not be flagged."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: myapp:1.0\n"
            "    environment:\n"
            "      HOMEPAGE: https://example.com/path\n"
            "      REDIS_URL: redis://localhost:6379\n"
        )
        result = audit_compose(compose)
        assert len(result.secrets) == 0
        assert result.migration_ready

    def test_data_volume_makes_stateful(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n  app:\n    image: myapp:1.0\n    volumes:\n      - app_data:/data\n"
        )
        result = audit_compose(compose)
        assert "app" in result.stateful_services

    def test_invalid_compose_raises(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("just a string\n")
        with pytest.raises(ValueError, match="Invalid compose"):
            audit_compose(compose)


# Secret extraction


class TestExtractSecrets:
    def test_dry_run_no_changes(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  db:\n"
            "    image: postgres:18\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: mysecret\n"
        )
        original = compose.read_text()
        result = extract_secrets(compose, dry_run=True)
        assert result.secrets_extracted == 1
        assert compose.read_text() == original  # file unchanged

    def test_extracts_to_env_file(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  db:\n"
            "    image: postgres:18\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: mysecret\n"
            "      POSTGRES_USER: admin\n"
        )
        result = extract_secrets(compose, dry_run=False)
        assert result.secrets_extracted == 1
        assert "db" in result.services_modified

        # .env written with secret
        env_file = tmp_path / ".env"
        assert env_file.exists()
        env_content = env_file.read_text()
        assert "DB_POSTGRES_PASSWORD=mysecret" in env_content

        # compose rewritten with reference
        new_compose = compose.read_text()
        assert "mysecret" not in new_compose
        assert "${DB_POSTGRES_PASSWORD}" in new_compose

        # Backup created
        assert (tmp_path / "docker-compose.yml.bak").exists()

    def test_preserves_existing_env(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  db:\n"
            "    image: postgres:18\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: newsecret\n"
        )
        env_file = tmp_path / ".env"
        env_file.write_text("EXISTING_VAR=keep_me\n")

        extract_secrets(compose, dry_run=False)

        env_content = env_file.read_text()
        assert "EXISTING_VAR=keep_me" in env_content
        assert "DB_POSTGRES_PASSWORD=newsecret" in env_content

    def test_skips_variable_references(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  db:\n"
            "    image: postgres:18\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: ${ALREADY_A_REF}\n"
        )
        result = extract_secrets(compose, dry_run=True)
        assert result.secrets_extracted == 0

    def test_list_style_extraction(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: myapp:1.0\n"
            "    environment:\n"
            "      - SECRET_KEY=topsecret\n"
            "      - DEBUG=false\n"
        )
        result = extract_secrets(compose, dry_run=False)
        assert result.secrets_extracted == 1

        env_content = (tmp_path / ".env").read_text()
        assert "APP_SECRET_KEY=topsecret" in env_content

    def test_env_file_permissions(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  db:\n"
            "    image: postgres:18\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: secret\n"
        )
        extract_secrets(compose, dry_run=False)
        env_file = tmp_path / ".env"
        assert oct(env_file.stat().st_mode)[-3:] == "600"

    def test_extracts_uri_credentials(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: myapp:1.0\n"
            "    environment:\n"
            "      DATABASE_URL: postgresql://admin:hunter2@db/myapp\n"
            "      REDIS_URL: redis://localhost:6379\n"
        )
        result = extract_secrets(compose, dry_run=False)
        assert result.secrets_extracted == 1
        assert "app" in result.services_modified

        env_content = (tmp_path / ".env").read_text()
        assert "APP_DATABASE_URL=postgresql://admin:hunter2@db/myapp" in env_content

        new_compose = compose.read_text()
        assert "hunter2" not in new_compose
        assert "${APP_DATABASE_URL}" in new_compose

    def test_sanitized_compose_has_no_secrets(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  db:\n"
            "    image: postgres:18\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: verysecretvalue\n"
        )
        result = extract_secrets(compose, dry_run=True)
        assert "verysecretvalue" not in result.sanitized_compose
        assert "${DB_POSTGRES_PASSWORD}" in result.sanitized_compose


# Digest pinning


class TestPinComposeDigests:
    def test_pins_images(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25-alpine\n"
            "  db:\n"
            "    image: postgres:18-alpine\n"
        )
        digests = (
            DigestInfo(
                service="web",
                current_image="nginx:1.25-alpine",
                current_digest=None,
                latest_digest="sha256:webdigest",
                latest_tag="1.25-alpine",
                image_age_hours=72,
                needs_update=True,
                pin_reference="nginx:1.25-alpine@sha256:webdigest",
            ),
            DigestInfo(
                service="db",
                current_image="postgres:18-alpine",
                current_digest=None,
                latest_digest="sha256:dbdigest",
                latest_tag="18-alpine",
                image_age_hours=168,
                needs_update=True,
                pin_reference="postgres:18-alpine@sha256:dbdigest",
            ),
        )
        result = pin_compose_digests(compose, digests, dry_run=False)
        assert result.images_pinned == 2
        assert result.images_skipped == 0

        content = compose.read_text()
        assert "nginx:1.25-alpine@sha256:webdigest" in content
        assert "postgres:18-alpine@sha256:dbdigest" in content

    def test_skips_already_pinned(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  web:\n    image: nginx:1.25-alpine@sha256:existing\n")
        digests = (
            DigestInfo(
                service="web",
                current_image="nginx:1.25-alpine@sha256:existing",
                current_digest="sha256:existing",
                latest_digest="sha256:new",
                latest_tag="1.25-alpine",
                image_age_hours=72,
                needs_update=True,
                pin_reference="nginx:1.25-alpine@sha256:new",
            ),
        )
        result = pin_compose_digests(compose, digests, dry_run=True)
        assert result.images_pinned == 0
        assert result.images_skipped == 1
        assert "already pinned" in result.skipped_reasons[0]

    def test_skips_latest_tag(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  web:\n    image: nginx:latest\n")
        digests = (
            DigestInfo(
                service="web",
                current_image="nginx:latest",
                current_digest=None,
                latest_digest="sha256:abc",
                latest_tag="latest",
                image_age_hours=1,
                needs_update=True,
                pin_reference="nginx:latest@sha256:abc",
            ),
        )
        result = pin_compose_digests(compose, digests, dry_run=True)
        assert result.images_pinned == 0
        assert result.images_skipped == 1
        assert ":latest" in result.skipped_reasons[0]

    def test_pinned_image_stays_single_line(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  web:\n    image: nginx:1.25-alpine\n")
        long_digest = "sha256:" + "a" * 64
        digests = (
            DigestInfo(
                service="web",
                current_image="nginx:1.25-alpine",
                current_digest=None,
                latest_digest=long_digest,
                latest_tag="1.25-alpine",
                image_age_hours=72,
                needs_update=True,
                pin_reference=f"nginx:1.25-alpine@{long_digest}",
            ),
        )
        result = pin_compose_digests(compose, digests, dry_run=True)
        # Image line should be single-line, not split across lines
        for line in result.compose_content.splitlines():
            if "image:" in line:
                assert f"nginx:1.25-alpine@{long_digest}" in line
                break
        else:
            pytest.fail("No image: line found in output")

    def test_dry_run_no_file_changes(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text("services:\n  web:\n    image: nginx:1.25\n")
        original = compose.read_text()
        digests = (
            DigestInfo(
                service="web",
                current_image="nginx:1.25",
                current_digest=None,
                latest_digest="sha256:abc",
                latest_tag="1.25",
                image_age_hours=72,
                needs_update=True,
                pin_reference="nginx:1.25@sha256:abc",
            ),
        )
        result = pin_compose_digests(compose, digests, dry_run=True)
        assert result.images_pinned == 1
        assert compose.read_text() == original


# Renovate config generation


class TestGenerateRenovateConfig:
    def _make_audit(self, images, stateful=(), stateless=()):
        return ComposeAudit(
            project="test",
            file_path="/test/docker-compose.yml",
            service_count=len(images),
            images=tuple(images),
            secrets=(),
            volumes=(),
            stateful_services=tuple(stateful),
            stateless_services=tuple(stateless),
            migration_ready=True,
            issues=(),
        )

    def test_own_registry_no_delay(self):
        images = [
            ImageReference(
                service="morsl",
                image="ghcr.io/featurecreep-cron/morsl:latest",
                tag="latest",
                digest=None,
                registry="ghcr.io",
                is_pinned=False,
                is_floating=True,
                tag_pattern="latest",
            ),
        ]
        audit = self._make_audit(images, stateless=("morsl",))
        result = generate_renovate_config(
            audit,
            own_registries=("ghcr.io/featurecreep-cron/",),
        )
        assert len(result.policies) == 1
        assert result.policies[0].minimum_release_age == "0 days"
        assert result.policies[0].automerge is True

    def test_database_longer_cooldown(self):
        images = [
            ImageReference(
                service="db",
                image="postgres:18-alpine",
                tag="18-alpine",
                digest=None,
                registry="docker.io",
                is_pinned=False,
                is_floating=False,
                tag_pattern="semver-os",
            ),
        ]
        audit = self._make_audit(images, stateful=("db",))
        result = generate_renovate_config(audit)
        assert len(result.policies) == 1
        assert result.policies[0].minimum_release_age == "7 days"
        assert result.policies[0].automerge is False

    def test_third_party_default_cooldown(self):
        images = [
            ImageReference(
                service="proxy",
                image="traefik:v3.0",
                tag="v3.0",
                digest=None,
                registry="docker.io",
                is_pinned=False,
                is_floating=False,
                tag_pattern="semver",
            ),
        ]
        audit = self._make_audit(images, stateless=("proxy",))
        result = generate_renovate_config(audit, default_cooldown_days=3)
        assert len(result.policies) == 1
        assert result.policies[0].minimum_release_age == "3 days"
        assert result.policies[0].automerge is True

    def test_latest_tag_warning(self):
        images = [
            ImageReference(
                service="web",
                image="nginx",
                tag=None,
                digest=None,
                registry="docker.io",
                is_pinned=False,
                is_floating=True,
                tag_pattern="latest",
            ),
        ]
        audit = self._make_audit(images, stateless=("web",))
        result = generate_renovate_config(audit)
        assert any(":latest" in w for w in result.warnings)

    def test_config_json_valid(self):
        import json

        images = [
            ImageReference(
                service="web",
                image="nginx:1.25",
                tag="1.25",
                digest=None,
                registry="docker.io",
                is_pinned=False,
                is_floating=False,
                tag_pattern="semver",
            ),
        ]
        audit = self._make_audit(images, stateless=("web",))
        result = generate_renovate_config(audit)
        parsed = json.loads(result.config_json)
        assert "$schema" in parsed
        assert "packageRules" in parsed
        assert parsed["docker"]["pinDigests"] is True

    def test_mixed_images(self):
        images = [
            ImageReference(
                service="morsl",
                image="ghcr.io/featurecreep-cron/morsl:v1",
                tag="v1",
                digest=None,
                registry="ghcr.io",
                is_pinned=False,
                is_floating=False,
                tag_pattern="semver",
            ),
            ImageReference(
                service="db",
                image="postgres:18-alpine",
                tag="18-alpine",
                digest=None,
                registry="docker.io",
                is_pinned=False,
                is_floating=False,
                tag_pattern="semver-os",
            ),
            ImageReference(
                service="proxy",
                image="traefik:v3.0",
                tag="v3.0",
                digest=None,
                registry="docker.io",
                is_pinned=False,
                is_floating=False,
                tag_pattern="semver",
            ),
        ]
        audit = self._make_audit(
            images,
            stateful=("db",),
            stateless=("morsl", "proxy"),
        )
        result = generate_renovate_config(
            audit,
            own_registries=("ghcr.io/featurecreep-cron/",),
        )
        # Should have 3 policy groups: own, database, third-party
        assert len(result.policies) == 3

        own = [p for p in result.policies if p.minimum_release_age == "0 days"]
        db = [p for p in result.policies if not p.automerge]
        third = [p for p in result.policies if p.automerge and p.minimum_release_age == "3 days"]

        assert len(own) == 1
        assert len(db) == 1
        assert len(third) == 1

    def test_custom_cooldown_days(self):
        images = [
            ImageReference(
                service="web",
                image="nginx:1.25",
                tag="1.25",
                digest=None,
                registry="docker.io",
                is_pinned=False,
                is_floating=False,
                tag_pattern="semver",
            ),
        ]
        audit = self._make_audit(images, stateless=("web",))
        result = generate_renovate_config(
            audit,
            default_cooldown_days=5,
            database_cooldown_days=14,
        )
        assert result.policies[0].minimum_release_age == "5 days"


# Version constraint generation


class TestVersionConstraint:
    def test_semver_os_constraint(self):
        from roustabout.supply_chain import _version_constraint

        img = ImageReference(
            service="db",
            image="postgres:18-alpine",
            tag="18-alpine",
            digest=None,
            registry="docker.io",
            is_pinned=False,
            is_floating=False,
            tag_pattern="semver-os",
        )
        result = _version_constraint(img)
        assert result == r"/^18(\.\d+)*-alpine$/"

    def test_semver_constraint(self):
        from roustabout.supply_chain import _version_constraint

        img = ImageReference(
            service="web",
            image="nginx:1.25",
            tag="1.25",
            digest=None,
            registry="docker.io",
            is_pinned=False,
            is_floating=False,
            tag_pattern="semver",
        )
        result = _version_constraint(img)
        assert result == r"/^v?1\.\d+(\.\d+)*$/"

    def test_latest_no_constraint(self):
        from roustabout.supply_chain import _version_constraint

        img = ImageReference(
            service="web",
            image="nginx",
            tag=None,
            digest=None,
            registry="docker.io",
            is_pinned=False,
            is_floating=True,
            tag_pattern="latest",
        )
        assert _version_constraint(img) is None


# Round-trip integration test


class TestRoundTrip:
    def test_audit_extract_pin_audit(self, tmp_path):
        """Full migration flow: audit -> extract -> pin -> audit again."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25-alpine\n"
            "    environment:\n"
            "      APP_NAME: myapp\n"
            "  db:\n"
            "    image: postgres:18-alpine\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: supersecret\n"
            "    volumes:\n"
            "      - pgdata:/var/lib/postgresql/data\n"
            "volumes:\n"
            "  pgdata:\n"
        )

        # Step 1: audit — not ready
        audit1 = audit_compose(compose)
        assert not audit1.migration_ready
        assert len([s for s in audit1.secrets if not s.is_reference]) == 1

        # Step 2: extract secrets
        result = extract_secrets(compose, dry_run=False)
        assert result.secrets_extracted == 1
        assert "supersecret" not in compose.read_text()

        # Step 3: pin digests
        digests = (
            DigestInfo(
                service="web",
                current_image="nginx:1.25-alpine",
                current_digest=None,
                latest_digest="sha256:webdigest",
                latest_tag="1.25-alpine",
                image_age_hours=72,
                needs_update=True,
                pin_reference="nginx:1.25-alpine@sha256:webdigest",
            ),
            DigestInfo(
                service="db",
                current_image="postgres:18-alpine",
                current_digest=None,
                latest_digest="sha256:dbdigest",
                latest_tag="18-alpine",
                image_age_hours=168,
                needs_update=True,
                pin_reference="postgres:18-alpine@sha256:dbdigest",
            ),
        )
        pin_result = pin_compose_digests(compose, digests, dry_run=False)
        assert pin_result.images_pinned == 2

        # Step 4: audit again — now ready
        audit2 = audit_compose(compose)
        assert audit2.migration_ready
        assert all(img.is_pinned for img in audit2.images)


# --- Generate-and-extract pipeline (LLD-036) ---


def _make_container(**kwargs):
    """Build a container with sensible defaults for pipeline tests."""
    defaults = dict(
        name="test-app",
        id="abc123",
        status="running",
        image="nginx:1.25",
        image_id="sha256:abc",
    )
    defaults.update(kwargs)
    return make_container(**defaults)


def _make_env(*containers):
    """Build a DockerEnvironment for pipeline tests."""
    return make_environment(
        containers=list(containers),
        generated_at="2026-03-27T00:00:00Z",
        docker_version="25.0.3",
    )


class TestGenerateAndExtract:
    def test_dry_run_no_files(self, tmp_path):
        env = _make_env(
            _make_container(
                name="web",
                compose_project="app",
                compose_service="web",
                env=[("SECRET_TOKEN", "topsecret"), ("APP_NAME", "myapp")],
            ),
        )
        output = tmp_path / "stacks"
        result = generate_and_extract(env, output, dry_run=True)
        assert result.dry_run is True
        assert result.total_secrets_extracted == 1
        assert not (output / "app").exists()

    def test_writes_compose_and_env(self, tmp_path):
        env = _make_env(
            _make_container(
                name="db",
                compose_project="data",
                compose_service="db",
                env=[("POSTGRES_PASSWORD", "hunter2"), ("PGDATA", "/var/lib/pg")],
            ),
        )
        output = tmp_path / "stacks"
        result = generate_and_extract(env, output)
        assert result.dry_run is False
        assert result.total_secrets_extracted == 1

        stack_dir = output / "data"
        assert (stack_dir / "docker-compose.yml").exists()
        assert (stack_dir / ".env").exists()

        # .env has secret
        env_content = (stack_dir / ".env").read_text()
        assert "hunter2" in env_content

        # compose has reference, not value
        compose_content = (stack_dir / "docker-compose.yml").read_text()
        assert "hunter2" not in compose_content
        assert "${DB_POSTGRES_PASSWORD}" in compose_content

    def test_env_file_permissions(self, tmp_path):
        env = _make_env(
            _make_container(
                name="db",
                compose_project="data",
                compose_service="db",
                env=[("POSTGRES_PASSWORD", "secret")],
            ),
        )
        output = tmp_path / "stacks"
        generate_and_extract(env, output)
        env_file = output / "data" / ".env"
        assert oct(env_file.stat().st_mode)[-3:] == "600"

    def test_multiple_stacks(self, tmp_path):
        env = _make_env(
            _make_container(
                name="web", compose_project="frontend", compose_service="web",
                env=[("SECRET_KEY", "webkey")],
            ),
            _make_container(
                name="db", compose_project="backend", compose_service="db",
                env=[("POSTGRES_PASSWORD", "dbpass")],
            ),
        )
        output = tmp_path / "stacks"
        result = generate_and_extract(env, output)
        assert len(result.stacks) == 2
        assert result.total_secrets_extracted == 2
        assert (output / "frontend" / "docker-compose.yml").exists()
        assert (output / "backend" / "docker-compose.yml").exists()

    def test_with_mapping(self, tmp_path):
        env = _make_env(
            _make_container(
                name="sonarr", compose_service="sonarr",
                env=[("API_KEY", "sonarrkey")],
            ),
            _make_container(
                name="radarr", compose_service="radarr",
                env=[("API_KEY", "radarrkey")],
            ),
        )
        mapping = {"sonarr": "media", "radarr": "media"}
        output = tmp_path / "stacks"
        result = generate_and_extract(
            env, output, group_by="mapping", stack_mapping=mapping
        )
        assert len(result.stacks) == 1
        assert result.stacks[0].stack_name == "media"
        assert result.total_secrets_extracted == 2

    def test_gitignore_written(self, tmp_path):
        # Create a git repo so _update_gitignore works
        (tmp_path / ".git").mkdir()
        env = _make_env(
            _make_container(
                name="db", compose_project="data", compose_service="db",
                env=[("POSTGRES_PASSWORD", "secret")],
            ),
        )
        output = tmp_path / "stacks"
        generate_and_extract(env, output)
        gitignore = output / "data" / ".gitignore"
        assert gitignore.exists()
        assert ".env" in gitignore.read_text()

    def test_idempotent(self, tmp_path):
        env = _make_env(
            _make_container(
                name="db", compose_project="data", compose_service="db",
                env=[("POSTGRES_PASSWORD", "secret")],
            ),
        )
        output = tmp_path / "stacks"
        r1 = generate_and_extract(env, output)
        r2 = generate_and_extract(env, output)
        assert r1.total_secrets_extracted == r2.total_secrets_extracted


class TestValidateOutputDir:
    def test_rejects_dotdot(self, tmp_path):
        with pytest.raises(ValueError, match="must not contain"):
            _validate_output_dir(tmp_path / ".." / "escape")

    def test_resolves_normal_path(self, tmp_path):
        result = _validate_output_dir(tmp_path / "stacks")
        assert ".." not in str(result)
