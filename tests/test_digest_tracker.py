"""Tests for digest_tracker — first-seen digest tracking and pre-deploy audit.

Covers LLD-039: digest state persistence, cooldown checks, compose static
analysis, and pre-deploy audit orchestration.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

# --- Digest state ---


class TestRecordDigest:
    def test_first_observation_sets_first_seen(self, tmp_path):
        from roustabout.digest_tracker import record_digest
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        record = record_digest(db, "nginx:latest", "sha256:abc123")
        assert record.image == "nginx:latest"
        assert record.digest == "sha256:abc123"
        assert record.source == "registry"
        assert record.age_hours >= 0

    def test_repeat_observation_updates_last_seen(self, tmp_path):
        from roustabout.digest_tracker import record_digest
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        first = record_digest(db, "nginx:latest", "sha256:abc123")
        time.sleep(0.01)
        second = record_digest(db, "nginx:latest", "sha256:abc123")
        assert second.first_seen == first.first_seen
        assert second.last_seen >= first.last_seen

    def test_different_digests_both_stored(self, tmp_path):
        from roustabout.digest_tracker import get_digests, record_digest
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        record_digest(db, "nginx:latest", "sha256:abc")
        record_digest(db, "nginx:latest", "sha256:def")
        records = get_digests(db, "nginx:latest")
        assert len(records) == 2

    def test_custom_source(self, tmp_path):
        from roustabout.digest_tracker import record_digest
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        record = record_digest(db, "nginx:latest", "sha256:abc", source="running")
        assert record.source == "running"

    def test_custom_host(self, tmp_path):
        from roustabout.digest_tracker import get_digests, record_digest
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        record_digest(db, "nginx:latest", "sha256:abc", host="server1")
        record_digest(db, "nginx:latest", "sha256:abc", host="server2")
        assert len(get_digests(db, "nginx:latest", host="server1")) == 1
        assert len(get_digests(db, "nginx:latest", host="server2")) == 1


class TestGetDigests:
    def test_empty_returns_empty(self, tmp_path):
        from roustabout.digest_tracker import get_digests
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        assert get_digests(db, "nginx:latest") == []

    def test_ordered_newest_first(self, tmp_path):
        from roustabout.digest_tracker import get_digests, record_digest
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        record_digest(db, "nginx:latest", "sha256:old")
        time.sleep(0.01)
        record_digest(db, "nginx:latest", "sha256:new")
        records = get_digests(db, "nginx:latest")
        assert records[0].digest == "sha256:new"
        assert records[1].digest == "sha256:old"


class TestDigestAge:
    def test_known_digest(self, tmp_path):
        from roustabout.digest_tracker import digest_age, record_digest
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        record_digest(db, "nginx:latest", "sha256:abc")
        age = digest_age(db, "nginx:latest", "sha256:abc")
        assert age is not None
        assert age >= 0

    def test_unknown_digest_returns_none(self, tmp_path):
        from roustabout.digest_tracker import digest_age
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        assert digest_age(db, "nginx:latest", "sha256:unknown") is None


class TestCheckDigestCooldown:
    def test_known_old_digest_passes(self, tmp_path):
        from roustabout.digest_tracker import check_digest_cooldown, record_digest
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        record_digest(db, "nginx:latest", "sha256:abc")
        # With min_hours=0, any known digest passes
        assert check_digest_cooldown(db, "nginx:latest", "sha256:abc", min_hours=0.0)

    def test_fresh_digest_fails_cooldown(self, tmp_path):
        from roustabout.digest_tracker import check_digest_cooldown, record_digest
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        record_digest(db, "nginx:latest", "sha256:abc")
        # Just recorded — won't pass a 24-hour cooldown
        assert not check_digest_cooldown(db, "nginx:latest", "sha256:abc", min_hours=24.0)

    def test_unknown_digest_fails(self, tmp_path):
        from roustabout.digest_tracker import check_digest_cooldown
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        assert not check_digest_cooldown(db, "nginx:latest", "sha256:unknown")


# --- Schema migration ---


class TestDigestMigration:
    def test_v2_migration_creates_table(self, tmp_path):
        from roustabout.state_db import open_db

        db = open_db(tmp_path / "state.db")
        # Table should exist after open
        rows = (
            db._reader_factory()
            .execute("SELECT name FROM sqlite_master WHERE type='table' AND name='digests'")
            .fetchall()
        )
        assert len(rows) == 1

    def test_existing_v1_db_migrates(self, tmp_path):
        """A database created at v1 should auto-migrate to v2 on next open."""
        import sqlite3

        db_path = tmp_path / "state.db"
        # Create a v1 database manually
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO schema_version VALUES (1, ?)",
            (datetime.now(UTC).isoformat(),),
        )
        conn.execute(
            "CREATE TABLE findings ("
            "key TEXT, host TEXT, state TEXT, reason TEXT, "
            "timestamp TEXT, PRIMARY KEY (key, host))"
        )
        conn.execute(
            "CREATE TABLE audit_log ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT, session_id TEXT, source TEXT, "
            "action TEXT, target TEXT, host TEXT, "
            "pre_state_hash TEXT, post_state_hash TEXT, "
            "result TEXT, detail TEXT, chain_hash TEXT)"
        )
        conn.execute(
            "CREATE TABLE sessions ("
            "id TEXT PRIMARY KEY, created_at TEXT, "
            "tier TEXT, host TEXT, last_activity TEXT)"
        )
        conn.close()

        from roustabout.state_db import open_db

        db = open_db(db_path)
        rows = (
            db._reader_factory()
            .execute("SELECT name FROM sqlite_master WHERE type='table' AND name='digests'")
            .fetchall()
        )
        assert len(rows) == 1


# --- Compose parsing ---


class TestParseComposeServices:
    def test_basic_service(self, tmp_path):
        from roustabout.digest_tracker import parse_compose_services

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n  web:\n    image: nginx:latest\n    ports:\n      - '80:80'\n"
        )
        services = parse_compose_services(compose)
        assert len(services) == 1
        assert services[0].name == "web"
        assert services[0].image == "nginx:latest"
        assert "80:80" in services[0].ports

    def test_privileged_detected(self, tmp_path):
        from roustabout.digest_tracker import parse_compose_services

        compose = tmp_path / "compose.yml"
        compose.write_text("services:\n  app:\n    image: alpine\n    privileged: true\n")
        services = parse_compose_services(compose)
        assert services[0].privileged is True

    def test_capabilities_parsed(self, tmp_path):
        from roustabout.digest_tracker import parse_compose_services

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine\n"
            "    cap_add:\n"
            "      - SYS_ADMIN\n"
            "      - NET_RAW\n"
        )
        services = parse_compose_services(compose)
        assert "SYS_ADMIN" in services[0].cap_add
        assert "NET_RAW" in services[0].cap_add

    def test_volumes_parsed(self, tmp_path):
        from roustabout.digest_tracker import parse_compose_services

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine\n"
            "    volumes:\n"
            "      - /var/run/docker.sock:/var/run/docker.sock\n"
            "      - ./data:/data\n"
        )
        services = parse_compose_services(compose)
        assert len(services[0].volumes) == 2

    def test_environment_dict_form(self, tmp_path):
        from roustabout.digest_tracker import parse_compose_services

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine\n"
            "    environment:\n"
            "      DB_PASSWORD: secret123\n"
            "      TZ: UTC\n"
        )
        services = parse_compose_services(compose)
        assert services[0].environment["DB_PASSWORD"] == "secret123"

    def test_environment_list_form(self, tmp_path):
        from roustabout.digest_tracker import parse_compose_services

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine\n"
            "    environment:\n"
            "      - DB_PASSWORD=secret123\n"
        )
        services = parse_compose_services(compose)
        assert services[0].environment["DB_PASSWORD"] == "secret123"

    def test_no_image_uses_empty_string(self, tmp_path):
        from roustabout.digest_tracker import parse_compose_services

        compose = tmp_path / "compose.yml"
        compose.write_text("services:\n  app:\n    build: .\n")
        services = parse_compose_services(compose)
        assert services[0].image == ""

    def test_healthcheck_detected(self, tmp_path):
        from roustabout.digest_tracker import parse_compose_services

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: alpine\n"
            "    healthcheck:\n"
            "      test: curl -f http://localhost\n"
        )
        services = parse_compose_services(compose)
        assert services[0].healthcheck is True

    def test_empty_services(self, tmp_path):
        from roustabout.digest_tracker import parse_compose_services

        compose = tmp_path / "compose.yml"
        compose.write_text("services: {}\n")
        services = parse_compose_services(compose)
        assert services == []


# --- Static compose checks ---


class TestComposeStaticChecks:
    def test_docker_socket_flagged(self, tmp_path):
        from roustabout.digest_tracker import check_compose_static

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: portainer\n"
            "    volumes:\n"
            "      - /var/run/docker.sock:/var/run/docker.sock\n"
        )
        findings = check_compose_static(compose)
        categories = [f.category for f in findings]
        assert "docker-socket" in categories

    def test_privileged_flagged(self, tmp_path):
        from roustabout.digest_tracker import check_compose_static

        compose = tmp_path / "compose.yml"
        compose.write_text("services:\n  app:\n    image: alpine\n    privileged: true\n")
        findings = check_compose_static(compose)
        categories = [f.category for f in findings]
        assert "privileged" in categories

    def test_dangerous_cap_flagged(self, tmp_path):
        from roustabout.digest_tracker import check_compose_static

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n  app:\n    image: alpine\n    cap_add:\n      - SYS_ADMIN\n"
        )
        findings = check_compose_static(compose)
        categories = [f.category for f in findings]
        assert "dangerous-capability" in categories

    def test_host_network_flagged(self, tmp_path):
        from roustabout.digest_tracker import check_compose_static

        compose = tmp_path / "compose.yml"
        compose.write_text("services:\n  app:\n    image: alpine\n    network_mode: host\n")
        findings = check_compose_static(compose)
        categories = [f.category for f in findings]
        assert "host-network" in categories

    def test_secrets_in_env_flagged(self, tmp_path):
        from roustabout.digest_tracker import check_compose_static

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  db:\n"
            "    image: postgres\n"
            "    environment:\n"
            "      POSTGRES_PASSWORD: hunter2\n"
        )
        findings = check_compose_static(compose)
        categories = [f.category for f in findings]
        assert "secrets-in-env" in categories

    def test_clean_compose_no_findings(self, tmp_path):
        from roustabout.digest_tracker import check_compose_static

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25\n"
            "    restart: unless-stopped\n"
            "    healthcheck:\n"
            "      test: curl -f http://localhost\n"
            "    deploy:\n"
            "      resources:\n"
            "        limits:\n"
            "          memory: 256M\n"
        )
        findings = check_compose_static(compose)
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) == 0

    def test_no_restart_policy_flagged(self, tmp_path):
        from roustabout.digest_tracker import check_compose_static

        compose = tmp_path / "compose.yml"
        compose.write_text("services:\n  app:\n    image: alpine\n")
        findings = check_compose_static(compose)
        categories = [f.category for f in findings]
        assert "no-restart-policy" in categories

    def test_stale_image_latest_tag(self, tmp_path):
        from roustabout.digest_tracker import check_compose_static

        compose = tmp_path / "compose.yml"
        compose.write_text("services:\n  app:\n    image: nginx:latest\n")
        findings = check_compose_static(compose)
        categories = [f.category for f in findings]
        assert "stale-image" in categories


# --- Pre-deploy audit orchestration ---


class TestAuditPredeploy:
    def test_returns_report(self, tmp_path):
        from unittest.mock import patch

        from roustabout.digest_tracker import audit_predeploy
        from roustabout.state_db import open_db

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n  web:\n    image: nginx:1.25\n    restart: unless-stopped\n"
        )
        db = open_db(tmp_path / "state.db")

        # Mock registry calls
        with patch("roustabout.digest_tracker._resolve_service_digest") as mock_resolve:
            mock_resolve.return_value = ("sha256:abc123", None)
            report = audit_predeploy(compose, db)

        assert hasattr(report, "findings")
        assert hasattr(report, "digest_results")
        assert hasattr(report, "passed")

    def test_critical_finding_fails_report(self, tmp_path):
        from unittest.mock import patch

        from roustabout.digest_tracker import audit_predeploy
        from roustabout.state_db import open_db

        compose = tmp_path / "compose.yml"
        compose.write_text("services:\n  app:\n    image: alpine\n    privileged: true\n")
        db = open_db(tmp_path / "state.db")

        with patch("roustabout.digest_tracker._resolve_service_digest") as mock_resolve:
            mock_resolve.return_value = ("sha256:abc123", None)
            report = audit_predeploy(compose, db)

        assert report.passed is False

    def test_digest_cooldown_failure_fails_report(self, tmp_path):
        from unittest.mock import patch

        from roustabout.digest_tracker import audit_predeploy
        from roustabout.state_db import open_db

        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:1.25\n"
            "    restart: unless-stopped\n"
            "    healthcheck:\n"
            "      test: curl -f http://localhost\n"
        )
        db = open_db(tmp_path / "state.db")

        with patch("roustabout.digest_tracker._resolve_service_digest") as mock_resolve:
            mock_resolve.return_value = ("sha256:brand-new", None)
            report = audit_predeploy(compose, db, cooldown_hours=24.0)

        # Brand new digest should fail cooldown
        failing = [r for r in report.digest_results if not r.meets_cooldown]
        assert len(failing) >= 1

    def test_unresolvable_digest_recorded(self, tmp_path):
        from unittest.mock import patch

        from roustabout.digest_tracker import audit_predeploy
        from roustabout.state_db import open_db

        compose = tmp_path / "compose.yml"
        compose.write_text("services:\n  web:\n    image: nginx:1.25\n")
        db = open_db(tmp_path / "state.db")

        with patch("roustabout.digest_tracker._resolve_service_digest") as mock_resolve:
            mock_resolve.return_value = (None, None)
            report = audit_predeploy(compose, db)

        assert report.digest_results[0].digest is None
        assert report.digest_results[0].meets_cooldown is False

    def test_build_only_service_skipped_for_digest(self, tmp_path):
        from unittest.mock import patch

        from roustabout.digest_tracker import audit_predeploy
        from roustabout.state_db import open_db

        compose = tmp_path / "compose.yml"
        compose.write_text("services:\n  custom:\n    build: .\n")
        db = open_db(tmp_path / "state.db")

        with patch("roustabout.digest_tracker._resolve_service_digest") as mock_resolve:
            report = audit_predeploy(compose, db)

        mock_resolve.assert_not_called()
        assert len(report.digest_results) == 0
