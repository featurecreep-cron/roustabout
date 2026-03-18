"""Tests for state_db — SQLite state database with hash-chained audit log.

Covers S1.1.1 (schema/triage), S1.1.2 (TOML migration), S1.1.3 (audit log/hash chain).
"""

from __future__ import annotations

import ast
import hashlib
import json
import threading
from pathlib import Path

import pytest

from roustabout import state_db

# Helpers

def _manual_chain_hash(previous: str, row_data: str) -> str:
    """Independent hash computation for verification."""
    payload = (previous + "\x1e" + row_data).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _manual_length_prefix(value: str) -> str:
    return f"{len(value.encode('utf-8'))}:{value}"


def _manual_row_data(*fields: str) -> str:
    return "\x1f".join(_manual_length_prefix(f) for f in fields)


# S1.1.1: Schema, connection management, finding triage


class TestOpenDB:
    """Database opening, WAL mode, and schema bootstrap."""

    def test_creates_database_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        db = state_db.open_db(db_path)
        try:
            assert db_path.exists()
        finally:
            state_db.close_db(db)

    def test_wal_mode_enabled(self, tmp_path: Path) -> None:
        db = state_db.open_db(tmp_path / "test.db")
        try:
            reader = db._reader_factory()
            mode = reader.execute("PRAGMA journal_mode").fetchone()[0]
            reader.close()
            assert mode == "wal"
        finally:
            state_db.close_db(db)

    def test_foreign_keys_enabled(self, tmp_path: Path) -> None:
        db = state_db.open_db(tmp_path / "test.db")
        try:
            reader = db._reader_factory()
            fk = reader.execute("PRAGMA foreign_keys").fetchone()[0]
            reader.close()
            assert fk == 1
        finally:
            state_db.close_db(db)

    def test_schema_version_tracked(self, tmp_path: Path) -> None:
        db = state_db.open_db(tmp_path / "test.db")
        try:
            reader = db._reader_factory()
            version = reader.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()[0]
            reader.close()
            assert version == state_db.LATEST_VERSION
        finally:
            state_db.close_db(db)

    def test_tables_created(self, tmp_path: Path) -> None:
        db = state_db.open_db(tmp_path / "test.db")
        try:
            reader = db._reader_factory()
            tables = {
                row[0]
                for row in reader.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            reader.close()
            assert {"schema_version", "findings", "audit_log", "sessions"} <= tables
        finally:
            state_db.close_db(db)

    def test_reopen_skips_applied_migrations(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        db = state_db.open_db(db_path)
        state_db.close_db(db)

        # Reopen — should not fail
        db = state_db.open_db(db_path)
        try:
            reader = db._reader_factory()
            version = reader.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()[0]
            reader.close()
            assert version == state_db.LATEST_VERSION
        finally:
            state_db.close_db(db)

    def test_version_error_if_db_ahead(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        db = state_db.open_db(db_path)
        # Manually insert a future version
        db._writer.execute("BEGIN IMMEDIATE")
        db._writer.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (999, "2099-01-01"),
        )
        db._writer.execute("COMMIT")
        state_db.close_db(db)

        with pytest.raises(state_db.StateDBVersionError):
            state_db.open_db(db_path)

    def test_unreadable_db_raises_state_db_error(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        db = state_db.open_db(db_path)
        state_db.close_db(db)

        db_path.chmod(0o000)
        try:
            with pytest.raises(state_db.StateDBError, match="not readable"):
                state_db.open_db(db_path)
        finally:
            db_path.chmod(0o644)


class TestFindingTriage:
    """Finding triage CRUD — S1.1.1 T4."""

    @pytest.fixture()
    def db(self, tmp_path: Path) -> state_db.StateDB:
        db = state_db.open_db(tmp_path / "test.db")
        yield db
        state_db.close_db(db)

    def test_set_and_load_finding(self, db: state_db.StateDB) -> None:
        state_db.set_finding_state(
            db,
            key="container1|privileged",
            host="localhost",
            state="accepted",
            reason="testing",
            session_id="test-session",
        )
        findings = state_db.load_findings(db, host="localhost")
        assert "container1|privileged" in findings
        f = findings["container1|privileged"]
        assert f.state == "accepted"
        assert f.reason == "testing"

    def test_upsert_overwrites(self, db: state_db.StateDB) -> None:
        state_db.set_finding_state(
            db,
            key="c|priv",
            host="localhost",
            state="accepted",
            reason="first",
            session_id="s1",
        )
        state_db.set_finding_state(
            db,
            key="c|priv",
            host="localhost",
            state="false-positive",
            reason="updated",
            session_id="s2",
        )
        findings = state_db.load_findings(db, host="localhost")
        assert findings["c|priv"].state == "false-positive"
        assert findings["c|priv"].reason == "updated"

    def test_host_isolation(self, db: state_db.StateDB) -> None:
        state_db.set_finding_state(
            db,
            key="c|priv",
            host="host-a",
            state="accepted",
            reason="a",
            session_id="s",
        )
        state_db.set_finding_state(
            db,
            key="c|priv",
            host="host-b",
            state="resolved",
            reason="b",
            session_id="s",
        )
        assert state_db.load_findings(db, host="host-a")["c|priv"].state == "accepted"
        assert state_db.load_findings(db, host="host-b")["c|priv"].state == "resolved"

    def test_clear_resolved_finding(self, db: state_db.StateDB) -> None:
        state_db.set_finding_state(
            db,
            key="c|priv",
            host="localhost",
            state="resolved",
            reason="done",
            session_id="s",
        )
        state_db.clear_resolved_finding(db, key="c|priv", host="localhost")
        findings = state_db.load_findings(db, host="localhost")
        assert "c|priv" not in findings

    def test_set_finding_logs_audit(self, db: state_db.StateDB) -> None:
        state_db.set_finding_state(
            db,
            key="c|priv",
            host="localhost",
            state="accepted",
            reason="test",
            session_id="s1",
        )
        reader = db._reader_factory()
        row = reader.execute(
            "SELECT action, target, result FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        reader.close()
        assert row[0] == "triage"
        assert row[1] == "c|priv"
        assert row[2] == "success"


# S1.1.2: TOML migration


class TestTOMLMigration:
    """TOML → SQLite finding state migration."""

    def _write_toml(self, path: Path, entries: dict[str, dict[str, str]]) -> None:
        lines = []
        for key, data in entries.items():
            lines.append(f'[findings."{key}"]')
            for k, v in data.items():
                lines.append(f'{k} = "{v}"')
            lines.append("")
        path.write_text("\n".join(lines))

    def test_migrates_populated_toml(self, tmp_path: Path) -> None:
        toml_path = tmp_path / "roustabout.state.toml"
        self._write_toml(
            toml_path,
            {
                "container1|privileged": {
                    "state": "accepted",
                    "reason": "test",
                    "timestamp": "2026-01-01T00:00:00",
                },
                "container2|socket": {
                    "state": "false-positive",
                    "reason": "intentional",
                    "timestamp": "2026-01-02T00:00:00",
                },
            },
        )

        db = state_db.open_db(tmp_path / "test.db", toml_search_paths=(toml_path,))
        try:
            findings = state_db.load_findings(db, host="localhost")
            assert len(findings) == 2
            assert findings["container1|privileged"].state == "accepted"
            assert findings["container2|socket"].state == "false-positive"
        finally:
            state_db.close_db(db)

    def test_empty_toml_migrates_without_error(self, tmp_path: Path) -> None:
        toml_path = tmp_path / "roustabout.state.toml"
        toml_path.write_text("# empty\n")

        db = state_db.open_db(tmp_path / "test.db", toml_search_paths=(toml_path,))
        try:
            findings = state_db.load_findings(db, host="localhost")
            assert len(findings) == 0
        finally:
            state_db.close_db(db)

    def test_skip_when_sqlite_already_has_data(self, tmp_path: Path) -> None:
        toml_path = tmp_path / "roustabout.state.toml"
        self._write_toml(
            toml_path,
            {"c|priv": {"state": "accepted", "reason": "x", "timestamp": "2026-01-01"}},
        )

        # First open — migrates
        db = state_db.open_db(tmp_path / "test.db", toml_search_paths=(toml_path,))
        state_db.close_db(db)

        # Update TOML to have different data
        self._write_toml(
            toml_path,
            {"c|new": {"state": "resolved", "reason": "y", "timestamp": "2026-02-01"}},
        )

        # Second open — should NOT re-migrate (detection guard)
        db = state_db.open_db(tmp_path / "test.db", toml_search_paths=(toml_path,))
        try:
            findings = state_db.load_findings(db, host="localhost")
            assert "c|priv" in findings
            assert "c|new" not in findings
        finally:
            state_db.close_db(db)

    def test_skip_when_no_toml(self, tmp_path: Path) -> None:
        # No TOML file present — should not error
        db = state_db.open_db(tmp_path / "test.db", toml_search_paths=())
        try:
            findings = state_db.load_findings(db, host="localhost")
            assert len(findings) == 0
        finally:
            state_db.close_db(db)

    def test_toml_preserved_after_migration(self, tmp_path: Path) -> None:
        toml_path = tmp_path / "roustabout.state.toml"
        self._write_toml(
            toml_path,
            {"c|priv": {"state": "accepted", "reason": "x", "timestamp": "2026-01-01"}},
        )

        db = state_db.open_db(tmp_path / "test.db", toml_search_paths=(toml_path,))
        state_db.close_db(db)

        # Original file still exists (not deleted)
        assert toml_path.exists()


# S1.1.3: Audit log with hash chain


class TestAuditLog:
    """Audit log insert and hash chain verification."""

    @pytest.fixture()
    def db(self, tmp_path: Path) -> state_db.StateDB:
        db = state_db.open_db(tmp_path / "test.db")
        yield db
        state_db.close_db(db)

    def test_insert_single_entry(self, db: state_db.StateDB) -> None:
        row_id = state_db.log_audit(
            db,
            session_id="s1",
            source="cli",
            action="start",
            target="nginx",
            host="localhost",
            pre_state_hash="abc",
            post_state_hash="def",
            result="success",
            detail=None,
        )
        assert row_id >= 1

    def test_chain_verification_passes(self, db: state_db.StateDB) -> None:
        for i in range(5):
            state_db.log_audit(
                db,
                session_id="s1",
                source="cli",
                action="start",
                target=f"container-{i}",
                host="localhost",
                pre_state_hash=f"pre-{i}",
                post_state_hash=f"post-{i}",
                result="success",
                detail=None,
            )
        result = state_db.verify_chain(db)
        assert result.valid is True
        assert result.rows_checked == 5

    def test_tampered_entry_detected(self, db: state_db.StateDB) -> None:
        state_db.log_audit(
            db,
            session_id="s1",
            source="cli",
            action="start",
            target="nginx",
            host="localhost",
            pre_state_hash="abc",
            post_state_hash="def",
            result="success",
            detail=None,
        )
        state_db.log_audit(
            db,
            session_id="s1",
            source="cli",
            action="stop",
            target="nginx",
            host="localhost",
            pre_state_hash="def",
            post_state_hash=None,
            result="success",
            detail=None,
        )

        # Tamper with the first row
        db._writer.execute("BEGIN IMMEDIATE")
        db._writer.execute("UPDATE audit_log SET target = 'hacked' WHERE id = 1")
        db._writer.execute("COMMIT")

        result = state_db.verify_chain(db)
        assert result.valid is False
        assert result.first_broken_row == 1

    def test_genesis_chain_hash(self, db: state_db.StateDB) -> None:
        state_db.log_audit(
            db,
            session_id="s1",
            source="cli",
            action="start",
            target="nginx",
            host="localhost",
            pre_state_hash="abc",
            post_state_hash="def",
            result="success",
            detail=None,
        )
        reader = db._reader_factory()
        row = reader.execute(
            "SELECT chain_hash FROM audit_log WHERE id = 1"
        ).fetchone()
        reader.close()
        assert row[0] is not None
        assert len(row[0]) == 64  # SHA-256 hex

    def test_detail_blob_scrubbing(self, db: state_db.StateDB) -> None:
        state_db.log_audit(
            db,
            session_id="s1",
            source="cli",
            action="start",
            target="nginx",
            host="localhost",
            pre_state_hash="abc",
            post_state_hash="def",
            result="success",
            detail={"image": "nginx:latest", "password": "hunter2", "api_key": "sk-abc123"},
        )
        reader = db._reader_factory()
        row = reader.execute("SELECT detail FROM audit_log WHERE id = 1").fetchone()
        reader.close()
        detail = json.loads(row[0])
        assert detail["image"] == "nginx:latest"
        assert detail["password"] == "[REDACTED]"
        assert detail["api_key"] == "[REDACTED]"

    def test_pre_post_state_diff_in_detail(self, db: state_db.StateDB) -> None:
        detail = {
            "diff": {"image": {"before": "nginx:1.24", "after": "nginx:1.25"}},
        }
        state_db.log_audit(
            db,
            session_id="s1",
            source="mcp",
            action="recreate",
            target="nginx",
            host="localhost",
            pre_state_hash="hash-before",
            post_state_hash="hash-after",
            result="success",
            detail=detail,
        )
        reader = db._reader_factory()
        row = reader.execute("SELECT detail FROM audit_log WHERE id = 1").fetchone()
        reader.close()
        stored = json.loads(row[0])
        assert stored["diff"]["image"]["before"] == "nginx:1.24"
        assert stored["diff"]["image"]["after"] == "nginx:1.25"

    def test_concurrent_writes_preserve_chain(self, db: state_db.StateDB) -> None:
        """Two threads writing audit entries — chain should stay valid."""
        errors: list[Exception] = []

        def writer(name: str) -> None:
            try:
                for i in range(10):
                    state_db.log_audit(
                        db,
                        session_id=f"session-{name}",
                        source="cli",
                        action="start",
                        target=f"container-{name}-{i}",
                        host="localhost",
                        pre_state_hash=f"pre-{name}-{i}",
                        post_state_hash=f"post-{name}-{i}",
                        result="success",
                        detail=None,
                    )
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=writer, args=("a",))
        t2 = threading.Thread(target=writer, args=("b",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors, f"Thread errors: {errors}"

        result = state_db.verify_chain(db)
        assert result.valid is True
        assert result.rows_checked == 20

    def test_verify_chain_with_host_filter(self, db: state_db.StateDB) -> None:
        state_db.log_audit(
            db,
            session_id="s1",
            source="cli",
            action="start",
            target="c1",
            host="host-a",
            pre_state_hash="a",
            post_state_hash="b",
            result="success",
            detail=None,
        )
        state_db.log_audit(
            db,
            session_id="s1",
            source="cli",
            action="start",
            target="c2",
            host="host-b",
            pre_state_hash="c",
            post_state_hash="d",
            result="success",
            detail=None,
        )
        result = state_db.verify_chain(db, host="host-a")
        assert result.partial is True


# Session tracking (used by S1.1.1 and S1.2.1)


class TestSessionTracking:
    """Session CRUD in state_db."""

    @pytest.fixture()
    def db(self, tmp_path: Path) -> state_db.StateDB:
        db = state_db.open_db(tmp_path / "test.db")
        yield db
        state_db.close_db(db)

    def test_create_and_get_session(self, db: state_db.StateDB) -> None:
        state_db.create_session(db, session_id="s1", tier="observe", host="localhost")
        session = state_db.get_session(db, session_id="s1")
        assert session is not None
        assert session.id == "s1"
        assert session.tier == "observe"
        assert session.host == "localhost"

    def test_update_session_tier(self, db: state_db.StateDB) -> None:
        state_db.create_session(db, session_id="s1", tier="observe", host="localhost")
        state_db.update_session_tier(db, session_id="s1", new_tier="operate")
        session = state_db.get_session(db, session_id="s1")
        assert session is not None
        assert session.tier == "operate"

    def test_update_session_activity(self, db: state_db.StateDB) -> None:
        state_db.create_session(db, session_id="s1", tier="observe", host="localhost")
        original = state_db.get_session(db, session_id="s1")
        assert original is not None
        state_db.update_session_activity(db, session_id="s1")
        updated = state_db.get_session(db, session_id="s1")
        assert updated is not None
        assert updated.last_activity >= original.last_activity

    def test_get_nonexistent_session(self, db: state_db.StateDB) -> None:
        assert state_db.get_session(db, session_id="nope") is None


# Circuit breaker queries


class TestCircuitBreaker:
    """Circuit breaker query logic."""

    @pytest.fixture()
    def db(self, tmp_path: Path) -> state_db.StateDB:
        db = state_db.open_db(tmp_path / "test.db")
        yield db
        state_db.close_db(db)

    def test_circuit_closed_by_default(self, db: state_db.StateDB) -> None:
        result = state_db.check_circuit(db, target="nginx", host="localhost")
        assert result.open is False
        assert result.consecutive_failures == 0

    def test_circuit_opens_after_threshold_failures(self, db: state_db.StateDB) -> None:
        for i in range(3):
            state_db.log_audit(
                db,
                session_id="s1",
                source="mcp",
                action="restart",
                target="nginx",
                host="localhost",
                pre_state_hash=f"pre-{i}",
                post_state_hash=None,
                result="failed",
                detail={"error_type": "mutation_error", "message": f"fail {i}"},
            )
        result = state_db.check_circuit(db, target="nginx", host="localhost")
        assert result.open is True
        assert result.consecutive_failures == 3

    def test_success_breaks_failure_streak(self, db: state_db.StateDB) -> None:
        state_db.log_audit(
            db,
            session_id="s1",
            source="mcp",
            action="restart",
            target="nginx",
            host="localhost",
            pre_state_hash="a",
            post_state_hash=None,
            result="failed",
            detail={"error_type": "mutation_error"},
        )
        state_db.log_audit(
            db,
            session_id="s1",
            source="mcp",
            action="restart",
            target="nginx",
            host="localhost",
            pre_state_hash="b",
            post_state_hash="c",
            result="success",
            detail=None,
        )
        state_db.log_audit(
            db,
            session_id="s1",
            source="mcp",
            action="restart",
            target="nginx",
            host="localhost",
            pre_state_hash="d",
            post_state_hash=None,
            result="failed",
            detail={"error_type": "mutation_error"},
        )
        result = state_db.check_circuit(db, target="nginx", host="localhost")
        assert result.open is False
        assert result.consecutive_failures == 1

    def test_connection_errors_dont_trip_breaker(self, db: state_db.StateDB) -> None:
        for i in range(3):
            state_db.log_audit(
                db,
                session_id="s1",
                source="mcp",
                action="restart",
                target="nginx",
                host="localhost",
                pre_state_hash=f"pre-{i}",
                post_state_hash=None,
                result="failed",
                detail={"error_type": "connection_error"},
            )
        result = state_db.check_circuit(db, target="nginx", host="localhost")
        assert result.open is False

    def test_reset_circuit(self, db: state_db.StateDB) -> None:
        for i in range(3):
            state_db.log_audit(
                db,
                session_id="s1",
                source="mcp",
                action="restart",
                target="nginx",
                host="localhost",
                pre_state_hash=f"pre-{i}",
                post_state_hash=None,
                result="failed",
                detail={"error_type": "mutation_error"},
            )
        state_db.reset_circuit(
            db,
            target="nginx",
            host="localhost",
            session_id="s1",
            reason="manual reset",
        )
        result = state_db.check_circuit(db, target="nginx", host="localhost")
        assert result.open is False


# Previous findings comparison


class TestPreviousFindings:
    """Audit-complete entries for notification triggers."""

    @pytest.fixture()
    def db(self, tmp_path: Path) -> state_db.StateDB:
        db = state_db.open_db(tmp_path / "test.db")
        yield db
        state_db.close_db(db)

    def test_no_previous_audit(self, db: state_db.StateDB) -> None:
        assert state_db.load_previous_audit(db, host="localhost") is None

    def test_stores_and_loads_findings_summary(self, db: state_db.StateDB) -> None:
        summary = [
            {"key": "c|priv", "severity": "critical", "category": "privileged", "container": "c"},
        ]
        state_db.log_audit_complete(
            db, session_id="s1", source="cli", host="localhost", findings_summary=summary
        )
        loaded = state_db.load_previous_audit(db, host="localhost")
        assert loaded == summary


# Hash chain internals


class TestHashChainInternals:
    """Direct tests on length prefix and row data building."""

    def test_length_prefix_ascii(self) -> None:
        assert state_db._length_prefix("hello") == "5:hello"

    def test_length_prefix_utf8(self) -> None:
        # "ä" is 2 bytes in UTF-8
        assert state_db._length_prefix("ä") == "2:ä"

    def test_length_prefix_emoji(self) -> None:
        # 🐳 is 4 bytes in UTF-8
        assert state_db._length_prefix("🐳") == "4:🐳"

    def test_build_row_data(self) -> None:
        result = state_db._build_row_data(
            "ts", "sid", "src", "act", "tgt", "host", "pre", None, "ok", None
        )
        expected = _manual_row_data("ts", "sid", "src", "act", "tgt", "host", "pre", "", "ok", "")
        assert result == expected

    def test_compute_chain_hash_deterministic(self) -> None:
        h1 = state_db._compute_chain_hash("prev", "data")
        h2 = state_db._compute_chain_hash("prev", "data")
        assert h1 == h2

    def test_compute_chain_hash_matches_manual(self) -> None:
        result = state_db._compute_chain_hash("prev", "data")
        expected = _manual_chain_hash("prev", "data")
        assert result == expected


# Lint test: only state_db.py imports sqlite3


class TestArchitecturalLint:
    """S1.1.1 T5: Lint test — only state_db.py imports sqlite3."""

    def test_only_state_db_imports_sqlite3(self) -> None:
        src_dir = Path(__file__).parent.parent / "src" / "roustabout"
        violations = []
        for py_file in src_dir.glob("*.py"):
            if py_file.name == "state_db.py":
                continue
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "sqlite3" or alias.name.startswith("sqlite3."):
                            violations.append(py_file.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module and (
                        node.module == "sqlite3" or node.module.startswith("sqlite3.")
                    ):
                        violations.append(py_file.name)
        assert violations == [], f"sqlite3 imported outside state_db.py: {violations}"
