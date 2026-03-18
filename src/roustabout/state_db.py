"""SQLite state database with hash-chained audit log.

Sole SQLite consumer in roustabout. Owns schema bootstrap, migration,
hash-chained audit writes, session tracking, finding triage, circuit
breaker queries, and audit chain verification.

No other module opens a database connection.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from roustabout.redactor import is_secret_key

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GENESIS = "roustabout-genesis"
SEPARATOR = "\x1f"  # ASCII Unit Separator
RECORD_SEPARATOR = "\x1e"  # ASCII Record Separator

LATEST_VERSION = 1

_MIGRATIONS: list[tuple[int, list[str]]] = [
    (1, [
        """CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )""",
        """CREATE TABLE findings (
            key TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT 'localhost',
            state TEXT NOT NULL CHECK (state IN ('accepted', 'false-positive', 'resolved')),
            reason TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            PRIMARY KEY (key, host)
        )""",
        """CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            session_id TEXT NOT NULL,
            source TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT 'localhost',
            pre_state_hash TEXT NOT NULL,
            post_state_hash TEXT,
            result TEXT NOT NULL,
            detail TEXT,
            chain_hash TEXT NOT NULL
        )""",
        "CREATE INDEX idx_audit_log_target ON audit_log (target, host, id DESC)",
        """CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            tier TEXT NOT NULL DEFAULT 'observe',
            host TEXT NOT NULL DEFAULT 'localhost',
            last_activity TEXT NOT NULL
        )""",
    ]),
]

# Default paths for TOML state file migration
_DEFAULT_TOML_PATHS = (
    Path("roustabout.state.toml"),
    Path.home() / ".config" / "roustabout" / "state.toml",
)

# Default paths for database
_DEFAULT_DB_PATHS = (
    Path("roustabout.db"),
    Path.home() / ".config" / "roustabout" / "roustabout.db",
)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class StateDB:
    """Opaque handle returned by open_db."""

    __slots__ = ("path", "_writer", "_writer_lock", "_reader_factory")

    def __init__(
        self,
        path: Path,
        _writer: sqlite3.Connection,
        _reader_factory: Callable[[], sqlite3.Connection],
    ) -> None:
        self.path = path
        self._writer = _writer
        self._writer_lock = threading.Lock()
        self._reader_factory = _reader_factory


@dataclass(frozen=True)
class SessionRow:
    id: str
    created_at: str
    tier: str
    host: str
    last_activity: str


@dataclass(frozen=True)
class FindingRow:
    key: str
    host: str
    state: str
    reason: str
    timestamp: str


@dataclass(frozen=True)
class CircuitState:
    open: bool
    consecutive_failures: int
    last_failure_detail: str | None


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    rows_checked: int
    first_broken_row: int | None
    error: str | None
    partial: bool = False


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class StateDBError(Exception):
    """Base class for state_db errors."""


class StateDBVersionError(StateDBError):
    """Database schema is newer than code — cannot open."""


class ChainIntegrityError(StateDBError):
    """Hash chain verification failed."""


# ---------------------------------------------------------------------------
# Hash chain internals
# ---------------------------------------------------------------------------


def _length_prefix(value: str) -> str:
    """Prefix with UTF-8 byte length to prevent collision attacks."""
    return f"{len(value.encode('utf-8'))}:{value}"


def _build_row_data(
    timestamp: str,
    session_id: str,
    source: str,
    action: str,
    target: str,
    host: str,
    pre_state_hash: str,
    post_state_hash: str | None,
    result: str,
    detail_json: str | None,
) -> str:
    """Concatenate length-prefixed fields with unit separator."""
    fields = [
        timestamp,
        session_id,
        source,
        action,
        target,
        host,
        pre_state_hash,
        post_state_hash or "",
        result,
        detail_json or "",
    ]
    return SEPARATOR.join(_length_prefix(f) for f in fields)


def _compute_chain_hash(previous_chain_hash: str, row_data: str) -> str:
    """SHA-256(previous_hash + record_separator + row_data), hex-encoded."""
    payload = (previous_chain_hash + RECORD_SEPARATOR + row_data).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Detail scrubbing
# ---------------------------------------------------------------------------


def _scrub_detail(detail: dict[str, Any]) -> dict[str, Any]:
    """Replace values of secret-matching keys with '[REDACTED]'.

    Recurses into nested dicts. Key-based detection via is_secret_key.
    """
    scrubbed: dict[str, Any] = {}
    for k, v in detail.items():
        if isinstance(v, str):
            if is_secret_key(k, v, ()):
                scrubbed[k] = "[REDACTED]"
            else:
                scrubbed[k] = v
        elif isinstance(v, dict):
            scrubbed[k] = _scrub_detail(v)
        elif isinstance(v, list):
            scrubbed[k] = [
                _scrub_detail(item) if isinstance(item, dict)
                else (
                    "[REDACTED]"
                    if isinstance(item, str) and is_secret_key(k, item, ())
                    else item
                )
                for item in v
            ]
        else:
            scrubbed[k] = v
    return scrubbed


# ---------------------------------------------------------------------------
# Connection setup
# ---------------------------------------------------------------------------


def _make_connection(path: Path) -> sqlite3.Connection:
    """Create a connection with standard pragmas."""
    conn = sqlite3.connect(str(path), check_same_thread=False, autocommit=True)
    actual_mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    if actual_mode != "wal":
        conn.close()
        raise StateDBError(
            f"Failed to enable WAL mode (got '{actual_mode}'). "
            "Check filesystem permissions and that the path is not on a network mount."
        )
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Schema bootstrap
# ---------------------------------------------------------------------------


def _bootstrap_schema(db: StateDB, toml_search_paths: tuple[Path, ...]) -> None:
    """Create tables and run migrations if needed."""
    conn = db._writer
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Check if schema_version table exists
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        ).fetchone()
        is_fresh = row is None

        if is_fresh:
            # Fresh database — run all migrations
            for version, statements in _MIGRATIONS:
                for stmt in statements:
                    conn.execute(stmt)
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (version, datetime.now(UTC).isoformat()),
                )
            conn.execute("COMMIT")
            # Migrate TOML state if found
            _try_toml_migration(db, toml_search_paths)
        else:
            current = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0
            if current > LATEST_VERSION:
                conn.execute("ROLLBACK")
                raise StateDBVersionError(
                    f"Database schema version {current} is newer than code version "
                    f"{LATEST_VERSION}. Upgrade roustabout."
                )
            if current < LATEST_VERSION:
                for version, statements in _MIGRATIONS:
                    if version > current:
                        for stmt in statements:
                            conn.execute(stmt)
                        conn.execute(
                            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                            (version, datetime.now(UTC).isoformat()),
                        )
            conn.execute("COMMIT")
    except BaseException:
        with contextlib.suppress(Exception):
            conn.execute("ROLLBACK")
        raise


# ---------------------------------------------------------------------------
# TOML migration
# ---------------------------------------------------------------------------


def _try_toml_migration(
    db: StateDB, toml_search_paths: tuple[Path, ...]
) -> None:
    """Migrate TOML finding state to SQLite on fresh database."""
    from roustabout.state import load_state

    selected: Path | None = None
    for candidate in toml_search_paths:
        if candidate.exists():
            selected = candidate
            break

    if selected is None:
        return

    entries = load_state(selected)
    if not entries:
        return

    conn = db._writer
    conn.execute("BEGIN IMMEDIATE")
    try:
        count = 0
        for key, entry in entries.items():
            conn.execute(
                "INSERT OR IGNORE INTO findings (key, host, state, reason, timestamp) "
                "VALUES (?, 'localhost', ?, ?, ?)",
                (key, entry.state.value, entry.reason, entry.timestamp),
            )
            count += 1
        conn.execute("COMMIT")

        # Log the migration in audit trail
        _log_audit_internal(
            db,
            session_id=f"migration-{datetime.now(UTC).isoformat()}",
            source="migrate",
            action="migrate-state",
            target="toml-migration",
            host="localhost",
            pre_state_hash="",
            post_state_hash=None,
            result="success",
            detail={"from": "toml", "path": str(selected), "entries": count},
        )
    except BaseException:
        with contextlib.suppress(Exception):
            conn.execute("ROLLBACK")
        raise


# ---------------------------------------------------------------------------
# Database lifecycle
# ---------------------------------------------------------------------------


def open_db(
    path: Path | None = None,
    *,
    toml_search_paths: tuple[Path, ...] | None = None,
) -> StateDB:
    """Open or create the state database.

    On first open: creates schema, runs migrations, migrates TOML state.
    On subsequent opens: runs any unapplied migrations.
    """
    if path is None:
        resolved = _DEFAULT_DB_PATHS[0]
    else:
        resolved = path

    resolved.parent.mkdir(parents=True, exist_ok=True)

    writer = _make_connection(resolved)

    def reader_factory() -> sqlite3.Connection:
        return _make_connection(resolved)

    db = StateDB(path=resolved, _writer=writer, _reader_factory=reader_factory)

    if toml_search_paths is None:
        toml_paths = _DEFAULT_TOML_PATHS
    else:
        toml_paths = toml_search_paths

    _bootstrap_schema(db, toml_paths)

    return db


def close_db(db: StateDB) -> None:
    """Close the writer connection."""
    db._writer.close()


# ---------------------------------------------------------------------------
# Audit log (internal helper for use within transactions)
# ---------------------------------------------------------------------------


def _log_audit_internal(
    db: StateDB,
    *,
    session_id: str,
    source: str,
    action: str,
    target: str,
    host: str,
    pre_state_hash: str,
    post_state_hash: str | None,
    result: str,
    detail: dict[str, Any] | None,
) -> int:
    """Append audit entry. Caller must handle locking if needed."""
    scrubbed = _scrub_detail(detail) if detail else None
    detail_json = json.dumps(scrubbed, sort_keys=True) if scrubbed else None

    ts = datetime.now(UTC).isoformat()
    row_data = _build_row_data(
        ts, session_id, source, action, target, host,
        pre_state_hash, post_state_hash, result, detail_json,
    )

    conn = db._writer
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row[0] if row else GENESIS
        chain_hash = _compute_chain_hash(prev_hash, row_data)

        cursor = conn.execute(
            """INSERT INTO audit_log
               (timestamp, session_id, source, action, target, host,
                pre_state_hash, post_state_hash, result, detail, chain_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ts, session_id, source, action, target, host,
             pre_state_hash, post_state_hash, result, detail_json, chain_hash),
        )
        conn.execute("COMMIT")
        return cursor.lastrowid  # type: ignore[return-value]
    except BaseException:
        with contextlib.suppress(Exception):
            conn.execute("ROLLBACK")
        raise


# ---------------------------------------------------------------------------
# Audit log (public API)
# ---------------------------------------------------------------------------


def log_audit(
    db: StateDB,
    *,
    session_id: str,
    source: str,
    action: str,
    target: str,
    host: str,
    pre_state_hash: str,
    post_state_hash: str | None,
    result: str,
    detail: dict[str, Any] | None,
) -> int:
    """Append an audit log entry with hash chain computation.

    Thread-safe via writer lock.
    """
    with db._writer_lock:
        return _log_audit_internal(
            db,
            session_id=session_id,
            source=source,
            action=action,
            target=target,
            host=host,
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
            result=result,
            detail=detail,
        )


def verify_chain(db: StateDB, host: str | None = None) -> ChainVerification:
    """Walk the audit log and verify hash chain integrity."""
    reader = db._reader_factory()
    try:
        # Always read the full chain — host filter only limits which rows
        # we actively verify, but we need the full sequence for prev_hash.
        all_rows = reader.execute(
            """SELECT id, timestamp, session_id, source, action, target, host,
                      pre_state_hash, post_state_hash, result, detail, chain_hash
               FROM audit_log ORDER BY id"""
        ).fetchall()

        if not all_rows:
            return ChainVerification(
                valid=True, rows_checked=0, first_broken_row=None,
                error=None, partial=host is not None,
            )

        prev_hash = GENESIS
        checked = 0
        for row in all_rows:
            (row_id, ts, sid, src, act, tgt, h,
             pre, post, res, det, stored_hash) = row
            row_data = _build_row_data(ts, sid, src, act, tgt, h, pre, post, res, det)
            expected = _compute_chain_hash(prev_hash, row_data)

            # When filtering by host, only report mismatches for matching rows
            if host is None or h == host:
                checked += 1
                if expected != stored_hash:
                    return ChainVerification(
                        valid=False,
                        rows_checked=checked,
                        first_broken_row=row_id,
                        error=f"Hash mismatch at row {row_id}",
                        partial=host is not None,
                    )
            else:
                # Still need to verify chain continuity even for non-matching rows
                if expected != stored_hash:
                    return ChainVerification(
                        valid=False,
                        rows_checked=checked,
                        first_broken_row=row_id,
                        error=f"Hash mismatch at row {row_id} (cross-host)",
                        partial=True,
                    )

            prev_hash = stored_hash

        return ChainVerification(
            valid=True, rows_checked=checked, first_broken_row=None,
            error=None, partial=host is not None,
        )
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# Session tracking
# ---------------------------------------------------------------------------


def create_session(
    db: StateDB, *, session_id: str, tier: str, host: str
) -> None:
    """Insert a new session row."""
    now = datetime.now(UTC).isoformat()
    with db._writer_lock:
        conn = db._writer
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO sessions (id, created_at, tier, host, last_activity) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, now, tier, host, now),
            )
            conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                conn.execute("ROLLBACK")
            raise


def update_session_tier(db: StateDB, *, session_id: str, new_tier: str) -> None:
    """Update session tier."""
    with db._writer_lock:
        conn = db._writer
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "UPDATE sessions SET tier = ? WHERE id = ?",
                (new_tier, session_id),
            )
            conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                conn.execute("ROLLBACK")
            raise


def update_session_activity(db: StateDB, *, session_id: str) -> None:
    """Touch last_activity timestamp."""
    now = datetime.now(UTC).isoformat()
    with db._writer_lock:
        conn = db._writer
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "UPDATE sessions SET last_activity = ? WHERE id = ?",
                (now, session_id),
            )
            conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                conn.execute("ROLLBACK")
            raise


def get_session(db: StateDB, *, session_id: str) -> SessionRow | None:
    """Read session by ID."""
    reader = db._reader_factory()
    try:
        row = reader.execute(
            "SELECT id, created_at, tier, host, last_activity FROM sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        return SessionRow(
            id=row[0], created_at=row[1], tier=row[2],
            host=row[3], last_activity=row[4],
        )
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# Finding triage
# ---------------------------------------------------------------------------


def set_finding_state(
    db: StateDB,
    *,
    key: str,
    host: str,
    state: str,
    reason: str,
    session_id: str,
) -> None:
    """Upsert a finding triage entry and log to audit trail."""
    now = datetime.now(UTC).isoformat()
    with db._writer_lock:
        conn = db._writer
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                """INSERT INTO findings (key, host, state, reason, timestamp)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT (key, host) DO UPDATE
                   SET state = excluded.state,
                       reason = excluded.reason,
                       timestamp = excluded.timestamp""",
                (key, host, state, reason, now),
            )
            conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                conn.execute("ROLLBACK")
            raise

    # Log to audit trail (separate transaction)
    log_audit(
        db,
        session_id=session_id,
        source="cli",
        action="triage",
        target=key,
        host=host,
        pre_state_hash="",
        post_state_hash=None,
        result="success",
        detail={"state": state, "reason": reason},
    )


def load_findings(db: StateDB, *, host: str) -> dict[str, FindingRow]:
    """Load all triage entries for a host."""
    reader = db._reader_factory()
    try:
        rows = reader.execute(
            "SELECT key, host, state, reason, timestamp FROM findings WHERE host = ?",
            (host,),
        ).fetchall()
        return {
            row[0]: FindingRow(
                key=row[0], host=row[1], state=row[2],
                reason=row[3], timestamp=row[4],
            )
            for row in rows
        }
    finally:
        reader.close()


def clear_resolved_finding(db: StateDB, *, key: str, host: str) -> None:
    """Remove a resolved finding that has reappeared (regression)."""
    with db._writer_lock:
        conn = db._writer
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "DELETE FROM findings WHERE key = ? AND host = ?",
                (key, host),
            )
            conn.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(Exception):
                conn.execute("ROLLBACK")
            raise


# ---------------------------------------------------------------------------
# Circuit breaker queries
# ---------------------------------------------------------------------------


def check_circuit(
    db: StateDB, *, target: str, host: str, threshold: int = 3
) -> CircuitState:
    """Check if circuit is open for a target."""
    reader = db._reader_factory()
    try:
        rows = reader.execute(
            """SELECT result, detail FROM audit_log
               WHERE target = ? AND host = ?
               AND action NOT IN (
                   'audit-complete', 'triage',
                   'tier-change', 'migrate-state'
               )
               ORDER BY id DESC LIMIT ?""",
            (target, host, threshold),
        ).fetchall()

        if len(rows) < threshold:
            consecutive = sum(1 for r in rows if r[0] == "failed")
            return CircuitState(
                open=False,
                consecutive_failures=consecutive,
                last_failure_detail=None,
            )

        consecutive = 0
        last_detail = None
        for result_val, detail_json in rows:
            if result_val != "failed":
                break
            if not detail_json:
                break
            detail = json.loads(detail_json)
            if detail.get("error_type") != "mutation_error":
                break
            consecutive += 1
            if last_detail is None:
                last_detail = detail_json

        return CircuitState(
            open=consecutive >= threshold,
            consecutive_failures=consecutive,
            last_failure_detail=last_detail,
        )
    finally:
        reader.close()


def reset_circuit(
    db: StateDB,
    *,
    target: str,
    host: str,
    session_id: str,
    reason: str,
) -> None:
    """Insert a circuit-reset audit entry, breaking the failure streak."""
    log_audit(
        db,
        session_id=session_id,
        source="cli",
        action="circuit-reset",
        target=target,
        host=host,
        pre_state_hash="",
        post_state_hash=None,
        result="success",
        detail={"reason": reason},
    )


# ---------------------------------------------------------------------------
# Previous findings comparison
# ---------------------------------------------------------------------------


def load_previous_audit(
    db: StateDB, *, host: str
) -> list[dict[str, str]] | None:
    """Load finding summary from the most recent audit-complete entry."""
    reader = db._reader_factory()
    try:
        row = reader.execute(
            """SELECT detail FROM audit_log
               WHERE action = 'audit-complete' AND host = ?
               ORDER BY id DESC LIMIT 1""",
            (host,),
        ).fetchone()
        if row is None or row[0] is None:
            return None
        detail = json.loads(row[0])
        return detail.get("findings")
    finally:
        reader.close()


def log_audit_complete(
    db: StateDB,
    *,
    session_id: str,
    source: str,
    host: str,
    findings_summary: list[dict[str, str]],
) -> int:
    """Log an audit-complete entry with finding keys and severities."""
    return log_audit(
        db,
        session_id=session_id,
        source=source,
        action="audit-complete",
        target="audit",
        host=host,
        pre_state_hash="",
        post_state_hash=None,
        result="success",
        detail={"findings": findings_summary},
    )
