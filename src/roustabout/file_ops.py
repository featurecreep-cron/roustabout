"""File operations — read and write files on the Docker host.

Provides file access within configured path boundaries. Path traversal
protection, secret redaction on read, staging area for OPERATE tier writes.
"""

from __future__ import annotations

import difflib
import json
import os
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from roustabout.permissions import FrictionMechanism
from roustabout.redactor import sanitize

# Size limits
MAX_READ_BYTES = 1_048_576  # 1 MiB per file read
MAX_STAGING_TOTAL = 100_000_000  # 100 MB total staging area
DEFAULT_STAGING_TTL_HOURS = 48

# Filenames blocked even if under root (defense-in-depth)
_BLOCKED_NAMES = frozenset({".env", "docker.sock", ".ssh", ".gnupg"})


@dataclass(frozen=True)
class FileOpsConfig:
    """Configuration for file operations."""

    root: Path
    read_root: Path
    staging_root: Path
    ttl_hours: int = DEFAULT_STAGING_TTL_HOURS
    max_total_size: int = MAX_STAGING_TOTAL


@dataclass(frozen=True)
class FileReadResult:
    """Result of reading a file."""

    success: bool
    path: str
    content: str | None
    size: int
    truncated: bool
    error: str | None = None


@dataclass(frozen=True)
class FileWriteResult:
    """Result of writing a file."""

    success: bool
    path: str
    staged: bool
    staging_path: str | None
    backup_path: str | None
    diff: str | None
    apply_command: str | None
    error: str | None = None


@dataclass(frozen=True)
class StagedArtifact:
    """A file waiting in the staging area for operator approval."""

    id: str
    target_path: str
    staging_path: str
    diff: str | None
    created_at: float
    expires_at: float
    session_id: str
    applied: bool = False


# Path validation


def _validate_path(path: str, root: Path) -> Path:
    """Resolve path and validate it's within root.

    Raises ValueError if path resolves outside root or matches
    blocked patterns.
    """
    resolved = (root / path).resolve()

    if not resolved.is_relative_to(root.resolve()):
        raise ValueError(f"Path {path!r} resolves outside root")

    for part in resolved.parts:
        if part in _BLOCKED_NAMES:
            raise ValueError(f"Path {path!r} matches blocked pattern")

    return resolved


# Public API


def read_file(
    path: str,
    *,
    config: FileOpsConfig,
) -> FileReadResult:
    """Read a file within the configured read root.

    Content is redacted for secrets before returning.
    Large files are truncated.
    """
    try:
        resolved = _validate_path(path, config.read_root)
    except ValueError as e:
        return FileReadResult(
            success=False,
            path=path,
            content=None,
            size=0,
            truncated=False,
            error=str(e),
        )

    if not resolved.exists():
        return FileReadResult(
            success=False,
            path=str(resolved),
            content=None,
            size=0,
            truncated=False,
            error="File not found",
        )

    size = resolved.stat().st_size
    truncated = size > MAX_READ_BYTES

    raw = resolved.read_bytes()[:MAX_READ_BYTES]
    text = raw.decode("utf-8", errors="replace")
    content = sanitize(text)

    return FileReadResult(
        success=True,
        path=str(resolved),
        content=content,
        size=size,
        truncated=truncated,
    )


def write_file(
    path: str,
    content: str,
    *,
    config: FileOpsConfig,
    friction: FrictionMechanism,
    session_id: str,
) -> FileWriteResult:
    """Write a file with friction-appropriate handling.

    STAGE: writes to staging area, returns apply command.
    DIRECT: writes to operational path with backup.
    """
    if friction == FrictionMechanism.STAGE:
        return _write_staged(
            path,
            content,
            config=config,
            session_id=session_id,
        )
    elif friction == FrictionMechanism.DIRECT:
        return _write_direct(path, content, config=config)
    else:
        raise ValueError(f"Unexpected friction for file write: {friction}")


def list_staged(*, config: FileOpsConfig) -> list[StagedArtifact]:
    """List pending staged artifacts, sorted by creation time."""
    artifacts: list[StagedArtifact] = []
    if not config.staging_root.exists():
        return artifacts

    for entry in config.staging_root.iterdir():
        if not entry.is_dir() or entry.name == "backups":
            continue
        metadata_path = entry / "metadata.json"
        if not metadata_path.exists():
            continue
        metadata = json.loads(metadata_path.read_text())
        diff = _read_diff(entry)
        artifacts.append(
            StagedArtifact(
                id=metadata["operation_id"],
                target_path=metadata["target_path"],
                staging_path=str(entry / "artifact"),
                diff=diff,
                created_at=metadata["created_at"],
                expires_at=metadata["expires_at"],
                session_id=metadata["session_id"],
            )
        )

    return sorted(artifacts, key=lambda a: a.created_at)


def clean_expired(*, config: FileOpsConfig) -> int:
    """Remove expired staged artifacts. Returns count removed."""
    if not config.staging_root.exists():
        return 0

    now = time.time()
    removed = 0
    for entry in config.staging_root.iterdir():
        if not entry.is_dir() or entry.name == "backups":
            continue
        metadata_path = entry / "metadata.json"
        if not metadata_path.exists():
            shutil.rmtree(entry)
            removed += 1
            continue
        metadata = json.loads(metadata_path.read_text())
        if metadata.get("expires_at", 0) < now:
            shutil.rmtree(entry)
            removed += 1
    return removed


# Internal helpers


def _read_diff(staging_dir: Path) -> str | None:
    """Read diff from a staging directory, if present."""
    diff_path = staging_dir / "diff.patch"
    if diff_path.exists():
        return diff_path.read_text()
    return None


def _generate_diff(
    existing_path: Path,
    new_content: str,
    to_label: str,
) -> str | None:
    """Generate unified diff between existing file and new content."""
    if not existing_path.exists():
        return None
    existing = existing_path.read_text(encoding="utf-8", errors="replace")
    diff_lines = difflib.unified_diff(
        existing.splitlines(keepends=True),
        new_content.splitlines(keepends=True),
        fromfile=str(existing_path),
        tofile=to_label,
    )
    return "".join(diff_lines) or None


def _write_staged(
    path: str,
    content: str,
    *,
    config: FileOpsConfig,
    session_id: str,
) -> FileWriteResult:
    """Write to staging area with metadata."""
    try:
        target = _validate_path(path, config.root)
    except ValueError as e:
        return FileWriteResult(
            success=False,
            path=path,
            staged=True,
            staging_path=None,
            backup_path=None,
            diff=None,
            apply_command=None,
            error=str(e),
        )

    op_id = str(uuid.uuid4())
    staging_dir = config.staging_root / op_id
    staging_dir.mkdir(parents=True)

    artifact_path = staging_dir / "artifact"
    artifact_path.write_text(content, encoding="utf-8")

    diff = _generate_diff(target, content, f"staged:{op_id}")

    metadata = {
        "operation_id": op_id,
        "target_path": str(target),
        "session_id": session_id,
        "created_at": time.time(),
        "expires_at": time.time() + config.ttl_hours * 3600,
    }
    (staging_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    if diff:
        (staging_dir / "diff.patch").write_text(diff, encoding="utf-8")

    import shlex

    apply_cmd = f"cp {shlex.quote(str(artifact_path))} {shlex.quote(str(target))}"

    return FileWriteResult(
        success=True,
        path=str(target),
        staged=True,
        staging_path=str(artifact_path),
        backup_path=None,
        diff=diff,
        apply_command=apply_cmd,
    )


def _write_direct(
    path: str,
    content: str,
    *,
    config: FileOpsConfig,
) -> FileWriteResult:
    """Write directly to operational path (ELEVATE tier)."""
    try:
        target = _validate_path(path, config.root)
    except ValueError as e:
        return FileWriteResult(
            success=False,
            path=path,
            staged=False,
            staging_path=None,
            backup_path=None,
            diff=None,
            apply_command=None,
            error=str(e),
        )

    # Backup existing file
    backup_path = None
    if target.exists():
        backup_dir = config.staging_root / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        backup_name = f"{target.name}.{timestamp}"
        backup_path_obj = backup_dir / backup_name
        shutil.copy2(target, backup_path_obj)
        backup_path = str(backup_path_obj)

    diff = _generate_diff(target, content, f"{target} (new)")

    # Atomic write: temp file + rename
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.rename(tmp_path, target)
    except Exception:  # noqa: BLE001 — cleanup temp file on any write failure
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    return FileWriteResult(
        success=True,
        path=str(target),
        staged=False,
        staging_path=None,
        backup_path=backup_path,
        diff=diff,
        apply_command=None,
    )
