"""Tests for file_ops — file read/write with path traversal protection.

Covers LLD-038: file_ops.py — path validation, read, write, staging.
Uses tmp_path for filesystem tests — no real host paths.
"""

from __future__ import annotations

import json
import time

import pytest

from roustabout.permissions import FrictionMechanism

# --- Configuration ---


class TestFileOpsConfig:
    def test_defaults(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig

        config = FileOpsConfig(
            root=tmp_path / "apps",
            read_root=tmp_path / "apps",
            staging_root=tmp_path / "staging",
        )
        assert config.ttl_hours == 48
        assert config.max_total_size == 100_000_000


# --- Path traversal ---


class TestPathValidation:
    def test_path_within_root(self, tmp_path):
        from roustabout.file_ops import _validate_path

        root = tmp_path / "apps"
        root.mkdir()
        result = _validate_path("compose.yml", root)
        assert result == root / "compose.yml"

    def test_path_traversal_rejected(self, tmp_path):
        from roustabout.file_ops import _validate_path

        root = tmp_path / "apps"
        root.mkdir()
        with pytest.raises(ValueError, match="outside root"):
            _validate_path("../../../etc/shadow", root)

    def test_absolute_path_outside_root(self, tmp_path):
        from roustabout.file_ops import _validate_path

        root = tmp_path / "apps"
        root.mkdir()
        with pytest.raises(ValueError, match="outside root"):
            _validate_path("/etc/passwd", root)

    def test_symlink_outside_root(self, tmp_path):
        from roustabout.file_ops import _validate_path

        root = tmp_path / "apps"
        root.mkdir()
        link = root / "sneaky"
        link.symlink_to("/etc/passwd")
        with pytest.raises(ValueError, match="outside root"):
            _validate_path("sneaky", root)

    def test_blocked_filename_env(self, tmp_path):
        from roustabout.file_ops import _validate_path

        root = tmp_path / "apps"
        root.mkdir()
        with pytest.raises(ValueError, match="blocked"):
            _validate_path(".env", root)

    def test_blocked_filename_docker_sock(self, tmp_path):
        from roustabout.file_ops import _validate_path

        root = tmp_path / "apps"
        root.mkdir()
        with pytest.raises(ValueError, match="blocked"):
            _validate_path("docker.sock", root)

    def test_nested_path_valid(self, tmp_path):
        from roustabout.file_ops import _validate_path

        root = tmp_path / "apps"
        root.mkdir()
        result = _validate_path("stacks/media/compose.yml", root)
        assert result == (root / "stacks/media/compose.yml").resolve()


# --- File read ---


class TestReadFile:
    def test_read_success(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, read_file

        root = tmp_path / "apps"
        root.mkdir()
        (root / "test.yml").write_text("version: '3'\n")
        config = FileOpsConfig(
            root=root, read_root=root,
            staging_root=tmp_path / "staging",
        )

        result = read_file("test.yml", config=config)
        assert result.success is True
        assert "version" in result.content

    def test_read_nonexistent(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, read_file

        root = tmp_path / "apps"
        root.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root,
            staging_root=tmp_path / "staging",
        )

        result = read_file("missing.yml", config=config)
        assert result.success is False
        assert "not found" in (result.error or "").lower()

    def test_read_outside_root(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, read_file

        root = tmp_path / "apps"
        root.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root,
            staging_root=tmp_path / "staging",
        )

        result = read_file("../../etc/passwd", config=config)
        assert result.success is False
        assert "outside root" in (result.error or "")

    def test_read_truncation(self, tmp_path):
        from roustabout.file_ops import (
            MAX_READ_BYTES,
            FileOpsConfig,
            read_file,
        )

        root = tmp_path / "apps"
        root.mkdir()
        (root / "big.txt").write_text("x" * (MAX_READ_BYTES + 1000))
        config = FileOpsConfig(
            root=root, read_root=root,
            staging_root=tmp_path / "staging",
        )

        result = read_file("big.txt", config=config)
        assert result.success is True
        assert result.truncated is True

    def test_read_content_sanitized(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, read_file

        root = tmp_path / "apps"
        root.mkdir()
        # ANSI escapes should be stripped by sanitize()
        (root / "config.txt").write_text(
            "line1\x1b[31mred\x1b[0m\n"
        )
        config = FileOpsConfig(
            root=root, read_root=root,
            staging_root=tmp_path / "staging",
        )

        result = read_file("config.txt", config=config)
        assert result.success is True
        assert "\x1b" not in result.content


# --- File write (staged) ---


class TestWriteStaged:
    def test_staged_creates_artifact(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, write_file

        root = tmp_path / "apps"
        root.mkdir()
        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root, staging_root=staging,
        )

        result = write_file(
            "compose.yml", "version: '3'\n",
            config=config,
            friction=FrictionMechanism.STAGE,
            session_id="test",
        )

        assert result.success is True
        assert result.staged is True
        assert result.staging_path is not None
        assert result.apply_command is not None

    def test_staged_generates_diff(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, write_file

        root = tmp_path / "apps"
        root.mkdir()
        (root / "compose.yml").write_text("version: '2'\n")
        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root, staging_root=staging,
        )

        result = write_file(
            "compose.yml", "version: '3'\n",
            config=config,
            friction=FrictionMechanism.STAGE,
            session_id="test",
        )

        assert result.diff is not None
        assert "-version: '2'" in result.diff
        assert "+version: '3'" in result.diff

    def test_staged_writes_metadata(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, write_file

        root = tmp_path / "apps"
        root.mkdir()
        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root, staging_root=staging,
        )

        write_file(
            "app.yml", "content\n",
            config=config,
            friction=FrictionMechanism.STAGE,
            session_id="sess-1",
        )

        # Find metadata
        dirs = [d for d in staging.iterdir() if d.is_dir()]
        assert len(dirs) == 1
        metadata = json.loads((dirs[0] / "metadata.json").read_text())
        assert metadata["session_id"] == "sess-1"
        assert "expires_at" in metadata


# --- File write (direct) ---


class TestWriteDirect:
    def test_direct_writes_file(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, write_file

        root = tmp_path / "apps"
        root.mkdir()
        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root, staging_root=staging,
        )

        result = write_file(
            "compose.yml", "version: '3'\n",
            config=config,
            friction=FrictionMechanism.DIRECT,
            session_id="test",
        )

        assert result.success is True
        assert result.staged is False
        assert (root / "compose.yml").read_text() == "version: '3'\n"

    def test_direct_creates_backup(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, write_file

        root = tmp_path / "apps"
        root.mkdir()
        (root / "compose.yml").write_text("old content\n")
        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root, staging_root=staging,
        )

        result = write_file(
            "compose.yml", "new content\n",
            config=config,
            friction=FrictionMechanism.DIRECT,
            session_id="test",
        )

        assert result.backup_path is not None
        assert "old content" in open(result.backup_path).read()

    def test_direct_generates_diff(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, write_file

        root = tmp_path / "apps"
        root.mkdir()
        (root / "app.yml").write_text("old\n")
        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root, staging_root=staging,
        )

        result = write_file(
            "app.yml", "new\n",
            config=config,
            friction=FrictionMechanism.DIRECT,
            session_id="test",
        )

        assert result.diff is not None
        assert "-old" in result.diff
        assert "+new" in result.diff

    def test_direct_creates_parent_dirs(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, write_file

        root = tmp_path / "apps"
        root.mkdir()
        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root, staging_root=staging,
        )

        result = write_file(
            "stacks/media/compose.yml", "content\n",
            config=config,
            friction=FrictionMechanism.DIRECT,
            session_id="test",
        )

        assert result.success is True
        assert (root / "stacks/media/compose.yml").exists()

    def test_write_path_traversal_rejected(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, write_file

        root = tmp_path / "apps"
        root.mkdir()
        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root, staging_root=staging,
        )

        result = write_file(
            "../../etc/crontab", "bad\n",
            config=config,
            friction=FrictionMechanism.DIRECT,
            session_id="test",
        )

        assert result.success is False
        assert "outside root" in (result.error or "")


# --- Staging management ---


class TestListStaged:
    def test_list_empty(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, list_staged

        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=tmp_path, read_root=tmp_path, staging_root=staging,
        )

        result = list_staged(config=config)
        assert result == []

    def test_list_after_stage(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, list_staged, write_file

        root = tmp_path / "apps"
        root.mkdir()
        staging = tmp_path / "staging"
        staging.mkdir()
        config = FileOpsConfig(
            root=root, read_root=root, staging_root=staging,
        )

        write_file(
            "app.yml", "content\n",
            config=config,
            friction=FrictionMechanism.STAGE,
            session_id="test",
        )

        artifacts = list_staged(config=config)
        assert len(artifacts) == 1
        assert artifacts[0].session_id == "test"


class TestCleanExpired:
    def test_clean_removes_expired(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, clean_expired

        staging = tmp_path / "staging"
        staging.mkdir()

        # Create an expired artifact manually
        op_dir = staging / "expired-op"
        op_dir.mkdir()
        (op_dir / "artifact").write_text("old\n")
        (op_dir / "metadata.json").write_text(json.dumps({
            "operation_id": "expired-op",
            "target_path": "/apps/test.yml",
            "session_id": "old",
            "created_at": time.time() - 200000,
            "expires_at": time.time() - 100000,
        }))

        config = FileOpsConfig(
            root=tmp_path, read_root=tmp_path, staging_root=staging,
        )

        removed = clean_expired(config=config)
        assert removed == 1
        assert not op_dir.exists()

    def test_clean_keeps_fresh(self, tmp_path):
        from roustabout.file_ops import FileOpsConfig, clean_expired

        staging = tmp_path / "staging"
        staging.mkdir()

        # Create a fresh artifact
        op_dir = staging / "fresh-op"
        op_dir.mkdir()
        (op_dir / "artifact").write_text("new\n")
        (op_dir / "metadata.json").write_text(json.dumps({
            "operation_id": "fresh-op",
            "target_path": "/apps/test.yml",
            "session_id": "new",
            "created_at": time.time(),
            "expires_at": time.time() + 100000,
        }))

        config = FileOpsConfig(
            root=tmp_path, read_root=tmp_path, staging_root=staging,
        )

        removed = clean_expired(config=config)
        assert removed == 0
        assert op_dir.exists()
