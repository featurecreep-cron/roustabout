"""Tests for lockdown — break-glass kill switch for mutations.

Covers S2.3.1: File-based kill switch.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from roustabout import lockdown


class TestLockdownCheck:
    """Lockdown file presence controls mutation access."""

    def test_no_file_returns_normally(self, tmp_path: Path) -> None:
        lockdown.check(tmp_path / "lockdown")

    def test_file_present_raises(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "lockdown"
        lock_file.touch()
        with pytest.raises(lockdown.LockdownError) as exc_info:
            lockdown.check(lock_file)
        assert exc_info.value.status.locked is True

    def test_file_with_reason(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "lockdown"
        lock_file.write_text("Emergency: database corruption")
        with pytest.raises(lockdown.LockdownError) as exc_info:
            lockdown.check(lock_file)
        assert exc_info.value.status.reason == "Emergency: database corruption"

    def test_empty_file_reason_is_none(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "lockdown"
        lock_file.touch()
        with pytest.raises(lockdown.LockdownError) as exc_info:
            lockdown.check(lock_file)
        assert exc_info.value.status.reason is None

    def test_long_reason_truncated(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "lockdown"
        lock_file.write_text("x" * 2000)
        with pytest.raises(lockdown.LockdownError) as exc_info:
            lockdown.check(lock_file)
        assert len(exc_info.value.status.reason) == 1024

    def test_parent_directory_missing_returns_normally(self, tmp_path: Path) -> None:
        lockdown.check(tmp_path / "nonexistent" / "dir" / "lockdown")

    def test_permission_error_fails_closed(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "lockdown"
        with patch("os.stat", side_effect=PermissionError("denied")):
            with pytest.raises(lockdown.LockdownError) as exc_info:
                lockdown.check(lock_file)
            assert exc_info.value.status.locked is True
            assert "permission denied" in exc_info.value.status.reason

    def test_unreadable_file_still_locks(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "lockdown"
        lock_file.touch()
        lock_file.chmod(0o000)
        try:
            with pytest.raises(lockdown.LockdownError) as exc_info:
                lockdown.check(lock_file)
            assert exc_info.value.status.locked is True
            # Can't read reason, but lockdown is enforced
            assert exc_info.value.status.reason is None
        finally:
            lock_file.chmod(0o644)

    def test_path_in_status(self, tmp_path: Path) -> None:
        lock_file = tmp_path / "lockdown"
        lock_file.touch()
        with pytest.raises(lockdown.LockdownError) as exc_info:
            lockdown.check(lock_file)
        assert str(lock_file) in exc_info.value.status.path

    def test_io_error_fails_closed(self, tmp_path: Path) -> None:
        """Non-ENOENT OSError should fail closed (deny mutations)."""
        lock_file = tmp_path / "lockdown"
        # EIO (errno 5) — disk I/O error on a configured lockdown path
        io_error = OSError(5, "Input/output error")
        with patch("os.stat", side_effect=io_error):
            with pytest.raises(lockdown.LockdownError) as exc_info:
                lockdown.check(lock_file)
            assert exc_info.value.status.locked is True

    def test_zero_internal_imports(self) -> None:
        """lockdown.py must import nothing from roustabout."""
        import ast

        src = Path(__file__).parent.parent / "src" / "roustabout" / "lockdown.py"
        tree = ast.parse(src.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(
                "roustabout"
            ):
                pytest.fail(f"lockdown.py imports from roustabout: {node.module}")
