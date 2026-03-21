"""Break-glass lockdown — file-based kill switch for mutations.

If /etc/roustabout/lockdown exists, all mutations are denied.
Zero internal dependencies — must work even if every other module is broken.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

LOCKDOWN_PATH = Path("/etc/roustabout/lockdown")


@dataclass(frozen=True)
class LockdownStatus:
    locked: bool
    reason: str | None
    path: str


class LockdownError(Exception):
    """Mutations are blocked by lockdown."""

    def __init__(self, status: LockdownStatus) -> None:
        self.status = status
        super().__init__(f"Lockdown active: {status.reason or 'no reason given'}")


def check(path: Path = LOCKDOWN_PATH) -> None:
    """Check for lockdown. Raises LockdownError if lockdown file exists.

    Fast path: os.stat() for existence check.
    Fail-closed on PermissionError, fail-open on missing parent directory.
    """
    try:
        os.stat(path)
    except FileNotFoundError:
        return
    except PermissionError:
        raise LockdownError(
            LockdownStatus(
                locked=True,
                reason=f"lockdown check failed: permission denied on {path}",
                path=str(path),
            )
        )
    except OSError as exc:
        # ENOENT on parent directory = lockdown not configured, safe to skip.
        # Any other I/O error = fail closed — can't verify, assume locked.
        if getattr(exc, "errno", None) == 2:  # errno.ENOENT
            return
        raise LockdownError(
            LockdownStatus(
                locked=True,
                reason=f"lockdown check failed: {exc}",
                path=str(path),
            )
        )

    # File exists — lockdown active. Try to read reason.
    reason = None
    try:
        reason = path.read_text(encoding="utf-8")[:1024].strip() or None
    except (OSError, UnicodeDecodeError):
        pass

    raise LockdownError(LockdownStatus(locked=True, reason=reason, path=str(path)))
