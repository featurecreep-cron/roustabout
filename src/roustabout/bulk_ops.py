"""Bulk container operations — compose project and label selector support.

Each container operation routes through the gateway individually.
Blast radius cap prevents accidentally affecting too many containers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from roustabout.session import Session

logger = logging.getLogger(__name__)

DEFAULT_BLAST_RADIUS_CAP = 5


# Result type


@dataclass(frozen=True)
class BulkResult:
    """Outcome of a bulk operation."""

    success: bool
    action: str
    per_container: tuple[dict[str, Any], ...] = ()
    error: str | None = None


# Selectors


def select_by_project(containers: list[Any], project: str) -> list[Any]:
    """Select containers belonging to a compose project."""
    return [c for c in containers if c.labels.get("com.docker.compose.project") == project]


def select_by_label(containers: list[Any], selector: str) -> list[Any]:
    """Select containers matching a label selector.

    Formats:
    - "key=value" — match exact key/value
    - "key" — match any container with the key present
    """
    if "=" in selector:
        key, _, value = selector.partition("=")
        return [c for c in containers if c.labels.get(key) == value]
    return [c for c in containers if selector in c.labels]


# Bulk execution


def bulk_manage(
    *,
    action: str,
    targets: list[str],
    session: Session,
    blast_radius_cap: int = DEFAULT_BLAST_RADIUS_CAP,
    dry_run: bool = False,
    db: Any = None,
) -> BulkResult:
    """Execute an action on multiple containers through the gateway.

    Each container is processed individually through the full gate sequence.
    """
    if len(targets) > blast_radius_cap:
        return BulkResult(
            success=False,
            action=action,
            error=(
                f"Blast radius cap exceeded: {len(targets)} containers "
                f"exceeds limit of {blast_radius_cap}. "
                f"Narrow the target set or increase blast_radius_cap."
            ),
        )

    if dry_run:
        return BulkResult(
            success=True,
            action=action,
            per_container=tuple(
                {"target": t, "success": True, "result": "dry-run"} for t in targets
            ),
        )

    results = []
    all_success = True
    for target in targets:
        result = _execute_single(action, target, session, db)
        results.append(result)
        if not result.get("success"):
            all_success = False

    return BulkResult(
        success=all_success,
        action=action,
        per_container=tuple(results),
    )


def _execute_single(
    action: str,
    target: str,
    session: Session,
    db: Any,
) -> dict[str, Any]:
    """Execute a single container mutation through the gateway."""
    from roustabout.gateway import MutationCommand
    from roustabout.gateway import execute as gw_execute

    cmd = MutationCommand(action=action, target=target)
    result = gw_execute(cmd, session=session, db=db)

    return {
        "target": target,
        "success": result.success,
        "result": result.result,
        "error": result.error,
        "gate_failed": result.gate_failed,
    }
