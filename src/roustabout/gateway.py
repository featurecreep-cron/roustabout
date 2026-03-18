"""Operator gateway — single mutation entry point.

Every mutation from every interface (CLI, MCP, future API) routes through
gateway.execute(). The gateway enforces the gate sequence, logs to the
audit trail, and dispatches notifications.

Gate sequence:
0. Pre-gate inspect
1. Lockdown check
2. Permission check
3. Rate limit reserve
4. Circuit breaker check
5. Blast radius check
6. Pre-hash from step 0 (TargetNotFound if None)
7. TOCTOU verify (fresh read vs pre-hash)
8. Execute mutation
9. Audit log + notification
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

import docker.errors

from roustabout import lockdown, permissions
from roustabout.session import Session, get_current_session
from roustabout.state_db import StateDB

logger = logging.getLogger(__name__)

# Actions that are valid for the mutation gateway.
_MUTATION_ACTIONS = frozenset(
    action
    for action, cap in permissions.ACTION_CAPABILITY.items()
    if permissions.CAPABILITY_TIER[cap] >= permissions.PermissionTier.OPERATE
)

# Command and result types

@dataclass(frozen=True)
class MutationCommand:
    """What to do."""

    action: str
    target: str
    host: str = "localhost"
    new_image: str | None = None
    new_env: tuple[tuple[str, str], ...] | None = None
    new_labels: tuple[tuple[str, str], ...] | None = None
    dry_run: bool = False


@dataclass(frozen=True)
class GatewayResult:
    """What happened."""

    success: bool
    action: str
    target: str
    pre_state_hash: str
    post_state_hash: str | None
    result: str  # success, failed, rolled-back, denied, dry-run
    error: str | None = None
    gate_failed: str | None = None
    audit_id: int | None = None


# Gate exceptions

@dataclass
class CircuitOpen(Exception):
    """Circuit breaker open — too many consecutive failures."""

    target: str
    consecutive_failures: int

    def __post_init__(self) -> None:
        super().__init__(
            f"Circuit open for {self.target}: "
            f"{self.consecutive_failures} consecutive failures"
        )


@dataclass
class BlastRadiusExceeded(Exception):
    """Operation affects too many containers."""

    affected_count: int
    threshold: int

    def __post_init__(self) -> None:
        super().__init__(
            f"Blast radius {self.affected_count} exceeds threshold {self.threshold}"
        )


@dataclass
class TargetNotFound(Exception):
    """Target container does not exist."""

    target: str

    def __post_init__(self) -> None:
        super().__init__(f"Container {self.target!r} not found")


@dataclass
class ConcurrentMutation(Exception):
    """Target state changed between pre-gate inspect and execution."""

    target: str
    expected_hash: str
    actual_hash: str

    def __post_init__(self) -> None:
        super().__init__(
            f"TOCTOU: {self.target} changed "
            f"(expected {self.expected_hash[:12]}, got {self.actual_hash[:12]})"
        )


# Module-level state
_default_db: StateDB | None = None


def set_default_db(db: StateDB) -> None:
    """Set the module-level default database for gateway operations."""
    global _default_db
    _default_db = db


# Gate helpers

def _inspect_target(session: Session, target: str) -> Any:
    """Lightweight single-container inspect for pre-gate label reading.

    Returns ContainerInfo or None if container doesn't exist.
    Raises on Docker API errors other than "not found".
    """
    from roustabout.collector import container_to_info

    try:
        container = session.docker.client.containers.get(target)
        return container_to_info(container)
    except docker.errors.NotFound:
        return None


def _compute_target_hash(session: Session, target: str) -> str | None:
    """Compute a hash of the target container's current state.

    Returns None if container doesn't exist.
    Raises on Docker API errors other than "not found".
    """
    try:
        container = session.docker.client.containers.get(target)
    except docker.errors.NotFound:
        return None
    container.reload()
    attrs = container.attrs
    config = attrs["Config"]
    host_config = attrs["HostConfig"]
    state_data = json.dumps(
        {
            "status": attrs["State"]["Status"],
            "image": attrs["Image"],
            "env": sorted(config.get("Env", [])),
            "cmd": config.get("Cmd"),
            "entrypoint": config.get("Entrypoint"),
            "user": config.get("User", ""),
            "labels": sorted(config.get("Labels", {}).items()),
            "network_mode": host_config.get("NetworkMode", ""),
            "privileged": host_config.get("Privileged", False),
            "cap_add": sorted(host_config.get("CapAdd") or []),
            "cap_drop": sorted(host_config.get("CapDrop") or []),
            "pid_mode": host_config.get("PidMode", ""),
            "ipc_mode": host_config.get("IpcMode", ""),
            "security_opt": sorted(
                host_config.get("SecurityOpt") or []
            ),
            "read_only": host_config.get("ReadonlyRootfs", False),
            "devices": sorted(
                json.dumps(d, sort_keys=True)
                for d in (host_config.get("Devices") or [])
            ),
            "binds": sorted(host_config.get("Binds") or []),
            "port_bindings": json.dumps(
                host_config.get("PortBindings") or {},
                sort_keys=True,
            ),
        },
        sort_keys=True,
    )
    return hashlib.sha256(state_data.encode("utf-8")).hexdigest()



def _check_blast_radius(command: MutationCommand, session: Session) -> None:
    """Check if operation affects too many containers.

    Phase 1: all operations are single-container. No-op.
    """


# Public API

def execute(
    command: MutationCommand,
    *,
    session: Session | None = None,
    db: StateDB | None = None,
) -> GatewayResult:
    """Execute a mutation through the full gate sequence."""
    from roustabout import state_db as sdb

    s = session or get_current_session()
    database = db or _default_db

    reservation = None

    try:
        # Validate action is a mutation
        if command.action not in _MUTATION_ACTIONS:
            raise ValueError(
                f"Gateway only handles mutations, "
                f"got read action {command.action!r}"
            )

        # Step 0: Pre-gate inspect (lightweight, for permission labels)
        target_info = _inspect_target(s, command.target)

        # Step 0b: Pre-gate hash (from Docker attrs, for TOCTOU)
        pre_hash = _compute_target_hash(s, command.target)

        # Step 1: Lockdown
        lockdown.check()

        # Step 2: Permission check
        permissions.check(s, command.action, target_info)

        # Step 3: Rate limit reserve
        reservation = s.rate_limiter.reserve(command.target)

        # Step 4: Circuit breaker
        if database is not None:
            circuit = sdb.check_circuit(
                database, target=command.target, host=command.host
            )
            if circuit.open:
                raise CircuitOpen(
                    target=command.target,
                    consecutive_failures=circuit.consecutive_failures,
                )

        # Step 5: Blast radius
        _check_blast_radius(command, s)

        # Step 6: Target existence (pre_hash is None if not found)
        if pre_hash is None:
            raise TargetNotFound(target=command.target)

        # Step 7: TOCTOU verify — fresh hash must match pre-gate hash
        verify_hash = _compute_target_hash(s, command.target)
        if verify_hash is None:
            raise TargetNotFound(target=command.target)
        if verify_hash != pre_hash:
            raise ConcurrentMutation(
                target=command.target,
                expected_hash=pre_hash,
                actual_hash=verify_hash,
            )

        # Step 8: Dry-run check
        if command.dry_run:
            return GatewayResult(
                success=True,
                action=command.action,
                target=command.target,
                pre_state_hash=verify_hash,
                post_state_hash=None,
                result="dry-run",
            )

        # Step 9: Execute mutation
        from roustabout import mutations

        mutation_result = mutations.execute(
            s.docker, command.action, command.target,
            new_image=command.new_image,
        )

        # Commit rate limiter token
        s.rate_limiter.commit(reservation)
        reservation = None

        # Post-mutation hash
        post_hash = _compute_target_hash(s, command.target)

        result_str = "success" if mutation_result.success else "failed"

        # Step 10: Notification (fire-and-forget)
        from roustabout import notifications

        notifications.send_mutation_event(
            action=command.action,
            target=command.target,
            success=mutation_result.success,
            session_id=s.id,
        )

        # Audit log
        audit_id = None
        if database is not None:
            audit_id = sdb.log_audit(
                database,
                session_id=s.id,
                source="gateway",
                action=command.action,
                target=command.target,
                host=command.host,
                pre_state_hash=verify_hash,
                post_state_hash=post_hash,
                result=result_str,
                detail={"action": command.action},
            )

        return GatewayResult(
            success=mutation_result.success,
            action=command.action,
            target=command.target,
            pre_state_hash=verify_hash,
            post_state_hash=post_hash,
            result=result_str,
            error=mutation_result.error,
            audit_id=audit_id,
        )

    except (
        lockdown.LockdownError,
        permissions.PermissionDenied,
        CircuitOpen,
        BlastRadiusExceeded,
        TargetNotFound,
        ConcurrentMutation,
    ) as e:
        # Gate rejection
        return GatewayResult(
            success=False,
            action=command.action,
            target=command.target,
            pre_state_hash="",
            post_state_hash=None,
            result="denied",
            error=str(e),
            gate_failed=type(e).__name__,
        )

    finally:
        if reservation is not None:
            s.rate_limiter.release(reservation)
