"""Operator gateway — single mutation entry point.

Every mutation from every interface (CLI, MCP, future API) routes through
gateway.execute(). The gateway enforces the gate sequence, logs to the
audit trail, dispatches notifications, and implements the friction model's
confirmation and directed-command gates.

Gate sequence:
0. Pre-gate inspect
1. Lockdown check
2. Permission check → friction routing
   - DIRECTED: return suggested command, no mutation
   - STAGE: delegate to staging handler, no mutation
3. Rate limit reserve
4. Circuit breaker check
5. Blast radius check
6. Confirmation gate (CONFIRM friction only)
7. TOCTOU verify (fresh read vs pre-hash)
7b. Pre-mutation backup (stub)
8. Execute mutation
9. Audit log + notification
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

import docker.errors

from roustabout import lockdown, permissions
from roustabout.permissions import FrictionMechanism
from roustabout.session import RateLimitExceeded, Session, get_current_session
from roustabout.state_db import StateDB

logger = logging.getLogger(__name__)

# Actions that are valid for the mutation gateway.
_MUTATION_ACTIONS = frozenset(
    action
    for action, cap in permissions.ACTION_CAPABILITY.items()
    if cap not in permissions._READ_CAPABILITIES
)

# Command and result types

DEFAULT_CONFIRMATION_TIMEOUT = 300  # 5 minutes


@dataclass(frozen=True)
class MutationCommand:
    """What to do."""

    action: str
    target: str
    host: str = "localhost"
    new_image: str | None = None
    new_env: tuple[tuple[str, str], ...] | None = None
    new_labels: tuple[tuple[str, str], ...] | None = None
    exec_command: tuple[str, ...] | None = None
    compose_path: str | None = None
    dry_run: bool = False


@dataclass(frozen=True)
class GatewayResult:
    """What happened."""

    success: bool
    action: str
    target: str
    pre_state_hash: str
    post_state_hash: str | None
    # success, failed, rolled-back, denied, dry-run, directed,
    # pending-confirmation, staged
    result: str
    error: str | None = None
    gate_failed: str | None = None
    audit_id: int | None = None
    friction: str | None = None
    suggested_command: str | None = None
    confirmation_id: str | None = None


@dataclass(frozen=True)
class ConfirmationRequest:
    """Pending confirmation for an OPERATE-tier operation."""

    id: str
    command: MutationCommand
    session_id: str
    semantic_diff: str | None
    audit_findings: list[str] | None
    created_at: float
    expires_at: float
    pre_state_hash: str


# Gate exceptions


@dataclass
class CircuitOpen(Exception):
    """Circuit breaker open — too many consecutive failures."""

    target: str
    consecutive_failures: int

    def __post_init__(self) -> None:
        super().__init__(
            f"Circuit open for {self.target}: {self.consecutive_failures} consecutive failures"
        )


@dataclass
class BlastRadiusExceeded(Exception):
    """Operation affects too many containers."""

    affected_count: int
    threshold: int

    def __post_init__(self) -> None:
        super().__init__(f"Blast radius {self.affected_count} exceeds threshold {self.threshold}")


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
        container = session.docker.client.containers.get(target)  # type: ignore[attr-defined]
        return container_to_info(container)
    except docker.errors.NotFound:
        return None


def _compute_target_hash(session: Session, target: str) -> str | None:
    """Compute a hash of the target container's current state.

    Returns None if container doesn't exist.
    Raises on Docker API errors other than "not found".
    """
    try:
        container = session.docker.client.containers.get(target)  # type: ignore[attr-defined]
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
            "security_opt": sorted(host_config.get("SecurityOpt") or []),
            "read_only": host_config.get("ReadonlyRootfs", False),
            "devices": sorted(
                json.dumps(d, sort_keys=True) for d in (host_config.get("Devices") or [])
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


def _build_suggested_command(command: MutationCommand) -> str:
    """Build the shell command an operator should run for DIRECTED friction.

    Returns a copy-pasteable command string.
    """
    if command.action in ("start", "stop", "restart"):
        return f"docker {command.action} {command.target}"
    elif command.action == "recreate":
        return f"docker compose up -d {command.target}"
    elif command.action == "exec" and command.exec_command:
        cmd_str = " ".join(command.exec_command)
        return f"docker exec {command.target} {cmd_str}"
    elif command.action == "compose-apply" and command.compose_path:
        return f"docker compose -f {command.compose_path} up -d"
    else:
        return f"# Manual action required: {command.action} on {command.target}"


def _handle_staging(
    command: MutationCommand,
    session: Session,
    db: StateDB | None,
) -> GatewayResult:
    """Handle STAGE friction — write to staging area, return apply command.

    Stub until file_ops module is implemented.
    """
    return GatewayResult(
        success=True,
        action=command.action,
        target=command.target,
        pre_state_hash="",
        post_state_hash=None,
        result="staged",
        friction="stage",
    )


def _create_confirmation(
    command: MutationCommand,
    session: Session,
    target_info: Any,
    pre_hash: str | None,
) -> ConfirmationRequest:
    """Create a pending confirmation request for OPERATE-tier operations."""
    now = time.time()
    return ConfirmationRequest(
        id=str(uuid.uuid4()),
        command=command,
        session_id=session.id,
        semantic_diff=None,
        audit_findings=None,
        created_at=now,
        expires_at=now + DEFAULT_CONFIRMATION_TIMEOUT,
        pre_state_hash=pre_hash or "",
    )


def _run_pre_mutation_backup(
    session: Session,
    target: str,
    db: StateDB | None,
) -> None:
    """Run pre-mutation backup command if configured.

    Stub until exec module is implemented. Always returns None (no backup configured).
    """
    return None


def approve_confirmation(
    confirmation_id: str,
    *,
    db: StateDB | None = None,
) -> GatewayResult:
    """Approve a pending confirmation and execute the operation.

    Stub until confirmation persistence is implemented.
    """
    raise NotImplementedError("Confirmation approval not yet implemented")


def reject_confirmation(
    confirmation_id: str,
    *,
    db: StateDB | None = None,
) -> None:
    """Reject a pending confirmation.

    Stub until confirmation persistence is implemented.
    """
    raise NotImplementedError("Confirmation rejection not yet implemented")


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
            raise ValueError(f"Gateway only handles mutations, got read action {command.action!r}")

        # Step 0: Pre-gate inspect (lightweight, for permission labels)
        target_info = _inspect_target(s, command.target)

        # Step 0b: Pre-gate hash (from Docker attrs, for TOCTOU)
        pre_hash = _compute_target_hash(s, command.target)

        # Step 1: Lockdown
        lockdown.check()

        # Step 2: Permission check → PermissionResult (friction model)
        perm_result = permissions.check(s, command.action, target_info)

        # --- Friction routing ---

        # DIRECTED: No mutation. Return the command for the operator to run.
        if perm_result.friction == FrictionMechanism.DIRECTED:
            suggested = _build_suggested_command(command)
            return GatewayResult(
                success=True,
                action=command.action,
                target=command.target,
                pre_state_hash="",
                post_state_hash=None,
                result="directed",
                friction="directed",
                suggested_command=suggested,
            )

        # STAGE: Delegate to staging handler (file_ops or compose module).
        if perm_result.friction == FrictionMechanism.STAGE:
            return _handle_staging(command, s, database)

        # --- From here: DIRECT, CONFIRM, ALLOWLIST, DENYLIST proceed through gates ---

        # Step 3: Rate limit reserve
        reservation = s.rate_limiter.reserve(command.target)

        # Step 4: Circuit breaker
        if database is not None:
            circuit = sdb.check_circuit(database, target=command.target, host=command.host)
            if circuit.open:
                raise CircuitOpen(
                    target=command.target,
                    consecutive_failures=circuit.consecutive_failures,
                )

        # Step 5: Blast radius
        _check_blast_radius(command, s)

        # Step 6: Confirmation gate (CONFIRM friction only)
        if perm_result.friction == FrictionMechanism.CONFIRM:
            confirmation = _create_confirmation(command, s, target_info, pre_hash)
            return GatewayResult(
                success=False,
                action=command.action,
                target=command.target,
                pre_state_hash=pre_hash or "",
                post_state_hash=None,
                result="pending-confirmation",
                friction="confirm",
                confirmation_id=confirmation.id,
            )

        # Step 7: Compose-apply takes a different path — no TOCTOU
        # (it operates on a compose file, not a single container)
        if command.action == "compose-apply" and command.compose_path:
            if command.dry_run:
                return GatewayResult(
                    success=True,
                    action=command.action,
                    target=command.target,
                    pre_state_hash="",
                    post_state_hash=None,
                    result="dry-run",
                    friction=perm_result.friction.value,
                )

            from pathlib import Path

            from roustabout.compose_gitops import apply_compose

            apply_result = apply_compose(Path(command.compose_path))

            s.rate_limiter.commit(reservation)
            reservation = None

            result_str = "success" if apply_result.success else "failed"

            from roustabout import notifications

            notifications.send_mutation_event(
                action=command.action,
                target=command.target,
                success=apply_result.success,
                session_id=s.id,
            )

            return GatewayResult(
                success=apply_result.success,
                action=command.action,
                target=command.target,
                pre_state_hash="",
                post_state_hash=None,
                result=result_str,
                error=apply_result.error,
                friction=perm_result.friction.value,
            )

        # Step 7: Target existence (pre_hash is None if not found)
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

        # Step 7b: Pre-mutation backup (stub — always None)
        _run_pre_mutation_backup(s, command.target, database)

        # Step 8: Dry-run check
        if command.dry_run:
            return GatewayResult(
                success=True,
                action=command.action,
                target=command.target,
                pre_state_hash=verify_hash,
                post_state_hash=None,
                result="dry-run",
                friction=perm_result.friction.value,
            )

        # Step 9: Execute mutation
        from roustabout import mutations

        mutation_result = mutations.execute(
            s.docker,
            command.action,
            command.target,
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
            friction=perm_result.friction.value,
        )

    except (
        lockdown.LockdownError,
        permissions.PermissionDenied,
        RateLimitExceeded,
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
