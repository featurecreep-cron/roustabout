"""Secret rotation — lifecycle management for secrets.

Extends SecretBroker with rotation and sharing audit.
Rotation is ELEVATE-tier — it mutates secrets and restarts containers.

LLD: docs/roustabout/designs/031-secret-rotation.md
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


# Data types


@dataclass(frozen=True)
class RotationPolicy:
    """Rotation schedule for a secret."""

    secret_name: str
    strategy: str  # regenerate, expire-notify, manual
    interval_days: int
    warn_days: int
    consumers: tuple[str, ...]
    restart_order: tuple[str, ...]


@dataclass(frozen=True)
class RotationStatus:
    """Current rotation status for a secret."""

    secret_name: str
    last_rotated: datetime | None
    next_rotation: datetime | None
    age_days: int
    stale: bool
    consumers: tuple[str, ...]


@dataclass(frozen=True)
class SharedSecret:
    """A secret shared across multiple containers."""

    secret_name: str
    containers: tuple[str, ...]
    blast_radius: int


@dataclass(frozen=True)
class SecretSharingReport:
    """Secrets shared across multiple containers."""

    shared_secrets: tuple[SharedSecret, ...]
    unique_secrets: int
    total_secrets: int


@dataclass(frozen=True)
class RotationResult:
    """Result of a secret rotation attempt."""

    success: bool
    secret_name: str
    containers_updated: tuple[str, ...]
    containers_restarted: tuple[str, ...]
    containers_failed: tuple[str, ...]
    rolled_back: bool
    rollback_failed: bool = False
    error: str | None = None


# Public API


def get_rotation_status(
    secret_broker: Any,
    policies: tuple[RotationPolicy, ...],
) -> tuple[RotationStatus, ...]:
    """Check rotation status for all configured policies."""
    results: list[RotationStatus] = []
    now = datetime.now(UTC)

    for policy in policies:
        try:
            metadata = secret_broker.get_metadata(policy.secret_name)
            last_rotated = metadata.last_updated if metadata else None
        except Exception:  # noqa: broad-except — treat metadata errors as unknown age
            last_rotated = None

        if last_rotated:
            age = (now - last_rotated).days
            next_rotation = last_rotated.replace(
                day=last_rotated.day,
            )
            from datetime import timedelta

            next_rotation = last_rotated + timedelta(days=policy.interval_days)
        else:
            age = -1
            next_rotation = None

        results.append(
            RotationStatus(
                secret_name=policy.secret_name,
                last_rotated=last_rotated,
                next_rotation=next_rotation,
                age_days=max(0, age),
                stale=age > policy.interval_days if age >= 0 else True,
                consumers=policy.consumers,
            )
        )

    return tuple(results)


def check_stale_secrets(
    secret_broker: Any,
    policies: tuple[RotationPolicy, ...],
) -> tuple[RotationStatus, ...]:
    """Return only secrets that are past their rotation interval."""
    all_status = get_rotation_status(secret_broker, policies)
    return tuple(s for s in all_status if s.stale)


def rotate_secret(
    secret_broker: Any,
    gateway: Any,
    session: Any,
    policy: RotationPolicy,
) -> RotationResult:
    """Execute a secret rotation. Routes through gateway for restarts."""
    if policy.strategy != "regenerate":
        return RotationResult(
            success=False,
            secret_name=policy.secret_name,
            containers_updated=(),
            containers_restarted=(),
            containers_failed=(),
            rolled_back=False,
            error=f"Strategy {policy.strategy!r} does not support auto-rotation",
        )

    # 1. Backup current value
    try:
        old_value = secret_broker.get_value(policy.secret_name)
    except Exception as e:  # noqa: broad-except — any broker error aborts rotation
        return RotationResult(
            success=False,
            secret_name=policy.secret_name,
            containers_updated=(),
            containers_restarted=(),
            containers_failed=(),
            rolled_back=False,
            error=f"Failed to read current secret: {e}",
        )

    # 2. Generate new value
    try:
        new_value = secret_broker.generate(policy.secret_name)
    except Exception as e:  # noqa: broad-except — any broker error aborts rotation
        return RotationResult(
            success=False,
            secret_name=policy.secret_name,
            containers_updated=(),
            containers_restarted=(),
            containers_failed=(),
            rolled_back=False,
            error=f"Failed to generate new secret: {e}",
        )

    # 3. Inject into all consumers
    updated: list[str] = []
    for container_name in policy.consumers:
        try:
            secret_broker.inject(policy.secret_name, container_name, new_value)
            updated.append(container_name)
        except Exception as e:  # noqa: broad-except — injection failure triggers rollback
            # Rollback injected containers
            for rollback_name in updated:
                try:
                    secret_broker.inject(policy.secret_name, rollback_name, old_value)
                except Exception:  # noqa: broad-except — best-effort rollback
                    pass
            return RotationResult(
                success=False,
                secret_name=policy.secret_name,
                containers_updated=tuple(updated),
                containers_restarted=(),
                containers_failed=(container_name,),
                rolled_back=True,
                error=f"Injection failed for {container_name}: {e}",
            )

    # 4. Restart in order
    restarted: list[str] = []
    for container_name in policy.restart_order:
        from roustabout.gateway import MutationCommand

        result = gateway.execute(
            MutationCommand(
                action="restart",
                target=container_name,
                host=getattr(session, "host", "localhost")
                if hasattr(session, "host")
                else "localhost",
            ),
            session=session,
        )

        if result.success:
            restarted.append(container_name)
        else:
            # Rollback: restore old secret, restart already-restarted containers
            rollback_ok = True
            for rollback_name in policy.consumers:
                try:
                    secret_broker.inject(policy.secret_name, rollback_name, old_value)
                except Exception:  # noqa: broad-except — best-effort rollback
                    rollback_ok = False

            for restart_name in restarted:
                rb_result = gateway.execute(
                    MutationCommand(
                        action="restart",
                        target=restart_name,
                        host=getattr(session, "host", "localhost")
                        if hasattr(session, "host")
                        else "localhost",
                    ),
                    session=session,
                )
                if not rb_result.success:
                    rollback_ok = False

            return RotationResult(
                success=False,
                secret_name=policy.secret_name,
                containers_updated=tuple(updated),
                containers_restarted=tuple(restarted),
                containers_failed=(container_name,),
                rolled_back=True,
                rollback_failed=not rollback_ok,
                error=f"Restart failed for {container_name}: {result.error}",
            )

    # 5. Record rotation
    try:
        secret_broker.record_rotation(policy.secret_name)
    except Exception:  # noqa: broad-except — recording failure is non-fatal
        logger.warning("Failed to record rotation for %s", policy.secret_name)

    return RotationResult(
        success=True,
        secret_name=policy.secret_name,
        containers_updated=tuple(updated),
        containers_restarted=tuple(restarted),
        containers_failed=(),
        rolled_back=False,
    )


def audit_secret_sharing(secret_broker: Any) -> SecretSharingReport:
    """Analyze which secrets are shared across containers."""
    secrets = secret_broker.list_secrets()
    shared: list[SharedSecret] = []

    for secret in secrets:
        consumers = secret_broker.get_consumers(secret.name)
        if len(consumers) > 1:
            shared.append(
                SharedSecret(
                    secret_name=secret.name,
                    containers=tuple(sorted(consumers)),
                    blast_radius=len(consumers),
                )
            )

    return SecretSharingReport(
        shared_secrets=tuple(sorted(shared, key=lambda s: -s.blast_radius)),
        unique_secrets=len(secrets) - len(shared),
        total_secrets=len(secrets),
    )


def policies_from_config(config: dict[str, Any]) -> tuple[RotationPolicy, ...]:
    """Parse rotation policies from roustabout.toml."""
    rotation_config = config.get("secrets", {}).get("rotation", {})
    if not rotation_config.get("enabled", False):
        return ()

    policies: list[RotationPolicy] = []
    for policy_dict in rotation_config.get("policies", []):
        policies.append(
            RotationPolicy(
                secret_name=policy_dict.get("name", ""),
                strategy=policy_dict.get("strategy", "manual"),
                interval_days=policy_dict.get("interval_days", 90),
                warn_days=policy_dict.get("warn_days", 14),
                consumers=tuple(policy_dict.get("consumers", [])),
                restart_order=tuple(policy_dict.get("restart_order", [])),
            )
        )

    return tuple(policies)
