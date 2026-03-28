"""Friction-based permission checks for the tiered capability model.

Maps actions to capabilities, resolves friction mechanisms per session tier.
Tiers control friction, not capability availability — every operation is
accessible at every tier with varying human involvement.

No I/O, no database, no Docker API calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from roustabout.models import ContainerInfo
from roustabout.redactor import sanitize
from roustabout.session import PermissionTier, Session


class FrictionMechanism(Enum):
    """How much human involvement an operation requires at a given tier."""

    DIRECT = "direct"
    CONFIRM = "confirm"
    STAGE = "stage"
    DIRECTED = "directed"
    ALLOWLIST = "allowlist"
    DENYLIST = "denylist"


@dataclass(frozen=True)
class PermissionResult:
    """Result of a permission check. Returns friction mechanism, not allow/deny."""

    action: str
    capability: str
    friction: FrictionMechanism
    session_tier: PermissionTier
    effective_tier: PermissionTier
    target: str | None


@dataclass
class PermissionDenied(Exception):
    """Only raised for truly denied operations.

    With the friction model, this is rare — most operations get friction instead.
    Kept for: elevate-only containers, modify-tier-labels at sub-ELEVATE.
    """

    required_capability: str
    required_tier: PermissionTier
    session_tier: PermissionTier
    target: str | None
    reason: str

    def __post_init__(self) -> None:
        super().__init__(self.reason)

    def __str__(self) -> str:
        return self.reason


# Default deny list — image patterns that force ELEVATE for mutations
_DEFAULT_ELEVATE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(?:^|/)postgres(?:ql)?[:\s]",
        r"(?:^|/)mysql[:\s]",
        r"(?:^|/)mariadb[:\s]",
        r"(?:^|/)mongo(?:db)?[:\s]",
        r"(?:^|/)redis[:\s]",
        r"(?:^|/)(?:go)?authentik[/:\s]",
        r"(?:^|/)authelia[:\s]",
        r"(?:^|/)traefik[:\s]",
        r"(?:^|/)nginx-proxy-manager[:\s]",
        r"(?:^|/)vaultwarden[:\s]",
        r"(?:^|/)keycloak[:\s]",
    )
)


# Action → capability mapping

ACTION_CAPABILITY: dict[str, str] = {
    # Lifecycle mutations
    "start": "can_start",
    "stop": "can_stop",
    "restart": "can_restart",
    "recreate": "can_recreate",
    "recreate-spec-change": "can_recreate_spec_change",
    "update-image": "can_update_image",
    "prune": "can_prune",
    # Exec
    "exec": "can_exec",
    # File operations
    "file-read": "can_file_read",
    "file-write": "can_file_write",
    # Compose operations
    "compose-apply": "can_compose_apply",
    # Admin
    "modify-secrets": "can_modify_secrets",
    "modify-tier-labels": "can_modify_tier_labels",
    "notify-configure": "can_notify_configure",
    # Read operations
    "snapshot": "can_snapshot",
    "audit": "can_audit",
    "audit-compose": "can_audit_compose",
    "diff": "can_diff",
    "generate": "can_generate",
    "read-logs": "can_read_logs",
    "read-health": "can_read_health",
    "dr-plan": "can_dr_plan",
    "digest-age": "can_digest_age",
    "reverse-map-env": "can_reverse_map_env",
}

# Friction ladder per capability per tier
# Missing tier entries inherit DIRECTED (safest default)

CAPABILITY_FRICTION: dict[str, dict[PermissionTier, FrictionMechanism]] = {
    # Read ops: direct at all tiers
    "can_snapshot": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_audit": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_audit_compose": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_diff": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_generate": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_read_logs": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_read_health": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_dr_plan": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_digest_age": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_reverse_map_env": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    "can_file_read": {t: FrictionMechanism.DIRECT for t in PermissionTier},
    # Lifecycle: DIRECTED at OBSERVE, DIRECT at OPERATE+
    "can_start": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.DIRECT,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    "can_stop": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.DIRECT,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    "can_restart": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.DIRECT,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    "can_recreate": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.DIRECT,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    # Spec change / update: DIRECTED → CONFIRM → DIRECT
    "can_recreate_spec_change": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.CONFIRM,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    "can_update_image": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.CONFIRM,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    # Exec: DIRECTED → ALLOWLIST → DENYLIST
    "can_exec": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.ALLOWLIST,
        PermissionTier.ELEVATE: FrictionMechanism.DENYLIST,
    },
    # File write: DIRECTED → STAGE → DIRECT
    "can_file_write": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.STAGE,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    # Compose apply: DIRECTED → CONFIRM → DIRECT
    "can_compose_apply": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.CONFIRM,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    # Admin ops
    "can_prune": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.DIRECTED,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    "can_modify_secrets": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.DIRECTED,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
    "can_modify_tier_labels": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.DIRECTED,
        PermissionTier.ELEVATE: FrictionMechanism.CONFIRM,
    },
    "can_notify_configure": {
        PermissionTier.OBSERVE: FrictionMechanism.DIRECTED,
        PermissionTier.OPERATE: FrictionMechanism.DIRECT,
        PermissionTier.ELEVATE: FrictionMechanism.DIRECT,
    },
}


# Read operations — deny list doesn't apply to these
_READ_CAPABILITIES = frozenset(
    cap for cap in CAPABILITY_FRICTION
    if all(
        CAPABILITY_FRICTION[cap][t] == FrictionMechanism.DIRECT
        for t in PermissionTier
    )
)


# Public API


def resolve_friction(
    capability: str,
    session_tier: PermissionTier,
) -> FrictionMechanism:
    """Look up friction mechanism for a capability at a tier.

    Falls back to DIRECTED if the capability or tier is missing.
    """
    cap_map = CAPABILITY_FRICTION.get(capability, {})
    return cap_map.get(session_tier, FrictionMechanism.DIRECTED)


def check(
    session: Session,
    action: str,
    target_info: ContainerInfo | None,
) -> PermissionResult:
    """Resolve friction mechanism for this action at this session's tier.

    Returns PermissionResult with friction mechanism.

    Raises:
        PermissionDenied: Only for elevate-only containers at sub-ELEVATE
            tier, or modify-tier-labels at sub-ELEVATE tier.
        ValueError: Unknown action string.
    """
    capability = ACTION_CAPABILITY.get(action)
    if capability is None:
        raise ValueError(f"Unknown action: {action!r}")

    effective_tier = session.tier

    # Per-container tier override — only for non-read operations
    if target_info is not None and capability not in _READ_CAPABILITIES:
        _check_container_override(session, target_info, action, capability)

    # Hard deny: modify-tier-labels always requires ELEVATE
    if (
        capability == "can_modify_tier_labels"
        and session.tier < PermissionTier.ELEVATE
    ):
        raise PermissionDenied(
            required_capability=capability,
            required_tier=PermissionTier.ELEVATE,
            session_tier=session.tier,
            target=target_info.name if target_info else None,
            reason=(
                "Modifying tier labels requires ELEVATE tier. "
                f"Current tier: {session.tier.value}. "
                "Next step: request elevation with "
                "request_elevation(reason='...')"
            ),
        )

    friction = resolve_friction(capability, effective_tier)

    return PermissionResult(
        action=action,
        capability=capability,
        friction=friction,
        session_tier=session.tier,
        effective_tier=effective_tier,
        target=target_info.name if target_info else None,
    )


def can_session_do(session: Session, action: str) -> bool:
    """Check if the session can perform this action at any friction level.

    Returns True for all known actions — every action is available at
    every tier with varying friction. Returns False for unknown actions.
    """
    return action in ACTION_CAPABILITY


def list_capabilities(session: Session) -> list[dict[str, str | bool]]:
    """Return capability list with friction annotations.

    Used by docker_capabilities() meta-tool and MCP tool descriptions.
    """
    result = []
    for action, capability in ACTION_CAPABILITY.items():
        friction = resolve_friction(capability, session.tier)
        result.append({
            "capability": capability,
            "action": action,
            "friction": friction.value,
            "available": True,
        })
    return result


# Internal helpers


def _check_container_override(
    session: Session,
    container: ContainerInfo,
    action: str,
    capability: str,
) -> None:
    """Check per-container tier overrides. Raises PermissionDenied if denied."""
    labels = dict(container.labels)
    raw_tier = labels.get("roustabout.tier")
    # Labels are untrusted Docker input — sanitize before security decisions
    tier_label = sanitize(raw_tier) if raw_tier else None

    if tier_label == "elevate-only" and session.tier < PermissionTier.ELEVATE:
        raise PermissionDenied(
            required_capability=capability,
            required_tier=PermissionTier.ELEVATE,
            session_tier=session.tier,
            target=container.name,
            reason=(
                f"Container '{container.name}' requires ELEVATE tier "
                f"for '{action}'. Current tier: {session.tier.value}. "
                "Next step: request elevation with "
                "request_elevation(reason='...')"
            ),
        )

    # Default deny list — database, auth, proxy images
    if _matches_deny_list(container.image) and session.tier < PermissionTier.ELEVATE:
        raise PermissionDenied(
            required_capability=capability,
            required_tier=PermissionTier.ELEVATE,
            session_tier=session.tier,
            target=container.name,
            reason=(
                f"Container '{container.name}' (image: {container.image}) "
                f"is on the default protection list and requires ELEVATE "
                f"tier for '{action}'. Current tier: {session.tier.value}. "
                "Next step: request elevation with "
                "request_elevation(reason='...')"
            ),
        )


def _matches_deny_list(image: str) -> bool:
    """Check if an image matches the default elevate-only deny list."""
    return any(pattern.search(image) for pattern in _DEFAULT_ELEVATE_PATTERNS)
