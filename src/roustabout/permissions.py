"""Stateless permission checks for the tiered capability model.

Maps actions to capabilities, capabilities to tiers.
Checks whether a session has the required capability for an action,
with optional per-container tier overrides via Docker labels.

No I/O, no database, no Docker API calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from roustabout.models import ContainerInfo
from roustabout.redactor import sanitize
from roustabout.session import PermissionTier, Session

# Default deny list — image patterns that force ELEVATE tier for mutations
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
    # Read operations (Observe tier)
    "snapshot": "can_snapshot",
    "audit": "can_audit",
    "diff": "can_diff",
    "generate": "can_generate",
    "read-logs": "can_read_logs",
    "read-health": "can_read_health",
    "dr-plan": "can_dr_plan",
    # Mutation operations (Operate tier)
    "start": "can_start",
    "stop": "can_stop",
    "restart": "can_restart",
    "recreate": "can_recreate",
    "notify-configure": "can_notify_configure",
    # Elevated operations
    "update-image": "can_update_image",
    "modify-compose": "can_modify_compose",
    "prune": "can_prune",
    "exec": "can_exec",
    "modify-secrets": "can_modify_secrets",
    "modify-tier-labels": "can_modify_tier_labels",
}

# Minimum tier required for each capability
CAPABILITY_TIER: dict[str, PermissionTier] = {
    "can_snapshot": PermissionTier.OBSERVE,
    "can_audit": PermissionTier.OBSERVE,
    "can_diff": PermissionTier.OBSERVE,
    "can_generate": PermissionTier.OBSERVE,
    "can_read_logs": PermissionTier.OBSERVE,
    "can_read_health": PermissionTier.OBSERVE,
    "can_dr_plan": PermissionTier.OBSERVE,
    "can_start": PermissionTier.OPERATE,
    "can_stop": PermissionTier.OPERATE,
    "can_restart": PermissionTier.OPERATE,
    "can_recreate": PermissionTier.OPERATE,
    "can_notify_configure": PermissionTier.OPERATE,
    "can_update_image": PermissionTier.ELEVATE,
    "can_modify_compose": PermissionTier.ELEVATE,
    "can_prune": PermissionTier.ELEVATE,
    "can_exec": PermissionTier.ELEVATE,
    "can_modify_secrets": PermissionTier.ELEVATE,
    "can_modify_tier_labels": PermissionTier.ELEVATE,
}


# Exception

@dataclass
class PermissionDenied(Exception):
    """Session lacks required capability or tier."""

    required_capability: str
    required_tier: PermissionTier
    session_tier: PermissionTier
    target: str | None
    reason: str

    def __post_init__(self) -> None:
        super().__init__(self.reason)

    def __str__(self) -> str:
        return self.reason


# Public API

def check(
    session: Session,
    action: str,
    target_info: ContainerInfo | None,
) -> None:
    """Check if session has permission for this action on this target.

    Raises PermissionDenied if the session lacks the required capability or tier.
    Raises ValueError for unknown actions.
    """
    capability = ACTION_CAPABILITY.get(action)
    if capability is None:
        raise ValueError(f"Unknown action: {action!r}")

    base_tier = CAPABILITY_TIER[capability]
    required_tier = base_tier

    # Per-container tier override (only for mutation actions)
    if target_info is not None and base_tier >= PermissionTier.OPERATE:
        required_tier = _resolve_container_tier(target_info, base_tier)

    if not (session.tier >= required_tier):
        raise PermissionDenied(
            required_capability=capability,
            required_tier=required_tier,
            session_tier=session.tier,
            target=target_info.name if target_info else None,
            reason=(
                f"Action '{action}' requires {required_tier.value} tier, "
                f"session has {session.tier.value}"
            ),
        )

    if capability not in session.capabilities:
        raise PermissionDenied(
            required_capability=capability,
            required_tier=required_tier,
            session_tier=session.tier,
            target=target_info.name if target_info else None,
            reason=f"Session lacks capability '{capability}'",
        )


def can_session_do(session: Session, action: str) -> bool:
    """Non-raising check without target override. For MCP tool filtering."""
    capability = ACTION_CAPABILITY.get(action)
    if capability is None:
        return False
    return capability in session.capabilities


def list_capabilities(session: Session) -> list[dict[str, str | bool]]:
    """Return capability list for the docker_capabilities() meta-tool."""
    return [
        {
            "capability": capability,
            "tier": tier.value,
            "available": capability in session.capabilities,
        }
        for capability, tier in CAPABILITY_TIER.items()
    ]


# Internal helpers

def _resolve_container_tier(
    container: ContainerInfo,
    base_tier: PermissionTier,
) -> PermissionTier:
    """Determine the effective tier for an operation on a specific container.

    Checks:
    1. Explicit label override (roustabout.tier=elevate-only)
    2. Default deny list (database, auth, proxy images)
    """
    labels = dict(container.labels)
    raw_tier = labels.get("roustabout.tier")
    # Labels are untrusted Docker input — sanitize before security decisions
    tier_label = sanitize(raw_tier) if raw_tier else None
    if tier_label == "elevate-only":
        return PermissionTier.ELEVATE

    # Default deny list — image pattern matching
    if _matches_deny_list(container.image):
        return max(base_tier, PermissionTier.ELEVATE)

    return base_tier


def _matches_deny_list(image: str) -> bool:
    """Check if an image matches the default elevate-only deny list."""
    return any(pattern.search(image) for pattern in _DEFAULT_ELEVATE_PATTERNS)
