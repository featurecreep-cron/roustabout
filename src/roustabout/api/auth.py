"""API key authentication and tier resolution."""

from __future__ import annotations

from dataclasses import dataclass, field

_VALID_TIERS = frozenset({"observe", "operate", "elevate"})


class AuthError(Exception):
    """Authentication failure."""


@dataclass(frozen=True)
class KeyInfo:
    """Resolved API key information."""

    tier: str
    label: str


@dataclass(frozen=True)
class AuthConfig:
    """API key configuration.

    Keys map pre-shared tokens to tier and label.
    """

    keys: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict) -> AuthConfig:
        """Construct from a raw config dict (e.g., from TOML)."""
        return cls(keys=raw.get("keys", {}))


def resolve_api_key(key: str | None, config: AuthConfig) -> KeyInfo:
    """Resolve an API key to tier and label.

    Raises AuthError if key is missing, empty, unknown, or has invalid tier.
    """
    if key is None:
        raise AuthError("missing API key")
    if not key or key not in config.keys:
        raise AuthError("invalid API key")

    entry = config.keys[key]
    tier = entry.get("tier", "")
    if tier not in _VALID_TIERS:
        raise AuthError(f"invalid tier '{tier}' for key")
    label = entry.get("label", "unknown")
    return KeyInfo(tier=tier, label=label)
