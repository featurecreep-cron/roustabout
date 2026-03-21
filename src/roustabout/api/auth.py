"""API key authentication and tier resolution."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

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
    def from_dict(cls, raw: dict[str, Any]) -> AuthConfig:
        """Construct from a raw config dict (e.g., from TOML)."""
        return cls(keys=raw.get("keys", {}))

    @classmethod
    def from_env(cls) -> AuthConfig:
        """Construct from environment variables.

        Reads ROUSTABOUT_API_KEY (required), ROUSTABOUT_API_TIER (default: operate),
        and ROUSTABOUT_API_LABEL (default: env-key). Returns empty config if
        ROUSTABOUT_API_KEY is not set.
        """
        secret = os.environ.get("ROUSTABOUT_API_KEY", "")
        if not secret:
            return cls(keys={})
        tier = os.environ.get("ROUSTABOUT_API_TIER", "observe")
        label = os.environ.get("ROUSTABOUT_API_LABEL", "env-key")
        return cls(keys={secret: {"tier": tier, "label": label}})

    def merge(self, other: AuthConfig) -> AuthConfig:
        """Merge two configs. Keys from other override self on conflict."""
        merged = {**self.keys, **other.keys}
        return AuthConfig(keys=merged)


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
