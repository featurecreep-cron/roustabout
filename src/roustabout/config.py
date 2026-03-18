"""Configuration loading for roustabout.

Loads settings from TOML files with CLI override support.
Search order: --config flag > ROUSTABOUT_CONFIG env > ./roustabout.toml
> ~/.config/roustabout/config.toml

Unknown sections are silently ignored (forward-compatible with Phase 2+ features).
"""

from __future__ import annotations

import dataclasses
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATHS = (
    Path("roustabout.toml"),
    Path.home() / ".config" / "roustabout" / "config.toml",
)

# Default deny list: databases, auth stacks, reverse proxies → elevate-only
DEFAULT_ELEVATE_ONLY_IMAGES: tuple[str, ...] = (
    "postgres", "mysql", "mariadb", "mongo", "redis",
    "authentik", "authelia",
    "traefik", "nginx-proxy-manager",
)


@dataclass(frozen=True)
class Config:
    """Roustabout configuration.

    All fields have sensible defaults. Config files and CLI flags override them.
    """

    # --- Existing v0.5 fields ---
    redact_patterns: tuple[str, ...] = ()
    show_env: bool = False
    show_labels: bool = True
    output: str | None = None
    docker_host: str | None = None
    severity_overrides: dict[str, str] = field(default_factory=dict)

    # --- Phase 1 fields ---
    # Rate limiting
    rate_limit_per_container: int = 3
    rate_limit_window_seconds: int = 300
    rate_limit_global: int = 10

    # Blast radius
    blast_radius_cap: int = 5

    # Notification channels
    ntfy_url: str | None = None
    apprise_urls: tuple[str, ...] = ()

    # Notification routing (event_type → list of channel names)
    notification_routing: dict[str, list[str]] = field(default_factory=dict)

    # Permission tiers
    default_tier: str = "operate"
    elevate_only_images: tuple[str, ...] = DEFAULT_ELEVATE_ONLY_IMAGES
    allowlist_patterns: tuple[str, ...] = ()

    # Log access
    log_tail_default: int = 100

    # Response size
    response_size_cap: int = 262144  # 256KB

    # State database path
    state_db: str | None = None

    _UNSET = object()

    def merge(self, **overrides: Any) -> Config:
        """Return a new Config with explicitly provided overrides applied.

        Only keys present in overrides (regardless of value) are applied.
        Use this instead of dataclasses.replace() to merge CLI flags with
        config file values — CLI flags not provided by the user are excluded
        by the caller.
        """
        kwargs = {}
        for f in dataclasses.fields(self):
            if f.name in overrides:
                kwargs[f.name] = overrides[f.name]
            else:
                kwargs[f.name] = getattr(self, f.name)
        return Config(**kwargs)


def load_config(path: Path | None = None) -> Config:
    """Load configuration from a TOML file.

    Args:
        path: Explicit config file path. If None, searches default locations.
              Also checks ROUSTABOUT_CONFIG env var.

    Returns:
        Config with values from the file, or defaults if no file found.

    Raises:
        FileNotFoundError: If an explicit path is given but doesn't exist.
        ValueError: If the TOML file has invalid structure.
    """
    if path is not None:
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        return _parse_config(path)

    env_path = os.environ.get("ROUSTABOUT_CONFIG")
    if env_path:
        p = Path(env_path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p} (from ROUSTABOUT_CONFIG)")
        return _parse_config(p)

    for candidate in DEFAULT_CONFIG_PATHS:
        if candidate.exists():
            return _parse_config(candidate)

    return Config()


def _parse_config(path: Path) -> Config:
    """Parse a TOML config file into a Config object."""
    with open(path, "rb") as f:
        data = tomllib.load(f)

    kwargs: dict[str, Any] = {}

    if "redact_patterns" in data:
        patterns = data["redact_patterns"]
        if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
            raise ValueError(f"redact_patterns must be a list of strings in {path}")
        kwargs["redact_patterns"] = tuple(patterns)

    if "show_env" in data:
        if not isinstance(data["show_env"], bool):
            raise ValueError(f"show_env must be a boolean in {path}")
        kwargs["show_env"] = data["show_env"]

    if "show_labels" in data:
        if not isinstance(data["show_labels"], bool):
            raise ValueError(f"show_labels must be a boolean in {path}")
        kwargs["show_labels"] = data["show_labels"]

    if "output" in data:
        if not isinstance(data["output"], str):
            raise ValueError(f"output must be a string in {path}")
        kwargs["output"] = data["output"]

    if "docker_host" in data:
        if not isinstance(data["docker_host"], str):
            raise ValueError(f"docker_host must be a string in {path}")
        kwargs["docker_host"] = data["docker_host"]

    if "severity" in data:
        severity_table = data["severity"]
        if not isinstance(severity_table, dict):
            raise ValueError(f"severity must be a table in {path}")
        valid_levels = {"critical", "warning", "info"}
        for category, level in severity_table.items():
            if not isinstance(level, str) or level.lower() not in valid_levels:
                raise ValueError(f"severity.{category} must be one of {valid_levels} in {path}")
        kwargs["severity_overrides"] = {k: v.lower() for k, v in severity_table.items()}

    # --- Phase 1 fields ---

    _parse_positive_int(data, "rate_limit_per_container", kwargs, path)
    _parse_positive_int(data, "rate_limit_window_seconds", kwargs, path)
    _parse_positive_int(data, "rate_limit_global", kwargs, path)
    _parse_positive_int(data, "blast_radius_cap", kwargs, path)

    if "ntfy_url" in data:
        if not isinstance(data["ntfy_url"], str):
            raise ValueError(f"ntfy_url must be a string in {path}")
        kwargs["ntfy_url"] = data["ntfy_url"]

    if "apprise_urls" in data:
        urls = data["apprise_urls"]
        if not isinstance(urls, list) or not all(isinstance(u, str) for u in urls):
            raise ValueError(f"apprise_urls must be a list of strings in {path}")
        kwargs["apprise_urls"] = tuple(urls)

    if "notification_routing" in data:
        routing = data["notification_routing"]
        if not isinstance(routing, dict):
            raise ValueError(f"notification_routing must be a table in {path}")
        kwargs["notification_routing"] = {
            k: v if isinstance(v, list) else [v] for k, v in routing.items()
        }

    if "default_tier" in data:
        valid_tiers = {"observe", "operate", "elevate"}
        tier = data["default_tier"]
        if not isinstance(tier, str) or tier.lower() not in valid_tiers:
            raise ValueError(f"default_tier must be one of {valid_tiers} in {path}")
        kwargs["default_tier"] = tier.lower()

    if "elevate_only_images" in data:
        images = data["elevate_only_images"]
        if not isinstance(images, list) or not all(isinstance(i, str) for i in images):
            raise ValueError(f"elevate_only_images must be a list of strings in {path}")
        kwargs["elevate_only_images"] = tuple(images)

    if "allowlist_patterns" in data:
        patterns = data["allowlist_patterns"]
        if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
            raise ValueError(f"allowlist_patterns must be a list of strings in {path}")
        kwargs["allowlist_patterns"] = tuple(patterns)

    _parse_positive_int(data, "log_tail_default", kwargs, path)
    _parse_positive_int(data, "response_size_cap", kwargs, path)

    if "state_db" in data:
        if not isinstance(data["state_db"], str):
            raise ValueError(f"state_db must be a string in {path}")
        kwargs["state_db"] = data["state_db"]

    return Config(**kwargs)


def _parse_positive_int(
    data: dict[str, Any], key: str, kwargs: dict[str, Any], path: Path
) -> None:
    """Parse and validate a positive integer config value."""
    if key in data:
        val = data[key]
        if not isinstance(val, int) or val <= 0:
            raise ValueError(f"{key} must be a positive integer in {path}")
        kwargs[key] = val
