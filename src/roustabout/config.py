"""Configuration loading for roustabout.

Loads settings from TOML files with CLI override support.
Search order: --config flag > ./roustabout.toml > ~/.config/roustabout/config.toml
"""

from __future__ import annotations

import dataclasses
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATHS = (
    Path("roustabout.toml"),
    Path.home() / ".config" / "roustabout" / "config.toml",
)


@dataclass(frozen=True)
class Config:
    """Roustabout configuration.

    All fields have sensible defaults. Config files and CLI flags override them.
    """

    redact_patterns: tuple[str, ...] = ()
    show_env: bool = False
    show_labels: bool = True
    output: str | None = None
    docker_host: str | None = None
    severity_overrides: dict[str, str] = field(default_factory=dict)

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

    return Config(**kwargs)
