"""DockStarter .env import — thin adapter over env_splitter.

Supplies DockStarter-specific defaults (known globals) to the
general-purpose env_splitter primitives.

LLD: docs/roustabout/designs/037-dockstarter-env-import.md
"""

from __future__ import annotations

from pathlib import Path

from roustabout.env_splitter import (
    EnvSplitResult,
    EnvVar,
    ParsedEnv,
    match_service_prefix,
    parse_env,
    split_env,
)

# Re-export types under original names for backwards compatibility
DockStarterEnv = ParsedEnv
EnvMigrationResult = EnvSplitResult

# Known DockStarter global variables — stable, small set
DOCKSTARTER_GLOBALS = frozenset(
    {
        "PUID",
        "PGID",
        "TZ",
        "UMASK",
        "DOCKERCONFDIR",
        "DOCKERSTORAGEDIR",
        "DOCKERHOSTNAME",
        "DOCKERSHAREDDIR",
        "DOWNLOADSDIR",
        "MEDIADIR",
    }
)


def parse_dockstarter_env(
    env_path: Path,
    service_names: tuple[str, ...] | None = None,
) -> ParsedEnv:
    """Parse a DockStarter .env file and classify variables.

    Classification priority:
    1. Known globals (PUID, PGID, TZ, etc.) → shared
    2. Prefix match against service_names → per-service
    3. Everything else → unmapped
    """
    return parse_env(
        env_path,
        shared_vars=DOCKSTARTER_GLOBALS,
        service_names=service_names,
    )


def map_env_to_stacks(
    parsed: ParsedEnv,
    stack_mapping: dict[str, str],
    output_dir: Path,
    *,
    dry_run: bool = False,
) -> EnvSplitResult:
    """Write classified DockStarter vars to per-stack .env files."""
    return split_env(parsed, stack_mapping, output_dir, dry_run=dry_run)


# Re-export for existing test imports
_match_service_prefix = match_service_prefix

__all__ = [
    "DOCKSTARTER_GLOBALS",
    "DockStarterEnv",
    "EnvMigrationResult",
    "EnvVar",
    "map_env_to_stacks",
    "parse_dockstarter_env",
]
