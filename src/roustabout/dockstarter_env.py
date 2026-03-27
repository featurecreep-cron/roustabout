"""DockStarter .env import — format-specific input adapter.

Parses DockStarter's centralized .env files, classifies variables
as shared/per-service/secret, and maps them to per-stack .env files.

LLD: docs/roustabout/designs/037-dockstarter-env-import.md
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from roustabout.supply_chain import _is_extractable_secret

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


@dataclass(frozen=True)
class EnvVar:
    """A parsed environment variable from a DockStarter .env file."""

    key: str
    value: str
    service: str | None
    is_shared: bool
    is_secret: bool


@dataclass(frozen=True)
class DockStarterEnv:
    """Parsed and classified DockStarter .env contents."""

    shared_vars: tuple[EnvVar, ...]
    per_service_vars: dict[str, tuple[EnvVar, ...]]
    unmapped_vars: tuple[EnvVar, ...]
    source_path: str


@dataclass(frozen=True)
class EnvMigrationResult:
    """Result of mapping DockStarter vars to per-stack .env files."""

    stacks_written: int
    vars_mapped: int
    vars_duplicated: int
    unmapped_vars: tuple[str, ...]
    warnings: tuple[str, ...]
    dry_run: bool


def parse_dockstarter_env(
    env_path: Path,
    service_names: tuple[str, ...] | None = None,
) -> DockStarterEnv:
    """Parse a DockStarter .env file and classify variables.

    Classification priority:
    1. Known globals (PUID, PGID, TZ, etc.) → shared
    2. Prefix match against service_names → per-service
    3. Everything else → unmapped
    """
    if not env_path.exists():
        msg = f"DockStarter .env not found: {env_path}"
        raise FileNotFoundError(msg)

    shared: list[EnvVar] = []
    per_service: dict[str, list[EnvVar]] = {}
    unmapped: list[EnvVar] = []

    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Handle export prefix
        if line.startswith("export "):
            line = line[7:]

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]

        is_secret = _is_extractable_secret(key, value)

        # Priority 1: known globals
        if key in DOCKSTARTER_GLOBALS:
            shared.append(
                EnvVar(key=key, value=value, service=None, is_shared=True, is_secret=is_secret)
            )
            continue

        # Priority 2: prefix match against service names
        matched_service = None
        if service_names:
            matched_service = _match_service_prefix(key, service_names)

        if matched_service:
            per_service.setdefault(matched_service, []).append(
                EnvVar(
                    key=key,
                    value=value,
                    service=matched_service,
                    is_shared=False,
                    is_secret=is_secret,
                )
            )
        else:
            unmapped.append(
                EnvVar(key=key, value=value, service=None, is_shared=False, is_secret=is_secret)
            )

    frozen_per_service = {svc: tuple(vars_list) for svc, vars_list in sorted(per_service.items())}

    return DockStarterEnv(
        shared_vars=tuple(shared),
        per_service_vars=frozen_per_service,
        unmapped_vars=tuple(unmapped),
        source_path=str(env_path),
    )


def map_env_to_stacks(
    parsed: DockStarterEnv,
    stack_mapping: dict[str, str],
    output_dir: Path,
    *,
    dry_run: bool = False,
) -> EnvMigrationResult:
    """Write classified DockStarter vars to per-stack .env files.

    Shared vars are duplicated into every stack. Per-service vars are
    routed via stack_mapping. Services not in stack_mapping produce warnings.
    """
    # Collect vars per stack
    stack_vars: dict[str, dict[str, str]] = {}
    warnings: list[str] = []
    vars_mapped = 0
    unmapped_var_names: list[str] = []

    # Map per-service vars to stacks
    for service, vars_list in parsed.per_service_vars.items():
        stack = stack_mapping.get(service)
        if not stack:
            warnings.append(
                f"service '{service}' not in stack_mapping — {len(vars_list)} variable(s) unmapped"
            )
            unmapped_var_names.extend(v.key for v in vars_list)
            continue

        stack_vars.setdefault(stack, {})
        for var in vars_list:
            stack_vars[stack][var.key] = var.value
            vars_mapped += 1

    # Add shared vars to every stack
    all_stacks = set(stack_mapping.values()) | set(stack_vars.keys())
    vars_duplicated = 0
    for stack_name in all_stacks:
        stack_vars.setdefault(stack_name, {})
        for var in parsed.shared_vars:
            stack_vars[stack_name][var.key] = var.value
            vars_duplicated += 1

    # Add unmapped env vars to warnings
    for var in parsed.unmapped_vars:
        unmapped_var_names.append(var.key)

    stacks_written = 0
    if not dry_run:
        for stack_name, vars_dict in sorted(stack_vars.items()):
            if not vars_dict:
                continue
            stack_dir = output_dir / stack_name
            stack_dir.mkdir(parents=True, exist_ok=True)
            env_file = stack_dir / ".env"

            # Read existing .env to merge (append-aware)
            existing: dict[str, str] = {}
            if env_file.exists():
                for line in env_file.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        existing[k.strip()] = v.strip()

            merged = {**existing, **vars_dict}
            env_lines = [f"{k}={v}" for k, v in sorted(merged.items())]
            env_file.write_text("\n".join(env_lines) + "\n")
            env_file.chmod(0o600)
            stacks_written += 1
    else:
        stacks_written = len([s for s in stack_vars.values() if s])

    return EnvMigrationResult(
        stacks_written=stacks_written,
        vars_mapped=vars_mapped,
        vars_duplicated=vars_duplicated,
        unmapped_vars=tuple(sorted(set(unmapped_var_names))),
        warnings=tuple(warnings),
        dry_run=dry_run,
    )


def _match_service_prefix(
    key: str,
    service_names: tuple[str, ...],
) -> str | None:
    """Match a variable name to a service by prefix.

    Uses case-insensitive prefix match. Longest match wins to handle
    ambiguous prefixes (e.g., PLEXPY_PORT matches plexpy, not plex).
    """
    key_upper = key.upper()
    best_match: str | None = None
    best_len = 0

    for svc in service_names:
        prefix = svc.upper() + "_"
        if key_upper.startswith(prefix) and len(prefix) > best_len:
            best_match = svc
            best_len = len(prefix)

        # Also check double-underscore nesting (SONARR__AUTH__APIKEY)
        prefix_dunder = svc.upper() + "__"
        if key_upper.startswith(prefix_dunder) and len(prefix_dunder) > best_len:
            best_match = svc
            best_len = len(prefix_dunder)

    return best_match
