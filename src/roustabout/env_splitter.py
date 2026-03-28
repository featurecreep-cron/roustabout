"""General-purpose .env parser and splitter.

Parses a centralized .env file, classifies variables as shared/per-service/
unmapped, and writes them to per-directory .env files. Format-specific
adapters (e.g. dockstarter_env) supply classification rules.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from roustabout.supply_chain import _is_extractable_secret


@dataclass(frozen=True)
class EnvVar:
    """A parsed environment variable."""

    key: str
    value: str
    service: str | None
    is_shared: bool
    is_secret: bool


@dataclass(frozen=True)
class ParsedEnv:
    """Parsed and classified .env contents."""

    shared_vars: tuple[EnvVar, ...]
    per_service_vars: dict[str, tuple[EnvVar, ...]]
    unmapped_vars: tuple[EnvVar, ...]
    source_path: str


@dataclass(frozen=True)
class EnvSplitResult:
    """Result of splitting vars into per-directory .env files."""

    stacks_written: int
    vars_mapped: int
    vars_duplicated: int
    unmapped_vars: tuple[str, ...]
    warnings: tuple[str, ...]
    dry_run: bool


def parse_env(
    env_path: Path,
    *,
    shared_vars: frozenset[str] = frozenset(),
    service_names: tuple[str, ...] | None = None,
    var_to_service: Callable[[str, tuple[str, ...]], str | None] | None = None,
) -> ParsedEnv:
    """Parse and classify .env variables.

    Classification priority:
    1. Key in *shared_vars* → shared.
    2. *var_to_service* callback (if provided) → per-service.
    3. Prefix match against *service_names* → per-service (default).
    4. Everything else → unmapped.

    Args:
        env_path: Path to the .env file.
        shared_vars: Variable names that are always classified as shared.
        service_names: Known service names for prefix matching.
        var_to_service: Optional callback ``(key, service_names) -> service | None``
            for custom classification. Called before prefix matching.
    """
    if not env_path.exists():
        msg = f".env file not found: {env_path}"
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

        # Priority 1: known shared vars
        if key in shared_vars:
            shared.append(
                EnvVar(key=key, value=value, service=None, is_shared=True, is_secret=is_secret)
            )
            continue

        # Priority 2+3: callback then prefix match
        matched_service = None
        if service_names:
            if var_to_service is not None:
                matched_service = var_to_service(key, service_names)
            if matched_service is None:
                matched_service = match_service_prefix(key, service_names)

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

    return ParsedEnv(
        shared_vars=tuple(shared),
        per_service_vars=frozen_per_service,
        unmapped_vars=tuple(unmapped),
        source_path=str(env_path),
    )


def split_env(
    parsed: ParsedEnv,
    stack_mapping: dict[str, str],
    output_dir: Path,
    *,
    dry_run: bool = False,
) -> EnvSplitResult:
    """Write classified vars to per-directory .env files.

    Shared vars are duplicated into every stack. Per-service vars are
    routed via stack_mapping. Services not in stack_mapping produce warnings.
    """
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

    # Collect unmapped env vars
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

            # Read existing .env to merge
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

    return EnvSplitResult(
        stacks_written=stacks_written,
        vars_mapped=vars_mapped,
        vars_duplicated=vars_duplicated,
        unmapped_vars=tuple(sorted(set(unmapped_var_names))),
        warnings=tuple(warnings),
        dry_run=dry_run,
    )


def match_service_prefix(
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
