"""Compose GitOps — drift detection, semantic diff, git history.

Compares running containers against compose files to detect drift.
Provides Docker-aware semantic diff between compose file versions.
Tracks compose file history through git.

LLD: docs/roustabout/designs/028-compose-gitops.md
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from roustabout.redactor import sanitize

_yaml = YAML()
_yaml.preserve_quotes = True

logger = logging.getLogger(__name__)

# Compose file names to discover
_COMPOSE_FILENAMES = frozenset(
    {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
)

# Security-relevant compose fields
SECURITY_FIELDS = frozenset(
    {
        "privileged",
        "cap_add",
        "cap_drop",
        "security_opt",
        "network_mode",
        "pid",
        "userns_mode",
        "read_only",
        "devices",
        "volumes",
    }
)


# Data types


@dataclass(frozen=True)
class ComposeProject:
    """A compose project tracked by roustabout."""

    name: str
    path: Path
    git_root: Path | None
    services: tuple[str, ...]


@dataclass(frozen=True)
class Drift:
    """A single difference between compose spec and running state."""

    field: str
    compose_value: str
    running_value: str
    severity: str  # info, warning, critical


@dataclass(frozen=True)
class DriftReport:
    """Differences between compose spec and running containers."""

    project: str
    service: str
    container_name: str
    drifts: tuple[Drift, ...]
    compose_hash: str


@dataclass(frozen=True)
class ComposeChange:
    """A change between two compose file versions."""

    field: str
    old_value: str | None
    new_value: str | None
    change_type: str  # added, removed, modified
    security_relevant: bool


@dataclass(frozen=True)
class SemanticDiff:
    """Docker-aware diff between two compose file versions for one service."""

    service: str
    changes: tuple[ComposeChange, ...]


# --- Project discovery ---


def discover_projects(search_dir: Path) -> tuple[ComposeProject, ...]:
    """Find compose files in a directory tree."""
    projects: list[ComposeProject] = []

    for compose_path in search_dir.rglob("*"):
        if compose_path.name not in _COMPOSE_FILENAMES:
            continue
        if not compose_path.is_file():
            continue

        try:
            with open(compose_path) as f:
                content = _yaml.load(f)
        except Exception:  # noqa: BLE001 — skip unparseable compose files
            logger.warning("Failed to parse %s", compose_path)
            continue

        if not isinstance(content, dict):
            continue

        services = tuple(sorted(content.get("services", {}).keys()))
        name = compose_path.parent.name

        git_root = _find_git_root(compose_path)

        projects.append(
            ComposeProject(
                name=name,
                path=compose_path,
                git_root=git_root,
                services=services,
            )
        )

    return tuple(sorted(projects, key=lambda p: p.name))


def _find_git_root(path: Path) -> Path | None:
    """Find the git repository root for a path."""
    try:
        result = subprocess.run(
            ["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except Exception:  # noqa: BLE001 — git may not be available
        pass
    return None


# --- Drift detection ---


def _normalize_project_name(name: str) -> str:
    """Normalize project name to match Docker Compose v2 behavior.

    Compose v2 lowercases and strips non-alphanumeric characters
    (except hyphens) from the project name derived from the directory.
    """
    import re

    return re.sub(r"[^a-z0-9-]", "", name.lower())


def _resolve_container_name(project_name: str, service_name: str, spec: dict[str, Any]) -> str:
    """Resolve the expected container name for a service."""
    name = spec.get("container_name")
    if name:
        return name
    normalized = _normalize_project_name(project_name)
    return f"{normalized}-{service_name}-1"


def detect_drift(
    client: Any,
    project: ComposeProject,
) -> tuple[DriftReport, ...]:
    """Compare running containers against compose spec.

    Returns one DriftReport per service that has diverged.
    """
    import docker.errors

    with open(project.path) as f:
        compose = _yaml.load(f)

    compose_hash = hashlib.sha256(project.path.read_bytes()).hexdigest()
    services = compose.get("services", {})
    reports: list[DriftReport] = []

    for service_name, spec in services.items():
        container_name = _resolve_container_name(project.name, service_name, spec)

        try:
            container = client.containers.get(container_name)
        except docker.errors.NotFound:
            reports.append(
                DriftReport(
                    project=project.name,
                    service=service_name,
                    container_name=container_name,
                    drifts=(
                        Drift(
                            field="status",
                            compose_value="defined",
                            running_value="not running",
                            severity="critical",
                        ),
                    ),
                    compose_hash=compose_hash,
                )
            )
            continue

        drifts = _compare_service(spec, container)

        if drifts:
            reports.append(
                DriftReport(
                    project=project.name,
                    service=service_name,
                    container_name=container_name,
                    drifts=tuple(drifts),
                    compose_hash=compose_hash,
                )
            )

    return tuple(reports)


def _compare_service(spec: dict[str, Any], container: Any) -> list[Drift]:
    """Compare a compose service spec against a running container."""
    drifts: list[Drift] = []
    attrs = container.attrs
    config = attrs.get("Config", {})
    host_config = attrs.get("HostConfig", {})

    # Image
    spec_image = spec.get("image", "")
    running_image = config.get("Image", "")
    if spec_image and spec_image != running_image:
        # Check without tag for partial matches
        if spec_image.split(":")[0] != running_image.split(":")[0]:
            drifts.append(
                Drift(
                    field="image",
                    compose_value=sanitize(spec_image),
                    running_value=sanitize(running_image),
                    severity="critical",
                )
            )
        elif spec_image != running_image:
            drifts.append(
                Drift(
                    field="image",
                    compose_value=sanitize(spec_image),
                    running_value=sanitize(running_image),
                    severity="critical",
                )
            )

    # Environment
    spec_env = _normalize_env(spec.get("environment"))
    running_env = _parse_running_env(config.get("Env", []))
    # Only check spec keys — running container may have extra env from entrypoint
    for key, spec_val in spec_env.items():
        running_val = running_env.get(key)
        if running_val is not None and spec_val != running_val:
            drifts.append(
                Drift(
                    field=f"environment.{key}",
                    compose_value=sanitize(spec_val),
                    running_value=sanitize(running_val),
                    severity="warning",
                )
            )

    # Restart policy
    spec_restart = spec.get("restart", "")
    running_restart = host_config.get("RestartPolicy", {}).get("Name", "")
    if spec_restart and spec_restart != running_restart:
        drifts.append(
            Drift(
                field="restart",
                compose_value=sanitize(spec_restart),
                running_value=sanitize(running_restart),
                severity="info",
            )
        )

    # Privileged
    spec_priv = spec.get("privileged", False)
    running_priv = host_config.get("Privileged", False)
    if spec_priv != running_priv:
        drifts.append(
            Drift(
                field="privileged",
                compose_value=str(spec_priv),
                running_value=str(running_priv),
                severity="critical",
            )
        )

    # Network mode
    spec_net = spec.get("network_mode", "")
    running_net = host_config.get("NetworkMode", "")
    if spec_net and spec_net != running_net:
        drifts.append(
            Drift(
                field="network_mode",
                compose_value=sanitize(spec_net),
                running_value=sanitize(running_net),
                severity="warning",
            )
        )

    # Ports
    spec_ports = sorted(str(p) for p in spec.get("ports", []))
    running_bindings = attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
    running_ports = sorted(
        f"{b.get('HostPort', '')}:{k.split('/')[0]}"
        for k, binds in running_bindings.items()
        if binds
        for b in binds
    )
    if spec_ports and spec_ports != running_ports:
        drifts.append(
            Drift(
                field="ports",
                compose_value=sanitize(str(spec_ports)),
                running_value=sanitize(str(running_ports)),
                severity="warning",
            )
        )

    # Volumes / bind mounts
    spec_volumes = sorted(str(v) for v in spec.get("volumes", []))
    running_binds = sorted(host_config.get("Binds") or [])
    if spec_volumes and spec_volumes != running_binds:
        drifts.append(
            Drift(
                field="volumes",
                compose_value=sanitize(str(spec_volumes)),
                running_value=sanitize(str(running_binds)),
                severity="warning",
            )
        )

    return drifts


def _normalize_env(env: Any) -> dict[str, str]:
    """Normalize compose environment to dict."""
    if env is None:
        return {}
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    if isinstance(env, list):
        result: dict[str, str] = {}
        for item in env:
            item_str = str(item)
            if "=" in item_str:
                k, v = item_str.split("=", 1)
                result[k] = v
        return result
    return {}


def _parse_running_env(env_list: list[str]) -> dict[str, str]:
    """Parse Docker's ENV list to dict."""
    result: dict[str, str] = {}
    for item in env_list:
        if "=" in item:
            k, v = item.split("=", 1)
            result[k] = v
    return result


# --- Semantic diff ---


def semantic_diff(old_content: str, new_content: str) -> tuple[SemanticDiff, ...]:
    """Compare two compose file contents with Docker-aware intelligence."""
    old = _yaml.load(StringIO(old_content)) or {}
    new = _yaml.load(StringIO(new_content)) or {}

    old_services = old.get("services", {})
    new_services = new.get("services", {})

    results: list[SemanticDiff] = []
    all_services = set(old_services) | set(new_services)

    for name in sorted(all_services):
        old_spec = old_services.get(name, {})
        new_spec = new_services.get(name, {})
        changes = _diff_service(old_spec, new_spec)
        if changes:
            results.append(SemanticDiff(service=name, changes=tuple(changes)))

    return tuple(results)


def _diff_service(old: dict[str, Any], new: dict[str, Any]) -> list[ComposeChange]:
    """Compare two service specs."""
    changes: list[ComposeChange] = []
    all_keys = set(old) | set(new)

    for key in sorted(all_keys):
        old_val = old.get(key)
        new_val = new.get(key)

        old_norm = _normalize_field(key, old_val)
        new_norm = _normalize_field(key, new_val)

        if old_norm == new_norm:
            continue

        if old_val is None:
            change_type = "added"
        elif new_val is None:
            change_type = "removed"
        else:
            change_type = "modified"

        changes.append(
            ComposeChange(
                field=key,
                old_value=str(old_val) if old_val is not None else None,
                new_value=str(new_val) if new_val is not None else None,
                change_type=change_type,
                security_relevant=key in SECURITY_FIELDS,
            )
        )

    return changes


def _normalize_field(key: str, value: Any) -> Any:
    """Normalize compose values for comparison."""
    if value is None:
        return None

    if key == "environment" and isinstance(value, list):
        return dict(v.split("=", 1) for v in sorted(str(x) for x in value) if "=" in str(v))

    if key == "ports" and isinstance(value, list):
        return sorted(str(p) for p in value)

    if key == "volumes" and isinstance(value, list):
        return sorted(str(v) for v in value)

    return value


# --- Compose apply ---


@dataclass(frozen=True)
class ComposeApplyResult:
    """Result of applying a compose file."""

    success: bool
    compose_path: str
    services_affected: tuple[str, ...]
    output: str
    error: str | None = None


def apply_compose(compose_path: Path) -> ComposeApplyResult:
    """Deploy a compose file via docker compose up -d.

    Runs as a subprocess. Returns structured result with output.
    """
    path = Path(compose_path)

    if not path.exists():
        return ComposeApplyResult(
            success=False,
            compose_path=str(path),
            services_affected=(),
            output="",
            error=f"Compose file not found: {path}",
        )

    # Parse to find service names
    try:
        with open(path) as f:
            content = _yaml.load(f)
        services = tuple(sorted(content.get("services", {}).keys()))
    except Exception:  # noqa: BLE001 — report parse failures
        services = ()

    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(path), "up", "-d"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(path.parent),
        )
    except subprocess.TimeoutExpired:
        return ComposeApplyResult(
            success=False,
            compose_path=str(path),
            services_affected=services,
            output="",
            error="docker compose up -d timed out after 120s",
        )
    except FileNotFoundError:
        return ComposeApplyResult(
            success=False,
            compose_path=str(path),
            services_affected=services,
            output="",
            error="docker compose not found on PATH",
        )

    output = sanitize(result.stdout + result.stderr)

    return ComposeApplyResult(
        success=result.returncode == 0,
        compose_path=str(path),
        services_affected=services,
        output=output,
        error=output if result.returncode != 0 else None,
    )
