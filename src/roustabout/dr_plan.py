"""Disaster recovery plan generation from a DockerEnvironment snapshot.

Produces a Markdown document with step-by-step restore instructions using
plain Docker CLI commands. Actionable WITHOUT roustabout installed.

The caller (CLI/MCP) collects, sanitizes, and redacts the environment
before passing it here. dr_plan receives clean, safe data.
"""

from __future__ import annotations

import re
from collections import defaultdict

from roustabout.models import ContainerInfo, DockerEnvironment

# Default Docker networks that shouldn't appear in network setup
_DEFAULT_NETWORKS = frozenset({"bridge", "host", "none"})

# Docker internal label prefixes — skip in restore commands
_INTERNAL_LABEL_PREFIXES = (
    "com.docker.",
    "org.opencontainers.",
    "desktop.docker.",
    "maintainer",
)


def generate(env: DockerEnvironment) -> str:
    """Generate a DR plan from a collected, redacted DockerEnvironment.

    Returns a complete Markdown document.
    """
    lines: list[str] = []
    count = len(env.containers)

    lines.append("# Disaster Recovery Plan")
    lines.append(f"Generated: {env.generated_at}")
    lines.append(f"Docker version: {env.docker_version}")
    lines.append(f"Containers: {count}")
    lines.append("")

    if count == 0:
        lines.append("No containers found. Nothing to restore.")
        return "\n".join(lines)

    # Prerequisites
    lines.append("## Prerequisites")
    lines.append("- Docker Engine installed")
    lines.append("- Access to container images (Docker Hub, GHCR, etc.)")
    lines.append("- Backup data for volumes listed in the Backup Checklist below")
    lines.append("")

    # Network setup
    networks = _collect_networks(env)
    if networks:
        lines.append("## Network Setup")
        lines.append("Create these networks before starting containers:")
        lines.append("")
        for net_name in sorted(networks):
            lines.append("```bash")
            lines.append(f"docker network create {_shell_quote(net_name)}")
            lines.append("```")
            lines.append("")

    # Restore order
    ordered = _resolve_dependency_order(env)
    lines.append("## Restore Order")
    lines.append("Containers listed in dependency order. Start from top.")
    lines.append("")

    warnings: list[str] = []

    for i, container in enumerate(ordered, 1):
        _render_container_section(lines, i, container, env, warnings)

    # Warnings
    if warnings:
        lines.append("## Warnings")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    # Backup checklist
    checklist = _build_backup_checklist(env)
    lines.append("## Backup Checklist")
    if checklist:
        lines.append("Host paths that need preservation (deduplicated, sorted):")
        lines.append("")
        for path in checklist:
            lines.append(f"- `{path}`")
    else:
        lines.append("No host-path bind mounts found.")
    lines.append("")

    return "\n".join(lines)


def _render_container_section(
    lines: list[str],
    index: int,
    container: ContainerInfo,
    env: DockerEnvironment,
    warnings: list[str],
) -> None:
    """Render one container's DR section."""
    lines.append(f"### {index}. {container.name}")
    lines.append(f"**Image:** {container.image}")

    if container.compose_project:
        lines.append(f"**Compose project:** {container.compose_project}")
        if container.compose_service:
            lines.append(f"**Compose service:** {container.compose_service}")
    else:
        lines.append("**Compose project:** standalone")

    lines.append(f"**Status at snapshot:** {container.status}")

    # Init container detection
    if container.status == "exited" and not container.restart_policy:
        lines.append("")
        lines.append(
            "> **Note:** This container ran once and exited (no restart policy). "
            "It may be an init/migration container — run it before dependent services."
        )

    # Volumes table
    if container.mounts:
        lines.append("")
        lines.append("#### Volumes")
        lines.append("| Mount | Source | Type |")
        lines.append("|-------|--------|------|")
        for mount in container.mounts:
            src = mount.source
            if _is_anonymous_volume(src):
                src = f"{src[:12]}... (anonymous)"
                warnings.append(
                    f"{container.name}: anonymous volume at {mount.destination} "
                    "— data in Docker volume store, not a host path"
                )
            lines.append(f"| {mount.destination} | {src} | {mount.type} |")

    # Restore steps
    lines.append("")
    lines.append("#### Restore Steps")
    lines.append("```bash")

    # Volume prep
    has_bind = any(m.type == "bind" for m in container.mounts)
    has_volume = any(
        m.type == "volume" and not _is_anonymous_volume(m.source)
        for m in container.mounts
    )
    if has_bind or has_volume:
        lines.append("# 1. Restore volume data")
        for mount in container.mounts:
            if mount.type == "bind":
                lines.append(f"mkdir -p {_shell_quote(mount.source)}")
                lines.append(f"# Copy backup data to {mount.source}")
            elif mount.type == "volume" and not _is_anonymous_volume(mount.source):
                lines.append(f"docker volume create {_shell_quote(mount.source)}")
        lines.append("")
        lines.append("# 2. Create and start container")
    else:
        lines.append("# Create and start container")

    # Docker run command
    lines.append(_build_run_command(container, env))
    lines.append("```")

    # Additional networks (connect after creation)
    if len(container.networks) > 1:
        lines.append("")
        lines.append("#### Additional Networks")
        lines.append("```bash")
        for net in container.networks[1:]:
            parts = ["docker network connect"]
            if net.aliases:
                for alias in net.aliases:
                    parts.append(f"--alias {_shell_quote(alias)}")
            if net.ip_address:
                parts.append(f"--ip {net.ip_address}")
            parts.append(_shell_quote(net.name))
            parts.append(_shell_quote(container.name))
            lines.append(" ".join(parts))
        lines.append("```")

    # Post-start verification
    lines.append("")
    lines.append("#### Post-Start Verification")
    lines.append("```bash")
    lines.append(f"docker ps --filter name={_shell_quote(container.name)}")
    if container.healthcheck:
        lines.append(
            f"docker inspect --format='{{{{.State.Health.Status}}}}' "
            f"{_shell_quote(container.name)}"
        )
    lines.append("```")
    lines.append("")

    # Compose working dir (S5.1.2)
    compose_dir = _get_label(container, "com.docker.compose.project.working_dir")
    if compose_dir:
        warnings.append(
            f"{container.name}: created from compose files at {compose_dir}. "
            "Verify your backups include .env files from that directory."
        )

    # Locally-built image (S5.1.2)
    if _is_local_image(container.image):
        warnings.append(
            f"{container.name}: image '{container.image}' appears to be locally built "
            "and cannot be pulled from a registry. Back up the build context."
        )

    lines.append("---")
    lines.append("")


def _build_run_command(container: ContainerInfo, env: DockerEnvironment) -> str:
    """Generate a docker run command from ContainerInfo."""
    parts = ["docker run -d"]
    parts.append(f"  --name {_shell_quote(container.name)}")

    if container.restart_policy:
        parts.append(f"  --restart {container.restart_policy}")

    if container.hostname:
        parts.append(f"  --hostname {_shell_quote(container.hostname)}")

    # Network mode
    is_host_net = container.network_mode == "host"
    is_container_net = (container.network_mode or "").startswith("container:")

    if is_host_net:
        parts.append("  --network host")
    elif container.network_mode == "none":
        parts.append("  --network none")
    elif is_container_net:
        dep_id = container.network_mode.split(":", 1)[1]
        dep_name = _resolve_id_to_name(env, dep_id) or dep_id
        parts.append(f"  --network container:{_shell_quote(dep_name)}")
    elif container.networks:
        parts.append(f"  --network {_shell_quote(container.networks[0].name)}")

    # Ports (skip for host/container network modes)
    if not is_host_net and not is_container_net:
        for port in container.ports:
            if port.host_port:
                bind = (
                    f"{port.host_ip}:"
                    if port.host_ip and port.host_ip != "0.0.0.0"
                    else ""
                )
                parts.append(f"  -p {bind}{port.host_port}:{port.container_port}/{port.protocol}")

    # Volumes
    for mount in container.mounts:
        mode = f":{mount.mode}" if mount.mode != "rw" else ""
        if mount.type == "bind":
            parts.append(
                f"  -v {_shell_quote(mount.source)}:{_shell_quote(mount.destination)}{mode}"
            )
        elif mount.type == "volume":
            parts.append(
                f"  -v {_shell_quote(mount.source)}:{_shell_quote(mount.destination)}{mode}"
            )

    # Tmpfs
    for t in container.tmpfs:
        parts.append(f"  --tmpfs {_shell_quote(t)}")

    # Environment
    for key, value in container.env:
        parts.append(f"  -e {_shell_quote(f'{key}={value}')}")

    # Labels (skip Docker internals)
    for key, value in container.labels:
        if not _is_internal_label(key):
            parts.append(f"  --label {_shell_quote(f'{key}={value}')}")

    # Resource limits
    if container.mem_limit:
        parts.append(f"  --memory {_format_bytes(container.mem_limit)}")
    if container.cpus:
        parts.append(f"  --cpus {container.cpus}")

    # Security
    if container.privileged:
        parts.append("  --privileged")
    for cap in container.cap_add:
        parts.append(f"  --cap-add {cap}")
    for cap in container.cap_drop:
        parts.append(f"  --cap-drop {cap}")
    if container.read_only:
        parts.append("  --read-only")
    for opt in container.security_opt:
        parts.append(f"  --security-opt {_shell_quote(opt)}")

    # User and groups
    if container.user:
        parts.append(f"  --user {_shell_quote(container.user)}")
    for grp in container.group_add:
        parts.append(f"  --group-add {_shell_quote(grp)}")

    # PID mode
    if container.pid_mode:
        parts.append(f"  --pid {_shell_quote(container.pid_mode)}")

    # Devices
    for dev in container.devices:
        parts.append(f"  --device {_shell_quote(dev)}")

    # DNS
    for d in container.dns:
        parts.append(f"  --dns {_shell_quote(d)}")
    for ds in container.dns_search:
        parts.append(f"  --dns-search {_shell_quote(ds)}")

    # Extra hosts
    for eh in container.extra_hosts:
        parts.append(f"  --add-host {_shell_quote(eh)}")

    # Sysctls
    for key, value in container.sysctls:
        parts.append(f"  --sysctl {_shell_quote(f'{key}={value}')}")

    # Runtime (GPU, etc.)
    if container.runtime and container.runtime not in ("runc", "io.containerd.runc.v2"):
        parts.append(f"  --runtime {_shell_quote(container.runtime)}")

    # Shared memory size
    if container.shm_size:
        parts.append(f"  --shm-size {_format_bytes(container.shm_size)}")

    # Init
    if container.init:
        parts.append("  --init")

    # Stop signal and timeout
    if container.stop_signal:
        parts.append(f"  --stop-signal {container.stop_signal}")
    if container.stop_grace_period:
        parts.append(f"  --stop-timeout {container.stop_grace_period}")

    # Logging
    if container.log_driver:
        parts.append(f"  --log-driver {_shell_quote(container.log_driver)}")
    for key, value in container.log_opts:
        parts.append(f"  --log-opt {_shell_quote(f'{key}={value}')}")

    # Entrypoint — docker run --entrypoint accepts exactly ONE argument.
    # Multi-element entrypoints: first element is --entrypoint, rest go after image.
    entrypoint_extra: list[str] = []
    if container.entrypoint:
        parts.append(f"  --entrypoint {_shell_quote(container.entrypoint[0])}")
        entrypoint_extra = list(container.entrypoint[1:])

    # Image (always last before command args)
    parts.append(f"  {container.image}")

    # Command args: entrypoint extras first, then explicit command
    all_args = entrypoint_extra + list(container.command or ())
    if all_args:
        cmd = " ".join(_shell_quote(a) for a in all_args)
        parts.append(f"  {cmd}")

    return " \\\n".join(parts)


def _format_bytes(n: int) -> str:
    """Format a byte count as a human-readable Docker memory string."""
    if n >= 1073741824 and n % 1073741824 == 0:
        return f"{n // 1073741824}g"
    if n >= 1048576 and n % 1048576 == 0:
        return f"{n // 1048576}m"
    if n >= 1024 and n % 1024 == 0:
        return f"{n // 1024}k"
    return str(n)


def _shell_quote(s: str) -> str:
    """Shell-safe quoting using single quotes with escaped internal quotes."""
    if not s:
        return "''"
    # If the string contains only safe chars, return as-is
    if re.fullmatch(r"[a-zA-Z0-9_./:@=-]+", s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def _resolve_dependency_order(env: DockerEnvironment) -> list[ContainerInfo]:
    """Topological sort of containers by dependency.

    Returns containers in start order (dependencies first).
    Cycles are broken alphabetically with a warning.
    """
    by_name: dict[str, ContainerInfo] = {c.name: c for c in env.containers}

    # Build adjacency: container X depends on Y
    deps: dict[str, set[str]] = {c.name: set() for c in env.containers}

    for container in env.containers:
        # container: network mode
        if container.network_mode and container.network_mode.startswith("container:"):
            dep_id = container.network_mode.split(":", 1)[1]
            dep_name = _resolve_id_to_name(env, dep_id)
            if dep_name and dep_name in deps:
                deps[container.name].add(dep_name)

    # Kahn's algorithm
    in_degree: dict[str, int] = {name: 0 for name in deps}
    for name, dep_set in deps.items():
        for dep in dep_set:
            if dep in in_degree:
                in_degree[name] += 1

    # Reverse: who depends on me
    reverse: dict[str, set[str]] = defaultdict(set)
    for name, dep_set in deps.items():
        for dep in dep_set:
            reverse[dep].add(name)

    queue = sorted(name for name, deg in in_degree.items() if deg == 0)
    result: list[ContainerInfo] = []

    while queue:
        name = queue.pop(0)
        result.append(by_name[name])
        for dependent in sorted(reverse.get(name, [])):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)
        queue.sort()  # maintain alphabetical order within tier

    # Cycle detection: add remaining nodes alphabetically
    remaining = sorted(
        name for name, deg in in_degree.items() if deg > 0
    )
    for name in remaining:
        result.append(by_name[name])

    return result


def _resolve_id_to_name(env: DockerEnvironment, container_id: str) -> str | None:
    """Resolve a container ID (full or prefix) to its name."""
    for c in env.containers:
        if c.id == container_id or c.id.startswith(container_id):
            return c.name
    return None


def _collect_networks(env: DockerEnvironment) -> set[str]:
    """Collect non-default networks used by containers."""
    networks: set[str] = set()
    for container in env.containers:
        for net in container.networks:
            if net.name not in _DEFAULT_NETWORKS:
                networks.add(net.name)
    return networks


def _is_internal_label(key: str) -> bool:
    """Check if a label is Docker internal and should be skipped."""
    return any(key.startswith(prefix) for prefix in _INTERNAL_LABEL_PREFIXES)


def _is_anonymous_volume(name: str | None) -> bool:
    """Detect anonymous volumes by their 64-char hex string names."""
    if not name:
        return True
    return bool(re.fullmatch(r"[0-9a-f]{64}", name))


def _is_local_image(image: str) -> bool:
    """Detect locally-built images that can't be pulled from a registry.

    Images that are just a sha256 hash or have no registry prefix and no tag
    are likely local builds.
    """
    if image.startswith("sha256:"):
        return True
    return False


def _get_label(container: ContainerInfo, key: str) -> str | None:
    """Get a label value by key, or None if not present."""
    for k, v in container.labels:
        if k == key:
            return v
    return None


def _build_backup_checklist(env: DockerEnvironment) -> list[str]:
    """Collect all host paths that need backup, deduplicated and sorted."""
    paths: set[str] = set()
    for container in env.containers:
        for mount in container.mounts:
            if mount.type == "bind":
                paths.add(mount.source)
        # Compose working directory
        compose_dir = _get_label(container, "com.docker.compose.project.working_dir")
        if compose_dir:
            paths.add(compose_dir)
    return sorted(paths)
