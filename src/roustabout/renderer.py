"""Render a DockerEnvironment as structured markdown.

Deterministic: the same DockerEnvironment always produces identical output.
"""

from __future__ import annotations

from collections import defaultdict

from roustabout.models import ContainerInfo, DockerEnvironment

# Compose-internal labels that add noise, not signal
_COMPOSE_LABEL_PREFIXES = (
    "com.docker.compose.",
    "com.docker.desktop.",
)


def render(
    env: DockerEnvironment,
    *,
    show_env: bool = False,
    show_labels: bool = True,
) -> str:
    """Render a DockerEnvironment to markdown.

    Args:
        env: The environment snapshot to render.
        show_env: Include environment variables in output.
        show_labels: Include labels (excluding compose-internal) in output.
    """
    lines: list[str] = []

    _render_header(lines, env)
    _render_toc(lines, env)
    _render_containers(lines, env, show_env=show_env, show_labels=show_labels)
    _render_network_topology(lines, env)
    _render_attribution(lines)

    return "\n".join(lines) + "\n"


def _render_header(lines: list[str], env: DockerEnvironment) -> None:
    """Render the document header."""
    lines.append("# Docker Environment")
    lines.append("")
    running = sum(1 for c in env.containers if c.status == "running")
    total = len(env.containers)
    lines.append(f"- **Generated:** {env.generated_at}")
    lines.append(f"- **Docker version:** {env.docker_version}")
    lines.append(f"- **Containers:** {total} total, {running} running")
    lines.append("")


def _render_toc(lines: list[str], env: DockerEnvironment) -> None:
    """Render table of contents."""
    lines.append("## Contents")
    lines.append("")
    for container in env.containers:
        anchor = _make_anchor(container.name)
        status_marker = "" if container.status == "running" else f" ({container.status})"
        lines.append(f"- [{container.name}](#{anchor}){status_marker}")
    lines.append("")


def _render_containers(
    lines: list[str],
    env: DockerEnvironment,
    *,
    show_env: bool,
    show_labels: bool,
) -> None:
    """Render per-container sections, grouped by compose project."""
    grouped = _group_by_compose(env.containers)

    for project, containers in grouped:
        if project:
            lines.append(f"## Compose Project: {project}")
            lines.append("")
            # Find config files from any member
            config_files = next(
                (c.compose_config_files for c in containers if c.compose_config_files), None
            )
            if config_files:
                lines.append(f"Config: `{config_files}`")
                lines.append("")

        for container in containers:
            _render_container(
                lines, container, show_env=show_env, show_labels=show_labels, grouped=bool(project)
            )


def _render_container(
    lines: list[str],
    c: ContainerInfo,
    *,
    show_env: bool,
    show_labels: bool,
    grouped: bool,
) -> None:
    """Render a single container section."""
    heading = "###" if grouped else "##"
    lines.append(f"{heading} {c.name}")
    lines.append("")

    # Status line
    status_parts = [f"**Status:** {c.status}"]
    if c.health:
        status_parts.append(f"**Health:** {c.health}")
    lines.append(" | ".join(status_parts))
    lines.append("")

    # Image
    lines.append(f"**Image:** `{c.image}`")
    if c.image_digest:
        lines.append(f"**Digest:** `{c.image_digest}`")
    lines.append("")

    # Ports
    if c.ports:
        lines.append("#### Ports")
        lines.append("")
        lines.append("| Container | Host | Protocol |")
        lines.append("|-----------|------|----------|")
        for p in c.ports:
            host = f"{p.host_ip}:{p.host_port}" if p.host_ip else p.host_port
            lines.append(f"| {p.container_port} | {host} | {p.protocol} |")
        lines.append("")

    # Mounts
    if c.mounts:
        lines.append("#### Volumes / Mounts")
        lines.append("")
        lines.append("| Source | Destination | Type | Mode |")
        lines.append("|--------|-------------|------|------|")
        for m in c.mounts:
            lines.append(f"| `{m.source}` | `{m.destination}` | {m.type} | {m.mode} |")
        lines.append("")

    # Networks
    if c.networks:
        lines.append("#### Networks")
        lines.append("")
        for n in c.networks:
            alias_str = f" (aliases: {', '.join(n.aliases)})" if n.aliases else ""
            ip_str = n.ip_address if n.ip_address else "no IP"
            lines.append(f"- **{n.name}:** {ip_str}{alias_str}")
        lines.append("")

    # Environment
    if show_env and c.env:
        lines.append("#### Environment")
        lines.append("")
        lines.append("| Variable | Value |")
        lines.append("|----------|-------|")
        for key, value in c.env:
            lines.append(f"| `{key}` | `{value}` |")
        lines.append("")

    # Labels (excluding compose-internal)
    if show_labels and c.labels:
        filtered = [
            (k, v) for k, v in c.labels if not any(k.startswith(p) for p in _COMPOSE_LABEL_PREFIXES)
        ]
        if filtered:
            lines.append("#### Labels")
            lines.append("")
            lines.append("| Label | Value |")
            lines.append("|-------|-------|")
            for key, value in filtered:
                lines.append(f"| `{key}` | `{value}` |")
            lines.append("")

    # Metadata
    lines.append("#### Metadata")
    lines.append("")
    lines.append(f"- **ID:** `{c.id}`")
    lines.append(f"- **Created:** {c.created}")
    lines.append(f"- **Started:** {c.started_at}")
    if c.command:
        lines.append(f"- **Command:** `{c.command}`")
    if c.entrypoint:
        lines.append(f"- **Entrypoint:** `{c.entrypoint}`")
    lines.append(f"- **Restart count:** {c.restart_count}")
    if c.oom_killed:
        lines.append("- **OOM Killed:** yes")
    lines.append("")


def _render_network_topology(lines: list[str], env: DockerEnvironment) -> None:
    """Render a summary of which containers share which networks."""
    network_members: dict[str, list[str]] = defaultdict(list)

    for c in env.containers:
        for n in c.networks:
            network_members[n.name].append(c.name)

    if not network_members:
        return

    lines.append("## Network Topology")
    lines.append("")

    for net_name in sorted(network_members.keys()):
        members = sorted(network_members[net_name])
        lines.append(f"- **{net_name}:** {', '.join(members)}")

    lines.append("")


def _render_attribution(lines: list[str]) -> None:
    """Render the attribution comment."""
    lines.append(
        "<!-- Generated by roustabout (https://github.com/FeatureCreep-dev/roustabout) -->"
    )


def _group_by_compose(
    containers: tuple[ContainerInfo, ...],
) -> list[tuple[str | None, list[ContainerInfo]]]:
    """Group containers by compose project, ungrouped last.

    Returns list of (project_name, containers) tuples.
    None project_name means ungrouped.
    """
    projects: dict[str | None, list[ContainerInfo]] = defaultdict(list)

    for c in containers:
        projects[c.compose_project].append(c)

    result: list[tuple[str | None, list[ContainerInfo]]] = []

    # Named projects first, sorted
    for project in sorted(k for k in projects if k is not None):
        result.append((project, projects[project]))

    # Ungrouped last
    if None in projects:
        result.append((None, projects[None]))

    return result


def _make_anchor(name: str) -> str:
    """Convert a container name to a markdown anchor."""
    return name.lower().replace(" ", "-").replace(".", "").replace("/", "")
