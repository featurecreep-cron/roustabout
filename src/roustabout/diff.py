"""Compare two Docker environment snapshots.

Reads JSON snapshots and produces a structured diff showing
containers added, removed, and changed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ContainerChange:
    """A single change within a container."""

    field: str
    old: str
    new: str


@dataclass(frozen=True)
class ContainerDiff:
    """Diff for a single container between two snapshots."""

    name: str
    changes: tuple[ContainerChange, ...]


@dataclass(frozen=True)
class SnapshotDiff:
    """Complete diff between two environment snapshots."""

    old_timestamp: str
    new_timestamp: str
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[ContainerDiff, ...]


# Fields to compare between snapshots. Excludes volatile fields
# (id, started_at, restart_count, health, oom_killed) that change
# without meaningful config changes.
_COMPARE_FIELDS = (
    "image",
    "image_id",
    "status",
    "user",
    "restart_policy",
    "privileged",
    "network_mode",
    "read_only",
    "mem_limit",
    "cpus",
    "log_driver",
    "init",
    "pid_mode",
    "runtime",
    "hostname",
)

# Collection fields compared as sorted sets
_SET_FIELDS = (
    "cap_add",
    "cap_drop",
    "devices",
    "dns",
    "extra_hosts",
    "group_add",
    "security_opt",
    "tmpfs",
)


def diff_snapshots(old_path: Path, new_path: Path) -> SnapshotDiff:
    """Compare two JSON snapshot files and return the differences."""
    old_data = json.loads(old_path.read_text())
    new_data = json.loads(new_path.read_text())
    return _diff_envs(old_data, new_data)


def diff_dicts(old: dict[str, Any], new: dict[str, Any]) -> SnapshotDiff:
    """Compare two snapshot dicts (already parsed from JSON)."""
    return _diff_envs(old, new)


def _diff_envs(old: dict[str, Any], new: dict[str, Any]) -> SnapshotDiff:
    """Core diff logic between two environment dicts."""
    old_containers = {c["name"]: c for c in old.get("containers", [])}
    new_containers = {c["name"]: c for c in new.get("containers", [])}

    old_names = set(old_containers.keys())
    new_names = set(new_containers.keys())

    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)

    changed: list[ContainerDiff] = []
    for name in sorted(old_names & new_names):
        changes = _diff_container(old_containers[name], new_containers[name])
        if changes:
            changed.append(ContainerDiff(name=name, changes=tuple(changes)))

    return SnapshotDiff(
        old_timestamp=old.get("generated_at", ""),
        new_timestamp=new.get("generated_at", ""),
        added=tuple(added),
        removed=tuple(removed),
        changed=tuple(changed),
    )


def _diff_container(old: dict[str, Any], new: dict[str, Any]) -> list[ContainerChange]:
    """Compare two container dicts and return changes."""
    changes: list[ContainerChange] = []

    for field in _COMPARE_FIELDS:
        old_val = old.get(field)
        new_val = new.get(field)
        if old_val != new_val:
            changes.append(ContainerChange(field=field, old=str(old_val), new=str(new_val)))

    for field in _SET_FIELDS:
        old_val = sorted(old.get(field, []))
        new_val = sorted(new.get(field, []))
        if old_val != new_val:
            changes.append(ContainerChange(field=field, old=str(old_val), new=str(new_val)))

    # Compare env vars (dict form in JSON)
    old_env = old.get("env", {})
    new_env = new.get("env", {})
    if isinstance(old_env, dict) and isinstance(new_env, dict):
        env_added = sorted(set(new_env) - set(old_env))
        env_removed = sorted(set(old_env) - set(new_env))
        env_changed = sorted(k for k in set(old_env) & set(new_env) if old_env[k] != new_env[k])
        if env_added or env_removed or env_changed:
            parts = []
            if env_added:
                parts.append(f"added: {', '.join(env_added)}")
            if env_removed:
                parts.append(f"removed: {', '.join(env_removed)}")
            if env_changed:
                parts.append(f"changed: {', '.join(env_changed)}")
            changes.append(
                ContainerChange(field="env", old=f"{len(old_env)} vars", new="; ".join(parts))
            )

    # Compare ports
    old_ports = _port_set(old.get("ports", []))
    new_ports = _port_set(new.get("ports", []))
    if old_ports != new_ports:
        changes.append(
            ContainerChange(field="ports", old=str(sorted(old_ports)), new=str(sorted(new_ports)))
        )

    # Compare mounts
    old_mounts = _mount_set(old.get("mounts", []))
    new_mounts = _mount_set(new.get("mounts", []))
    if old_mounts != new_mounts:
        changes.append(
            ContainerChange(
                field="mounts", old=str(sorted(old_mounts)), new=str(sorted(new_mounts))
            )
        )

    # Compare networks
    old_nets = _network_set(old.get("networks", []))
    new_nets = _network_set(new.get("networks", []))
    if old_nets != new_nets:
        changes.append(
            ContainerChange(field="networks", old=str(sorted(old_nets)), new=str(sorted(new_nets)))
        )

    return changes


def _port_set(ports: list[dict[str, Any]]) -> set[str]:
    """Convert port list to comparable set of strings."""
    result: set[str] = set()
    for p in ports:
        hip = p.get("host_ip", "")
        hp = p.get("host_port", "")
        cp = p.get("container_port", "")
        proto = p.get("protocol", "tcp")
        result.add(f"{hip}:{hp}:{cp}/{proto}")
    return result


def _mount_set(mounts: list[dict[str, Any]]) -> set[str]:
    """Convert mount list to comparable set of strings."""
    return {
        f"{m.get('source', '')}:{m.get('destination', '')}:{m.get('mode', '')}" for m in mounts
    }


def _network_set(networks: list[dict[str, Any]]) -> set[str]:
    """Convert network list to comparable set of names."""
    return {n.get("name", "") for n in networks}


def render_diff(diff: SnapshotDiff) -> str:
    """Render a SnapshotDiff as markdown."""
    lines = ["# Snapshot Diff", ""]

    if diff.old_timestamp and diff.new_timestamp:
        lines.append(f"Comparing: `{diff.old_timestamp}` → `{diff.new_timestamp}`")
        lines.append("")

    total_changes = len(diff.added) + len(diff.removed) + len(diff.changed)
    if total_changes == 0:
        lines.append("No changes detected.")
        return "\n".join(lines) + "\n"

    parts = []
    if diff.added:
        parts.append(f"**{len(diff.added)} added**")
    if diff.removed:
        parts.append(f"**{len(diff.removed)} removed**")
    if diff.changed:
        parts.append(f"**{len(diff.changed)} changed**")
    lines.append(", ".join(parts))
    lines.append("")

    if diff.added:
        lines.append("## Added")
        lines.append("")
        for name in diff.added:
            lines.append(f"- {name}")
        lines.append("")

    if diff.removed:
        lines.append("## Removed")
        lines.append("")
        for name in diff.removed:
            lines.append(f"- {name}")
        lines.append("")

    if diff.changed:
        lines.append("## Changed")
        lines.append("")
        for cd in diff.changed:
            lines.append(f"### {cd.name}")
            lines.append("")
            lines.append("| Field | Old | New |")
            lines.append("|-------|-----|-----|")
            for change in cd.changes:
                lines.append(f"| {change.field} | {change.old} | {change.new} |")
            lines.append("")

    return "\n".join(lines) + "\n"
