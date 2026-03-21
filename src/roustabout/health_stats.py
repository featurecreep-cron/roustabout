"""Container health monitoring and resource usage.

Collects health status, resource stats, and disk usage from Docker API.
No mutations — read-only operations only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import docker.errors as _docker_errors

logger = logging.getLogger(__name__)


# Data types


@dataclass(frozen=True)
class ContainerHealth:
    """Container health and lifecycle state."""

    name: str
    status: str  # running, exited, restarting, paused, created
    health: str | None  # healthy, unhealthy, starting, None (no healthcheck)
    restart_count: int
    oom_killed: bool
    started_at: str
    health_log: tuple[dict[str, Any], ...] = ()
    healthcheck_config: dict[str, Any] | None = None


@dataclass(frozen=True)
class ContainerStats:
    """Point-in-time resource usage snapshot."""

    name: str
    cpu_percent: float
    memory_usage_bytes: int
    memory_limit_bytes: int
    memory_percent: float
    network_rx_bytes: int
    network_tx_bytes: int
    block_read_bytes: int | None  # None = unavailable (cgroup v2)
    block_write_bytes: int | None


@dataclass(frozen=True)
class DiskUsage:
    """Docker system disk usage breakdown."""

    images_count: int
    images_size_bytes: int
    containers_count: int
    containers_size_bytes: int
    volumes_count: int
    volumes_size_bytes: int
    build_cache_size_bytes: int


# Collection


def collect_health(client: Any) -> list[ContainerHealth]:
    """Collect health status for all containers."""
    containers = client.containers.list(all=True)
    results = []
    for c in containers:
        state = c.attrs.get("State", {})
        health_info = state.get("Health")
        config = c.attrs.get("Config", {})
        hc_config = config.get("Healthcheck")

        results.append(
            ContainerHealth(
                name=c.name,
                status=state.get("Status", c.status),
                health=health_info.get("Status") if health_info else None,
                restart_count=c.attrs.get("RestartCount", 0),
                oom_killed=state.get("OOMKilled", False),
                started_at=state.get("StartedAt", ""),
                health_log=tuple(health_info.get("Log", [])) if health_info else (),
                healthcheck_config=hc_config,
            )
        )
    return results


def collect_stats(
    client: Any,
    target: str | None = None,
) -> list[ContainerStats]:
    """Collect resource stats for containers.

    If target is specified, collect for that container only.
    """
    if target:
        containers = [client.containers.get(target)]
    else:
        containers = client.containers.list()

    results = []
    for c in containers:
        try:
            raw = c.stats(stream=False)
            results.append(_parse_stats(c.name, raw))
        except _docker_errors.DockerException:
            logger.warning("Failed to collect stats for %s", c.name)
    return results


def collect_disk_usage(client: Any) -> DiskUsage:
    """Collect Docker system disk usage."""
    df = client.df()

    images = df.get("Images", [])
    images_size = sum(img.get("Size", 0) for img in images)

    containers = df.get("Containers", [])
    containers_size = sum(c.get("SizeRw", 0) for c in containers)

    volumes = df.get("Volumes", [])
    volumes_size = sum(v.get("UsageData", {}).get("Size", 0) for v in volumes)

    build_cache = df.get("BuildCache", [])
    cache_size = sum(b.get("Size", 0) for b in build_cache)

    return DiskUsage(
        images_count=len(images),
        images_size_bytes=images_size,
        containers_count=len(containers),
        containers_size_bytes=containers_size,
        volumes_count=len(volumes),
        volumes_size_bytes=volumes_size,
        build_cache_size_bytes=cache_size,
    )


# Stats parsing


def _parse_stats(name: str, raw: dict[str, Any]) -> ContainerStats:
    """Parse docker stats JSON into ContainerStats."""
    cpu = _parse_cpu(raw)
    mem_usage, mem_limit, mem_percent = _parse_memory(raw)
    net_rx, net_tx = _parse_network(raw)
    block_read, block_write = _parse_block_io(raw)

    return ContainerStats(
        name=name,
        cpu_percent=cpu,
        memory_usage_bytes=mem_usage,
        memory_limit_bytes=mem_limit,
        memory_percent=mem_percent,
        network_rx_bytes=net_rx,
        network_tx_bytes=net_tx,
        block_read_bytes=block_read,
        block_write_bytes=block_write,
    )


def _parse_cpu(raw: dict[str, Any]) -> float:
    """Calculate CPU % from delta-based stats."""
    cpu_stats = raw.get("cpu_stats", {})
    pre_stats = raw.get("precpu_stats", {})

    cpu_delta = cpu_stats.get("cpu_usage", {}).get("total_usage", 0) - pre_stats.get(
        "cpu_usage", {}
    ).get("total_usage", 0)
    system_delta = cpu_stats.get("system_cpu_usage", 0) - pre_stats.get("system_cpu_usage", 0)

    if system_delta <= 0 or cpu_delta <= 0:
        return 0.0

    # Number of CPUs: prefer online_cpus, fall back to percpu_usage length
    num_cpus = cpu_stats.get("online_cpus")
    if not num_cpus:
        percpu = cpu_stats.get("cpu_usage", {}).get("percpu_usage")
        num_cpus = len(percpu) if percpu else 1

    return round((cpu_delta / system_delta) * num_cpus * 100.0, 2)  # type: ignore[no-any-return]


def _parse_memory(raw: dict[str, Any]) -> tuple[int, int, float]:
    """Parse memory usage, accounting for cache."""
    mem = raw.get("memory_stats", {})
    usage = mem.get("usage", 0)
    limit = mem.get("limit", 0)

    # Subtract cache (inactive file in v2, cache in v1)
    stats = mem.get("stats", {})
    cache = stats.get("inactive_file") or stats.get("cache") or 0
    net_usage = max(0, usage - cache)

    percent = round((net_usage / limit) * 100.0, 2) if limit > 0 else 0.0
    return net_usage, limit, percent


def _parse_network(raw: dict[str, Any]) -> tuple[int, int]:
    """Sum network I/O across all interfaces."""
    networks = raw.get("networks", {})
    rx = sum(iface.get("rx_bytes", 0) for iface in networks.values())
    tx = sum(iface.get("tx_bytes", 0) for iface in networks.values())
    return rx, tx


def _parse_block_io(raw: dict[str, Any]) -> tuple[int | None, int | None]:
    """Parse block I/O stats. Returns None if unavailable."""
    blkio = raw.get("blkio_stats", {})
    entries = blkio.get("io_service_bytes_recursive")

    if entries is None:
        return None, None

    read_bytes = 0
    write_bytes = 0
    for entry in entries:
        op = (entry.get("op") or "").lower()
        value = entry.get("value", 0)
        if op == "read":
            read_bytes += value
        elif op == "write":
            write_bytes += value

    return read_bytes, write_bytes


# Rendering


def _human_size(n: int | None) -> str:
    """Convert bytes to human-readable string."""
    if n is None:
        return "N/A"
    if n < 1024:
        return f"{n}B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024  # type: ignore[assignment]
        if n < 1024:
            return f"{n:.1f}{unit}"
    return f"{n:.1f}PB"


def render_health(healths: list[ContainerHealth]) -> str:
    """Render health status as markdown table."""
    lines = [
        "# Container Health",
        "",
        "| Container | Status | Health | Restarts | OOM | Started |",
        "|-----------|--------|--------|----------|-----|---------|",
    ]
    for h in healths:
        health = h.health or "none"
        lines.append(
            f"| {h.name} | {h.status} | {health} "
            f"| {h.restart_count} | {h.oom_killed} | {h.started_at} |"
        )
    return "\n".join(lines)


def render_stats(stats: list[ContainerStats]) -> str:
    """Render resource stats as markdown table."""
    lines = [
        "# Container Stats",
        "",
        "| Container | CPU % | Memory | Mem Limit | Mem % | Net RX | Net TX |",
        "|-----------|-------|--------|-----------|-------|--------|--------|",
    ]
    for s in stats:
        lines.append(
            f"| {s.name} | {s.cpu_percent}% "
            f"| {_human_size(s.memory_usage_bytes)} "
            f"| {_human_size(s.memory_limit_bytes)} "
            f"| {s.memory_percent}% "
            f"| {_human_size(s.network_rx_bytes)} "
            f"| {_human_size(s.network_tx_bytes)} |"
        )
    return "\n".join(lines)
