"""Deep health inspection — port checks and service probes.

Extends health_stats.py with active verification:
- Port health (OBSERVE): TCP connection test to published ports.
- Service health (ELEVATE): Probe commands inside containers via exec.

LLD: docs/roustabout/designs/032-deep-health.md
"""

from __future__ import annotations

import logging
import shlex
import socket
from dataclasses import dataclass
from typing import Any

from roustabout.session import DockerSession

logger = logging.getLogger(__name__)


# Data types


@dataclass(frozen=True)
class HealthProfile:
    """Health check configuration for a service type."""

    name: str
    port_check: int | None = None
    service_probe: str | None = None
    timeout: int = 5


@dataclass(frozen=True)
class DeepHealthResult:
    """Result of deep health inspection for one container."""

    container_name: str
    profile: str
    docker_health: str | None
    port_open: bool | None
    service_healthy: bool | None
    service_output: str | None
    overall: str  # healthy, degraded, unhealthy, unknown
    checks_performed: tuple[str, ...]


@dataclass(frozen=True)
class EnvironmentHealth:
    """Health summary across all containers."""

    total: int
    healthy: int
    degraded: int
    unhealthy: int
    unknown: int
    results: tuple[DeepHealthResult, ...]


# Image name → profile name heuristics

_IMAGE_PROFILES: dict[str, str] = {
    "postgres": "database",
    "mariadb": "database",
    "mysql": "database",
    "mongo": "database",
    "redis": "cache",
    "nginx": "web",
    "traefik": "web",
    "caddy": "web",
    "httpd": "web",
}


# Internal checks


def _check_port(host: str, port: int, timeout: int = 5) -> bool:
    """TCP connection test to a published port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


def _service_probe(
    docker_session: DockerSession,
    container_name: str,
    probe_command: str,
    timeout: int,
) -> tuple[bool, str]:
    """Run a service probe inside the container via exec.

    Returns (healthy, sanitized_output).
    """
    from roustabout.container_exec import ExecCommand
    from roustabout.container_exec import execute as exec_execute

    try:
        cmd_parts = tuple(shlex.split(probe_command))
    except ValueError:
        return False, f"Invalid probe command: {probe_command!r}"

    result = exec_execute(
        docker_session,
        ExecCommand(target=container_name, command=cmd_parts, timeout=timeout),
    )

    return result.success, result.stdout or result.stderr or ""


def _determine_overall(
    docker_health: str | None,
    port_open: bool | None,
    service_healthy: bool | None,
) -> str:
    """Combine check results into overall status."""
    checks: list[bool] = []
    if docker_health is not None:
        checks.append(docker_health == "healthy")
    if port_open is not None:
        checks.append(port_open)
    if service_healthy is not None:
        checks.append(service_healthy)

    if not checks:
        return "unknown"
    if all(checks):
        return "healthy"
    if any(checks):
        return "degraded"
    return "unhealthy"


# Profile resolution


def resolve_profile(
    container_name: str,
    labels: dict[str, str],
    image: str,
    configured_profiles: dict[str, HealthProfile],
) -> HealthProfile | None:
    """Match a container to a health profile.

    Priority: label > image heuristic > None.
    """
    profile_name = labels.get("roustabout.health-profile")
    if profile_name and profile_name in configured_profiles:
        return configured_profiles[profile_name]

    image_base = image.split("/")[-1].split(":")[0]
    for pattern, pname in _IMAGE_PROFILES.items():
        if pattern in image_base and pname in configured_profiles:
            return configured_profiles[pname]

    return None


# Public API


def check_container_health(
    client: Any,
    target: str,
    profile: HealthProfile | None = None,
    docker_session: DockerSession | None = None,
) -> DeepHealthResult:
    """Run all applicable health checks for a container.

    OBSERVE tier: Docker health + port check.
    ELEVATE tier (if docker_session provided): + service probe via exec.
    """
    checks_performed: list[str] = []

    # Docker health
    container = client.containers.get(target)
    state = container.attrs.get("State", {})
    health_info = state.get("Health")
    docker_health = health_info.get("Status") if health_info else None
    checks_performed.append("docker_health")

    # Port check
    port_open: bool | None = None
    if profile and profile.port_check is not None:
        # Check against the published port on localhost
        port_bindings = container.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
        port_key = f"{profile.port_check}/tcp"
        bindings = port_bindings.get(port_key)
        if bindings:
            host_port = bindings[0].get("HostPort")
            if host_port:
                port_open = _check_port("127.0.0.1", int(host_port), profile.timeout)
                checks_performed.append("port_check")

    # Service probe
    service_healthy: bool | None = None
    service_output: str | None = None
    if profile and profile.service_probe and docker_session is not None:
        service_healthy, service_output = _service_probe(
            docker_session, target, profile.service_probe, profile.timeout
        )
        checks_performed.append("service_probe")

    overall = _determine_overall(docker_health, port_open, service_healthy)
    profile_name = profile.name if profile else "none"

    return DeepHealthResult(
        container_name=target,
        profile=profile_name,
        docker_health=docker_health,
        port_open=port_open,
        service_healthy=service_healthy,
        service_output=service_output,
        overall=overall,
        checks_performed=tuple(checks_performed),
    )


def check_environment_health(
    client: Any,
    profiles: dict[str, HealthProfile] | None = None,
    docker_session: DockerSession | None = None,
) -> EnvironmentHealth:
    """Health check all running containers."""
    configured_profiles = profiles or {}
    containers = client.containers.list()
    results: list[DeepHealthResult] = []

    for container in containers:
        name = container.name
        labels = container.attrs.get("Config", {}).get("Labels", {}) or {}
        image = container.attrs.get("Config", {}).get("Image", "")

        profile = resolve_profile(name, labels, image, configured_profiles)

        try:
            result = check_container_health(
                client, name, profile=profile, docker_session=docker_session
            )
            results.append(result)
        except Exception:  # noqa: broad-except — skip individual container failures
            logger.warning("Failed deep health check for %s", name)
            results.append(
                DeepHealthResult(
                    container_name=name,
                    profile=profile.name if profile else "none",
                    docker_health=None,
                    port_open=None,
                    service_healthy=None,
                    service_output=None,
                    overall="unknown",
                    checks_performed=(),
                )
            )

    healthy = sum(1 for r in results if r.overall == "healthy")
    degraded = sum(1 for r in results if r.overall == "degraded")
    unhealthy = sum(1 for r in results if r.overall == "unhealthy")
    unknown = sum(1 for r in results if r.overall == "unknown")

    return EnvironmentHealth(
        total=len(results),
        healthy=healthy,
        degraded=degraded,
        unhealthy=unhealthy,
        unknown=unknown,
        results=tuple(results),
    )
