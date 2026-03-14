"""Data models for Docker environment documentation.

Frozen dataclasses with sorted tuples for deterministic output.
All collections are sorted at construction time.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PortBinding:
    """A single port binding between container and host."""

    container_port: int
    protocol: str
    host_ip: str
    host_port: str


@dataclass(frozen=True)
class MountInfo:
    """A volume or bind mount attached to a container."""

    source: str
    destination: str
    mode: str
    type: str


@dataclass(frozen=True)
class NetworkMembership:
    """A container's membership in a Docker network."""

    name: str
    ip_address: str
    aliases: tuple[str, ...]


@dataclass(frozen=True)
class HealthcheckConfig:
    """Container health check configuration (not status)."""

    test: tuple[str, ...]
    interval_ns: int
    timeout_ns: int
    retries: int
    start_period_ns: int


@dataclass(frozen=True)
class ContainerInfo:
    """Complete snapshot of a single container's state."""

    name: str
    id: str
    status: str
    image: str
    image_id: str
    image_digest: str | None
    ports: tuple[PortBinding, ...]
    mounts: tuple[MountInfo, ...]
    networks: tuple[NetworkMembership, ...]
    env: tuple[tuple[str, str], ...]
    labels: tuple[tuple[str, str], ...]
    health: str | None
    compose_project: str | None
    compose_service: str | None
    compose_config_files: str | None
    restart_count: int
    created: str
    started_at: str
    command: tuple[str, ...] | None
    entrypoint: tuple[str, ...] | None
    oom_killed: bool
    user: str | None
    restart_policy: str | None
    privileged: bool
    network_mode: str | None
    # Compose generator fields
    healthcheck: HealthcheckConfig | None
    devices: tuple[str, ...]
    cap_add: tuple[str, ...]
    cap_drop: tuple[str, ...]
    runtime: str | None
    shm_size: int | None
    tmpfs: tuple[str, ...]
    sysctls: tuple[tuple[str, str], ...]
    security_opt: tuple[str, ...]
    pid_mode: str | None
    dns: tuple[str, ...]
    dns_search: tuple[str, ...]
    extra_hosts: tuple[str, ...]
    group_add: tuple[str, ...]
    hostname: str | None
    stop_signal: str | None
    stop_grace_period: int | None
    mem_limit: int | None
    cpus: float | None
    init: bool
    log_driver: str | None
    log_opts: tuple[tuple[str, str], ...]
    read_only: bool
    image_created: str | None


@dataclass(frozen=True)
class DaemonInfo:
    """Docker daemon configuration relevant to security."""

    live_restore: bool
    default_log_driver: str
    default_log_opts: tuple[tuple[str, str], ...]
    storage_driver: str
    security_options: tuple[str, ...]
    cgroup_driver: str
    server_version: str


@dataclass(frozen=True)
class DockerEnvironment:
    """Complete snapshot of a Docker host's environment."""

    containers: tuple[ContainerInfo, ...]
    generated_at: str
    docker_version: str
    warnings: tuple[str, ...] = ()
    daemon: DaemonInfo | None = None


def make_container(
    *,
    name: str,
    id: str,
    status: str,
    image: str,
    image_id: str,
    image_digest: str | None = None,
    ports: list[PortBinding] | tuple[PortBinding, ...] = (),
    mounts: list[MountInfo] | tuple[MountInfo, ...] = (),
    networks: list[NetworkMembership] | tuple[NetworkMembership, ...] = (),
    env: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
    labels: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
    health: str | None = None,
    compose_project: str | None = None,
    compose_service: str | None = None,
    compose_config_files: str | None = None,
    restart_count: int = 0,
    created: str = "",
    started_at: str = "",
    command: list[str] | tuple[str, ...] | None = None,
    entrypoint: list[str] | tuple[str, ...] | None = None,
    oom_killed: bool = False,
    user: str | None = None,
    restart_policy: str | None = None,
    privileged: bool = False,
    network_mode: str | None = None,
    healthcheck: HealthcheckConfig | None = None,
    devices: list[str] | tuple[str, ...] = (),
    cap_add: list[str] | tuple[str, ...] = (),
    cap_drop: list[str] | tuple[str, ...] = (),
    runtime: str | None = None,
    shm_size: int | None = None,
    tmpfs: list[str] | tuple[str, ...] = (),
    sysctls: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
    security_opt: list[str] | tuple[str, ...] = (),
    pid_mode: str | None = None,
    dns: list[str] | tuple[str, ...] = (),
    dns_search: list[str] | tuple[str, ...] = (),
    extra_hosts: list[str] | tuple[str, ...] = (),
    group_add: list[str] | tuple[str, ...] = (),
    hostname: str | None = None,
    stop_signal: str | None = None,
    stop_grace_period: int | None = None,
    mem_limit: int | None = None,
    cpus: float | None = None,
    init: bool = False,
    log_driver: str | None = None,
    log_opts: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
    read_only: bool = False,
    image_created: str | None = None,
) -> ContainerInfo:
    """Construct a ContainerInfo with sorted collections.

    This is the only correct way to build a ContainerInfo — it ensures
    all collections are sorted for deterministic output.
    """
    return ContainerInfo(
        name=name,
        id=id,
        status=status,
        image=image,
        image_id=image_id,
        image_digest=image_digest,
        ports=tuple(sorted(ports, key=lambda p: (p.container_port, p.protocol))),
        mounts=tuple(sorted(mounts, key=lambda m: m.destination)),
        networks=tuple(sorted(networks, key=lambda n: n.name)),
        env=tuple(sorted(env, key=lambda e: e[0])),
        labels=tuple(sorted(labels, key=lambda lbl: lbl[0])),
        health=health,
        compose_project=compose_project,
        compose_service=compose_service,
        compose_config_files=compose_config_files,
        restart_count=restart_count,
        created=created,
        started_at=started_at,
        command=tuple(command) if command else None,
        entrypoint=tuple(entrypoint) if entrypoint else None,
        oom_killed=oom_killed,
        user=user,
        restart_policy=restart_policy,
        privileged=privileged,
        network_mode=network_mode,
        healthcheck=healthcheck,
        devices=tuple(sorted(devices)),
        cap_add=tuple(sorted(cap_add)),
        cap_drop=tuple(sorted(cap_drop)),
        runtime=runtime,
        shm_size=shm_size,
        tmpfs=tuple(sorted(tmpfs)),
        sysctls=tuple(sorted(sysctls, key=lambda s: s[0])),
        security_opt=tuple(sorted(security_opt)),
        pid_mode=pid_mode,
        dns=tuple(dns),  # preserve order (priority matters)
        dns_search=tuple(dns_search),
        extra_hosts=tuple(sorted(extra_hosts)),
        group_add=tuple(sorted(group_add)),
        hostname=hostname,
        stop_signal=stop_signal,
        stop_grace_period=stop_grace_period,
        mem_limit=mem_limit,
        cpus=cpus,
        init=init,
        log_driver=log_driver,
        log_opts=tuple(sorted(log_opts, key=lambda o: o[0])),
        read_only=read_only,
        image_created=image_created,
    )


def make_environment(
    *,
    containers: list[ContainerInfo] | tuple[ContainerInfo, ...],
    generated_at: str,
    docker_version: str,
    warnings: list[str] | tuple[str, ...] = (),
    daemon: DaemonInfo | None = None,
) -> DockerEnvironment:
    """Construct a DockerEnvironment with containers sorted by name."""
    return DockerEnvironment(
        containers=tuple(sorted(containers, key=lambda c: c.name)),
        generated_at=generated_at,
        docker_version=docker_version,
        warnings=tuple(warnings),
        daemon=daemon,
    )


def filter_by_project(
    env: DockerEnvironment,
    project: str,
) -> DockerEnvironment:
    """Return a new DockerEnvironment with only containers from the given compose project."""
    filtered = [c for c in env.containers if c.compose_project == project]
    return DockerEnvironment(
        containers=tuple(filtered),
        generated_at=env.generated_at,
        docker_version=env.docker_version,
        warnings=env.warnings,
    )
