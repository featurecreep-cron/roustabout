"""Data models for Docker environment documentation.

Frozen dataclasses with sorted tuples for deterministic output.
All collections are sorted at construction time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


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
class ContainerInfo:
    """Complete snapshot of a single container's state."""

    name: str
    id: str
    status: str
    image: str
    image_id: str
    image_digest: Optional[str]
    ports: tuple[PortBinding, ...]
    mounts: tuple[MountInfo, ...]
    networks: tuple[NetworkMembership, ...]
    env: tuple[tuple[str, str], ...]
    labels: tuple[tuple[str, str], ...]
    health: Optional[str]
    compose_project: Optional[str]
    compose_service: Optional[str]
    compose_config_files: Optional[str]
    restart_count: int
    created: str
    started_at: str
    command: Optional[str]
    entrypoint: Optional[str]
    oom_killed: bool


@dataclass(frozen=True)
class DockerEnvironment:
    """Complete snapshot of a Docker host's environment."""

    containers: tuple[ContainerInfo, ...]
    generated_at: str
    docker_version: str


def make_container(
    *,
    name: str,
    id: str,
    status: str,
    image: str,
    image_id: str,
    image_digest: Optional[str] = None,
    ports: list[PortBinding] | tuple[PortBinding, ...] = (),
    mounts: list[MountInfo] | tuple[MountInfo, ...] = (),
    networks: list[NetworkMembership] | tuple[NetworkMembership, ...] = (),
    env: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
    labels: list[tuple[str, str]] | tuple[tuple[str, str], ...] = (),
    health: Optional[str] = None,
    compose_project: Optional[str] = None,
    compose_service: Optional[str] = None,
    compose_config_files: Optional[str] = None,
    restart_count: int = 0,
    created: str = "",
    started_at: str = "",
    command: Optional[str] = None,
    entrypoint: Optional[str] = None,
    oom_killed: bool = False,
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
        labels=tuple(sorted(labels, key=lambda l: l[0])),
        health=health,
        compose_project=compose_project,
        compose_service=compose_service,
        compose_config_files=compose_config_files,
        restart_count=restart_count,
        created=created,
        started_at=started_at,
        command=command,
        entrypoint=entrypoint,
        oom_killed=oom_killed,
    )


def make_environment(
    *,
    containers: list[ContainerInfo] | tuple[ContainerInfo, ...],
    generated_at: str,
    docker_version: str,
) -> DockerEnvironment:
    """Construct a DockerEnvironment with containers sorted by name."""
    return DockerEnvironment(
        containers=tuple(sorted(containers, key=lambda c: c.name)),
        generated_at=generated_at,
        docker_version=docker_version,
    )
