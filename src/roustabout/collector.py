"""Collect Docker environment data via docker-py.

Reads the Docker socket, inspects every container, and returns
a DockerEnvironment with sorted, frozen model instances.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from roustabout.models import (
    MountInfo,
    NetworkMembership,
    PortBinding,
    make_container,
    make_environment,
)

if TYPE_CHECKING:
    import docker

    from roustabout.models import ContainerInfo, DockerEnvironment


def collect(client: docker.DockerClient) -> DockerEnvironment:
    """Snapshot the entire Docker environment into model objects."""
    raw_containers = client.containers.list(all=True)
    containers = [_collect_container(c) for c in raw_containers]

    version_info = client.version()

    return make_environment(
        containers=containers,
        generated_at=datetime.now(timezone.utc).isoformat(),
        docker_version=version_info.get("Version", "unknown"),
    )


def _collect_container(container) -> ContainerInfo:
    """Extract a ContainerInfo from a docker-py Container object."""
    attrs = container.attrs
    config = attrs.get("Config", {})
    state = attrs.get("State", {})
    network_settings = attrs.get("NetworkSettings", {})

    # Name: strip leading /
    name = container.name
    if name.startswith("/"):
        name = name[1:]

    # Image info
    image = container.image
    image_tag = image.tags[0] if image.tags else config.get("Image", "unknown")
    image_id = image.id
    repo_digests = image.attrs.get("RepoDigests", [])
    image_digest = repo_digests[0] if repo_digests else None

    # Ports from NetworkSettings.Ports (runtime truth)
    ports = _collect_ports(network_settings.get("Ports") or {})

    # Mounts
    mounts = _collect_mounts(attrs.get("Mounts") or [])

    # Networks
    networks = _collect_networks(network_settings.get("Networks") or {})

    # Environment variables
    env = _parse_env(config.get("Env") or [])

    # Labels
    raw_labels = config.get("Labels") or {}
    labels = list(raw_labels.items())

    # Health
    health_info = state.get("Health")
    health = health_info["Status"] if health_info else None

    # Compose metadata
    compose_project = raw_labels.get("com.docker.compose.project")
    compose_service = raw_labels.get("com.docker.compose.service")
    compose_config = raw_labels.get("com.docker.compose.project.config_files")

    # Command / entrypoint
    cmd = config.get("Cmd")
    command = " ".join(cmd) if cmd else None
    ep = config.get("Entrypoint")
    entrypoint = " ".join(ep) if ep else None

    return make_container(
        name=name,
        id=container.short_id,
        status=state.get("Status", container.status),
        image=image_tag,
        image_id=image_id,
        image_digest=image_digest,
        ports=ports,
        mounts=mounts,
        networks=networks,
        env=env,
        labels=labels,
        health=health,
        compose_project=compose_project,
        compose_service=compose_service,
        compose_config_files=compose_config,
        restart_count=attrs.get("RestartCount", 0),
        created=attrs.get("Created", ""),
        started_at=state.get("StartedAt", ""),
        command=command,
        entrypoint=entrypoint,
        oom_killed=state.get("OOMKilled", False),
    )


def _collect_ports(ports_dict: dict) -> list[PortBinding]:
    """Parse NetworkSettings.Ports into PortBinding objects."""
    result = []
    for port_proto, bindings in ports_dict.items():
        if not bindings:
            continue
        parts = port_proto.split("/")
        container_port = int(parts[0])
        protocol = parts[1] if len(parts) > 1 else "tcp"
        for binding in bindings:
            result.append(
                PortBinding(
                    container_port=container_port,
                    protocol=protocol,
                    host_ip=binding.get("HostIp", ""),
                    host_port=binding.get("HostPort", ""),
                )
            )
    return result


def _collect_mounts(mounts_list: list[dict]) -> list[MountInfo]:
    """Parse Mounts array into MountInfo objects."""
    return [
        MountInfo(
            source=m.get("Source", ""),
            destination=m.get("Destination", ""),
            mode=m.get("Mode", ""),
            type=m.get("Type", ""),
        )
        for m in mounts_list
    ]


def _collect_networks(networks_dict: dict) -> list[NetworkMembership]:
    """Parse NetworkSettings.Networks into NetworkMembership objects."""
    result = []
    for net_name, net_info in networks_dict.items():
        aliases = net_info.get("Aliases") or []
        result.append(
            NetworkMembership(
                name=net_name,
                ip_address=net_info.get("IPAddress", ""),
                aliases=tuple(sorted(aliases)),
            )
        )
    return result


def _parse_env(env_list: list[str]) -> list[tuple[str, str]]:
    """Parse KEY=VALUE environment strings into tuples.

    Handles values containing = signs correctly.
    """
    result = []
    for entry in env_list:
        if "=" in entry:
            key, _, value = entry.partition("=")
            result.append((key, value))
        else:
            result.append((entry, ""))
    return result
