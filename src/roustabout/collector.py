"""Collect Docker environment data via docker-py.

Reads the Docker socket, inspects every container, and returns
a DockerEnvironment with sorted, frozen model instances.
"""

from __future__ import annotations

import logging
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

logger = logging.getLogger(__name__)


def collect(client: docker.DockerClient) -> DockerEnvironment:
    """Snapshot the entire Docker environment into model objects.

    Does NOT catch DockerException from client.containers.list() — if the
    daemon is unreachable, that's a hard failure the caller must handle.
    Per-container failures are caught and reported as warnings.
    """
    raw_containers = client.containers.list(all=True)

    containers: list[ContainerInfo] = []
    warnings: list[str] = []

    for raw in raw_containers:
        try:
            containers.append(_collect_container(raw))
        except Exception as exc:
            name = getattr(raw, "name", "unknown")
            msg = f"container '{name}' skipped: {exc}"
            logger.warning(msg)
            warnings.append(msg)

    version_info = client.version()

    return make_environment(
        containers=containers,
        generated_at=datetime.now(timezone.utc).isoformat(),
        docker_version=version_info.get("Version", "unknown"),
        warnings=warnings,
    )


def _collect_container(container) -> ContainerInfo:
    """Extract a ContainerInfo from a docker-py Container object."""
    attrs = container.attrs
    config = attrs.get("Config", {})
    state = attrs.get("State", {})
    network_settings = attrs.get("NetworkSettings", {})

    # docker-py sometimes retains the API's leading slash on container names
    name = container.name
    if name.startswith("/"):
        name = name[1:]

    # container.image is None when the image has been deleted
    image = container.image
    if image is not None:
        image_tag = image.tags[0] if image.tags else config.get("Image", "unknown")
        image_id = image.id
        repo_digests = image.attrs.get("RepoDigests", [])
        image_digest = repo_digests[0] if repo_digests else None
    else:
        image_tag = config.get("Image", "unknown")
        image_id = "unknown"
        image_digest = None

    # NetworkSettings.Ports reflects actual runtime bindings, not just EXPOSE
    ports = _collect_ports(network_settings.get("Ports") or {})
    mounts = _collect_mounts(attrs.get("Mounts") or [])
    networks = _collect_networks(network_settings.get("Networks") or {})
    env = _parse_env(config.get("Env") or [])

    raw_labels = config.get("Labels") or {}
    labels = list(raw_labels.items())

    health_info = state.get("Health")
    health = health_info.get("Status") if health_info else None

    compose_project = raw_labels.get("com.docker.compose.project")
    compose_service = raw_labels.get("com.docker.compose.service")
    compose_config = raw_labels.get("com.docker.compose.project.config_files")

    cmd = config.get("Cmd")
    command = " ".join(cmd) if cmd else None
    ep = config.get("Entrypoint")
    entrypoint = " ".join(ep) if ep else None

    user = config.get("User") or None

    host_config = attrs.get("HostConfig", {})
    restart_info = host_config.get("RestartPolicy", {})
    restart_policy = restart_info.get("Name") or None

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
        user=user,
        restart_policy=restart_policy,
    )


def _collect_ports(ports_dict: dict) -> list[PortBinding]:
    port_bindings = []
    for port_proto, host_bindings in ports_dict.items():
        if not host_bindings:
            continue
        parts = port_proto.split("/")
        try:
            container_port = int(parts[0])
        except ValueError:
            logger.warning("Skipping malformed port key: %s", port_proto)
            continue
        protocol = parts[1] if len(parts) > 1 else "tcp"
        for binding in host_bindings:
            port_bindings.append(
                PortBinding(
                    container_port=container_port,
                    protocol=protocol,
                    host_ip=binding.get("HostIp", ""),
                    host_port=binding.get("HostPort", ""),
                )
            )
    return port_bindings


def _collect_mounts(mounts_list: list[dict]) -> list[MountInfo]:
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
    memberships = []
    for net_name, net_info in networks_dict.items():
        aliases = net_info.get("Aliases") or []
        memberships.append(
            NetworkMembership(
                name=net_name,
                ip_address=net_info.get("IPAddress", ""),
                aliases=tuple(sorted(aliases)),
            )
        )
    return memberships


def _parse_env(env_list: list[str]) -> list[tuple[str, str]]:
    """Parse KEY=VALUE environment strings into tuples.

    Handles values containing = signs correctly.
    """
    pairs = []
    for entry in env_list:
        if "=" in entry:
            key, _, value = entry.partition("=")
            pairs.append((key, value))
        else:
            pairs.append((entry, ""))
    return pairs
