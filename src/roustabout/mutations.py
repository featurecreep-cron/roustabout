"""Container mutation operations — start, stop, restart, recreate.

This is the only module that calls docker-py mutation methods.
Only gateway.py imports this module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, cast

import docker.errors as _docker_errors

from roustabout.redactor import sanitize
from roustabout.session import DockerSession


def _docker(docker: DockerSession) -> Any:
    """Cast DockerSession.client for docker-py API access."""
    return cast(Any, docker.client)

logger = logging.getLogger(__name__)


# Result type


@dataclass(frozen=True)
class MutationResult:
    """Outcome of a mutation operation."""

    success: bool
    action: str
    target: str
    error: str | None = None
    error_type: str | None = None  # connection_error, not_found, mutation_error


# Individual operations


def _stop(docker: DockerSession, target: str) -> MutationResult:
    container = _docker(docker).containers.get(target)
    container.stop()
    return MutationResult(success=True, action="stop", target=target)


def _start(docker: DockerSession, target: str) -> MutationResult:
    container = _docker(docker).containers.get(target)
    container.start()
    return MutationResult(success=True, action="start", target=target)


def _restart(docker: DockerSession, target: str) -> MutationResult:
    container = _docker(docker).containers.get(target)
    container.restart()
    return MutationResult(success=True, action="restart", target=target)


def _recreate(docker: DockerSession, target: str) -> MutationResult:
    """Recreate a container: stop, remove, create new with same config.

    Uses the container's image (pulling latest tag) and preserves
    name, volumes, networks, ports, env, and labels.
    """
    container = _docker(docker).containers.get(target)
    config: dict[str, Any] = container.attrs
    host_config: dict[str, Any] = config.get("HostConfig", {})
    network_config: dict[str, Any] = config.get("NetworkSettings", {}).get("Networks", {})

    image: str = config["Config"]["Image"]
    name: str = config["Name"].lstrip("/")

    # Build create kwargs from existing config
    create_kwargs: dict[str, Any] = {
        "image": image,
        "name": name,
        "detach": True,
        "environment": config["Config"].get("Env") or [],
        "labels": config["Config"].get("Labels") or {},
        "volumes": host_config.get("Binds") or [],
        "ports": _rebuild_port_bindings(host_config.get("PortBindings") or {}),
        "restart_policy": host_config.get("RestartPolicy") or {"Name": "no"},
    }

    # Preserve network mode if set
    net_mode = host_config.get("NetworkMode")
    if net_mode and net_mode != "default":
        create_kwargs["network_mode"] = net_mode

    # Stop and remove
    container.stop()
    container.remove()

    # Create and start
    new_container = _docker(docker).containers.create(**create_kwargs)

    # Reconnect to non-default networks (skip the primary network from network_mode)
    special_modes = ("default", "bridge", "host", "none")
    primary_net = net_mode if net_mode and net_mode not in special_modes else "bridge"
    for net_name, net_conf in network_config.items():
        if net_name == primary_net:
            continue  # already connected via network_mode or default
        try:
            network = _docker(docker).networks.get(net_name)
            network.connect(
                new_container,
                aliases=net_conf.get("Aliases") or [],
            )
        except _docker_errors.APIError:
            logger.warning("Could not reconnect to network %s", net_name)

    new_container.start()
    return MutationResult(success=True, action="recreate", target=target)


def _rebuild_port_bindings(
    bindings: dict[str, Any],
) -> dict[str, list[tuple[str, str]] | None]:
    """Convert Docker API PortBindings format to docker-py ports format."""
    result: dict[str, list[tuple[str, str]] | None] = {}
    for container_port, host_bindings in bindings.items():
        if not host_bindings:
            result[container_port] = None
            continue
        result[container_port] = [
            (b.get("HostIp", ""), b.get("HostPort", "")) for b in host_bindings
        ]
    return result


# Dispatch
_DISPATCH = {
    "start": _start,
    "stop": _stop,
    "restart": _restart,
    "recreate": _recreate,
}


def execute(
    docker: DockerSession,
    action: str,
    target: str,
    *,
    new_image: str | None = None,
) -> MutationResult:
    """Execute a container mutation.

    Routes to the appropriate handler based on action.
    All docker-py mutation calls are contained within this module.
    """
    handler = _DISPATCH.get(action)
    if handler is None:
        return MutationResult(
            success=False,
            action=action,
            target=target,
            error=f"Unknown mutation action: {action!r}",
            error_type="mutation_error",
        )

    try:
        return handler(docker, target)
    except _docker_errors.NotFound:
        return MutationResult(
            success=False,
            action=action,
            target=target,
            error=f"Container {target!r} not found",
            error_type="not_found",
        )
    except ConnectionError as e:
        return MutationResult(
            success=False,
            action=action,
            target=target,
            error=sanitize(str(e)),
            error_type="connection_error",
        )
    except _docker_errors.APIError as e:
        return MutationResult(
            success=False,
            action=action,
            target=target,
            error=sanitize(str(e)),
            error_type="mutation_error",
        )
