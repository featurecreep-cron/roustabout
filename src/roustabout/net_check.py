"""Network connectivity analysis between Docker containers.

Determines whether two containers can communicate based on shared
Docker networks, network mode, and published ports. Operates on the
model layer — no Docker API calls.
"""

from __future__ import annotations

from dataclasses import dataclass

from roustabout.models import ContainerInfo, DockerEnvironment


@dataclass(frozen=True)
class ConnectivityResult:
    """Result of a network connectivity check between two containers."""

    source: str
    target: str
    reachable: bool
    shared_networks: tuple[str, ...]
    reason: str


def check_connectivity(
    env: DockerEnvironment,
    source_name: str,
    target_name: str,
) -> ConnectivityResult:
    """Check if source container can reach target container.

    Checks shared Docker networks, host network mode, and container
    network mode sharing. Does not verify actual DNS resolution or
    firewall rules — this is a topology check only.
    """
    source = _find_container(env, source_name)
    target = _find_container(env, target_name)

    if source is None:
        return ConnectivityResult(
            source=source_name,
            target=target_name,
            reachable=False,
            shared_networks=(),
            reason=f"container '{source_name}' not found",
        )

    if target is None:
        return ConnectivityResult(
            source=source_name,
            target=target_name,
            reachable=False,
            shared_networks=(),
            reason=f"container '{target_name}' not found",
        )

    # Host network mode — can reach anything on the host
    if source.network_mode == "host" or target.network_mode == "host":
        return ConnectivityResult(
            source=source_name,
            target=target_name,
            reachable=True,
            shared_networks=(),
            reason="host network mode (shares host network stack)",
        )

    # Container network mode — shares another container's network stack
    source_shares = _shares_network_with(source, target, env)
    if source_shares:
        return ConnectivityResult(
            source=source_name,
            target=target_name,
            reachable=True,
            shared_networks=(),
            reason=source_shares,
        )

    target_shares = _shares_network_with(target, source, env)
    if target_shares:
        return ConnectivityResult(
            source=source_name,
            target=target_name,
            reachable=True,
            shared_networks=(),
            reason=target_shares,
        )

    # Shared Docker networks
    source_nets = {n.name for n in source.networks}
    target_nets = {n.name for n in target.networks}
    shared = sorted(source_nets & target_nets)

    if shared:
        return ConnectivityResult(
            source=source_name,
            target=target_name,
            reachable=True,
            shared_networks=tuple(shared),
            reason=f"shared network{'s' if len(shared) > 1 else ''}: {', '.join(shared)}",
        )

    return ConnectivityResult(
        source=source_name,
        target=target_name,
        reachable=False,
        shared_networks=(),
        reason="no shared networks",
    )


def check_all_connectivity(env: DockerEnvironment) -> list[ConnectivityResult]:
    """Check connectivity between all container pairs.

    Returns results for every unique pair (A→B, not both A→B and B→A).
    """
    results: list[ConnectivityResult] = []
    containers = sorted(env.containers, key=lambda c: c.name)
    for i, source in enumerate(containers):
        for target in containers[i + 1 :]:
            results.append(check_connectivity(env, source.name, target.name))
    return results


def _find_container(env: DockerEnvironment, name: str) -> ContainerInfo | None:
    """Find a container by name."""
    for c in env.containers:
        if c.name == name:
            return c
    return None


def _shares_network_with(a: ContainerInfo, b: ContainerInfo, env: DockerEnvironment) -> str | None:
    """Check if container a shares network stack with b via network_mode.

    Returns a description string if they share, None otherwise.
    """
    if not a.network_mode or not a.network_mode.startswith("container:"):
        return None

    dep_id = a.network_mode.split(":", 1)[1]
    # dep_id could be a container ID or name
    if dep_id == b.id or dep_id.startswith(b.id[:12]):
        return f"{a.name} shares network stack with {b.name} (network_mode: container:)"

    # Check if dep_id resolves to b's name
    for c in env.containers:
        if (c.id == dep_id or c.id.startswith(dep_id)) and c.name == b.name:
            return f"{a.name} shares network stack with {b.name} (network_mode: container:)"

    return None
