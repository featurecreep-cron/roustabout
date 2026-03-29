"""Network inspection — passive and active network diagnostics.

Passive inspection (OBSERVE): Docker API data — networks, IPs, aliases, ports.
Active probes (ELEVATE): DNS resolution and connectivity checks via exec.

LLD: docs/roustabout/designs/026-network-inspection.md
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import docker.errors

from roustabout.models import ContainerInfo, DockerEnvironment, NetworkMembership
from roustabout.redactor import sanitize
from roustabout.session import DockerSession

# --- Passive inspection data types (OBSERVE tier) ---


@dataclass(frozen=True)
class NetworkMember:
    """A container connected to a Docker network."""

    container_name: str
    container_id: str
    ipv4_address: str | None
    ipv6_address: str | None
    mac_address: str | None
    aliases: tuple[str, ...]


@dataclass(frozen=True)
class NetworkDetail:
    """Detailed info about a Docker network."""

    name: str
    id: str
    driver: str
    scope: str
    subnet: str | None
    gateway: str | None
    internal: bool
    containers: tuple[NetworkMember, ...]


@dataclass(frozen=True)
class PortListenerInfo:
    """Port exposure for a container."""

    container_port: int
    protocol: str
    host_ip: str | None
    host_port: str | None
    exposed: bool
    published: bool


@dataclass(frozen=True)
class ContainerNetworkView:
    """Complete network view for a single container."""

    container_name: str
    networks: tuple[NetworkMembership, ...]
    published_ports: tuple[PortListenerInfo, ...]
    dns_servers: tuple[str, ...]
    dns_search: tuple[str, ...]
    extra_hosts: tuple[str, ...]
    network_mode: str | None
    network_details: tuple[NetworkDetail, ...]


# --- Active probe data types (ELEVATE tier) ---


@dataclass(frozen=True)
class DNSProbeResult:
    """Result of resolving a name from inside a container."""

    source: str
    query: str
    resolved: bool
    addresses: tuple[str, ...]
    error: str | None = None


@dataclass(frozen=True)
class ConnectivityProbeResult:
    """Result of testing TCP connectivity between containers."""

    source: str
    target: str
    port: int
    reachable: bool
    latency_ms: float | None = None
    error: str | None = None


# --- Input validation ---

_SAFE_HOST_RE = re.compile(r"^[a-zA-Z0-9._:%-]+$")


def _validate_host(value: str, param_name: str) -> None:
    """Reject hostnames/IPs containing shell metacharacters."""
    if not value or not _SAFE_HOST_RE.match(value):
        raise ValueError(
            f"{param_name} contains invalid characters: {value!r}. "
            f"Allowed: alphanumeric, dots, hyphens, colons, underscores."
        )


# --- Internal helpers ---


def _collect_port_info(attrs: dict[str, Any]) -> tuple[PortListenerInfo, ...]:
    """Extract port info from container attrs dict."""
    exposed_raw = attrs.get("Config", {}).get("ExposedPorts", {}) or {}
    exposed_ports: set[tuple[int, str]] = set()
    for key in exposed_raw:
        port_str, _, proto = key.partition("/")
        try:
            exposed_ports.add((int(port_str), proto or "tcp"))
        except ValueError:
            continue

    port_bindings = attrs.get("NetworkSettings", {}).get("Ports", {}) or {}

    results: list[PortListenerInfo] = []
    seen: set[tuple[int, str]] = set()

    for key, bindings in port_bindings.items():
        port_str, _, proto = key.partition("/")
        try:
            port_num = int(port_str)
        except ValueError:
            continue
        proto = proto or "tcp"
        seen.add((port_num, proto))

        if bindings:
            for binding in bindings:
                results.append(
                    PortListenerInfo(
                        container_port=port_num,
                        protocol=proto,
                        host_ip=binding.get("HostIp") or None,
                        host_port=binding.get("HostPort") or None,
                        exposed=(port_num, proto) in exposed_ports,
                        published=True,
                    )
                )
        else:
            results.append(
                PortListenerInfo(
                    container_port=port_num,
                    protocol=proto,
                    host_ip=None,
                    host_port=None,
                    exposed=(port_num, proto) in exposed_ports,
                    published=False,
                )
            )

    for port_num, proto in exposed_ports:
        if (port_num, proto) not in seen:
            results.append(
                PortListenerInfo(
                    container_port=port_num,
                    protocol=proto,
                    host_ip=None,
                    host_port=None,
                    exposed=True,
                    published=False,
                )
            )

    return tuple(sorted(results, key=lambda p: (p.container_port, p.protocol)))


# --- Passive inspection (OBSERVE tier) ---


def inspect_container_network(
    client: Any,
    target: str,
) -> ContainerNetworkView:
    """Get complete network view for a container. OBSERVE tier.

    Raises docker.errors.NotFound if container doesn't exist.
    """
    container = client.containers.get(target)
    attrs = container.attrs

    network_settings = attrs.get("NetworkSettings", {})
    networks_raw = network_settings.get("Networks", {})

    host_config = attrs.get("HostConfig", {})
    dns = tuple(sanitize(d) for d in (host_config.get("Dns") or []))
    dns_search = tuple(sanitize(d) for d in (host_config.get("DnsSearch") or []))
    extra_hosts = tuple(sanitize(h) for h in (host_config.get("ExtraHosts") or []))
    network_mode = host_config.get("NetworkMode")

    memberships = []
    for net_name, net_info in networks_raw.items():
        aliases = tuple(net_info.get("Aliases") or [])
        memberships.append(
            NetworkMembership(
                name=net_name,
                ip_address=net_info.get("IPAddress", ""),
                aliases=aliases,
            )
        )

    network_details = []
    for membership in memberships:
        try:
            detail = inspect_network(client, membership.name)
            network_details.append(detail)
        except docker.errors.NotFound:
            pass

    ports = _collect_port_info(attrs)

    return ContainerNetworkView(
        container_name=sanitize(container.name),
        networks=tuple(memberships),
        published_ports=ports,
        dns_servers=dns,
        dns_search=dns_search,
        extra_hosts=extra_hosts,
        network_mode=network_mode,
        network_details=tuple(network_details),
    )


def inspect_network(
    client: Any,
    network_name: str,
) -> NetworkDetail:
    """Get detailed info about a Docker network. OBSERVE tier.

    Raises docker.errors.NotFound if network doesn't exist.
    """
    network = client.networks.get(network_name)
    attrs = network.attrs

    ipam = attrs.get("IPAM", {})
    ipam_config = ipam.get("Config", [])
    first_config = ipam_config[0] if ipam_config else {}
    subnet = first_config.get("Subnet")
    gateway_ip = first_config.get("Gateway")

    containers_raw = attrs.get("Containers", {})
    members = []
    for cid, cinfo in containers_raw.items():
        members.append(
            NetworkMember(
                container_name=sanitize(cinfo.get("Name", "")),
                container_id=cid[:12],
                ipv4_address=cinfo.get("IPv4Address", "").split("/")[0] or None,
                ipv6_address=cinfo.get("IPv6Address", "").split("/")[0] or None,
                mac_address=cinfo.get("MacAddress"),
                aliases=(),
            )
        )

    return NetworkDetail(
        name=sanitize(attrs.get("Name", network_name)),
        id=attrs.get("Id", "")[:12],
        driver=attrs.get("Driver", "unknown"),
        scope=attrs.get("Scope", "local"),
        subnet=subnet,
        gateway=gateway_ip,
        internal=attrs.get("Internal", False),
        containers=tuple(sorted(members, key=lambda m: m.container_name)),
    )


def list_container_ports(
    client: Any,
    target: str,
) -> tuple[PortListenerInfo, ...]:
    """Get port exposure details for a container. OBSERVE tier.

    Raises docker.errors.NotFound if container doesn't exist.
    """
    container = client.containers.get(target)
    return _collect_port_info(container.attrs)


# --- Active probes (ELEVATE tier) ---

_IP_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]{3,})")


def _parse_dns_output(output: str, hostname: str) -> tuple[str, ...]:
    """Extract IP addresses from getent or nslookup output."""
    addresses: list[str] = []
    for line in output.strip().splitlines():
        for match in _IP_PATTERN.finditer(line):
            addr = match.group(1)
            if addr not in ("127.0.0.1", "::1") or hostname in ("localhost", "127.0.0.1"):
                addresses.append(addr)
    return tuple(dict.fromkeys(addresses))


def probe_dns(
    docker_session: DockerSession,
    source_container: str,
    hostname: str,
) -> DNSProbeResult:
    """Resolve a hostname from inside a container. ELEVATE tier (uses exec)."""
    from roustabout.exec import ExecCommand
    from roustabout.exec import execute as exec_execute

    _validate_host(hostname, "hostname")

    result = exec_execute(
        docker_session,
        ExecCommand(target=source_container, command=("getent", "hosts", hostname), timeout=10),
    )

    if not result.success:
        result = exec_execute(
            docker_session,
            ExecCommand(target=source_container, command=("nslookup", hostname), timeout=10),
        )

    if result.success and result.stdout:
        addresses = _parse_dns_output(result.stdout, hostname)
        return DNSProbeResult(
            source=source_container,
            query=hostname,
            resolved=True,
            addresses=addresses,
        )

    return DNSProbeResult(
        source=source_container,
        query=hostname,
        resolved=False,
        addresses=(),
        error=result.stderr or result.error or "DNS resolution failed",
    )


def probe_connectivity(
    docker_session: DockerSession,
    source_container: str,
    target_host: str,
    port: int,
    timeout: int = 5,
) -> ConnectivityProbeResult:
    """Test TCP connectivity from one container to a host:port. ELEVATE tier."""
    from roustabout.exec import ExecCommand
    from roustabout.exec import execute as exec_execute

    _validate_host(target_host, "target_host")

    # Approach 1: bash /dev/tcp
    cmd = (
        "bash",
        "-c",
        f"echo > /dev/tcp/{target_host}/{port} && echo CONNECTED || echo FAILED",
    )
    result = exec_execute(
        docker_session,
        ExecCommand(target=source_container, command=cmd, timeout=timeout + 2),
    )

    if result.success and "CONNECTED" in result.stdout:
        return ConnectivityProbeResult(
            source=source_container,
            target=target_host,
            port=port,
            reachable=True,
            latency_ms=None,
        )

    # Approach 2: nc/ncat
    cmd = ("nc", "-z", "-w", str(timeout), target_host, str(port))
    result = exec_execute(
        docker_session,
        ExecCommand(target=source_container, command=cmd, timeout=timeout + 2),
    )

    if result.success:
        return ConnectivityProbeResult(
            source=source_container,
            target=target_host,
            port=port,
            reachable=True,
            latency_ms=None,
        )

    return ConnectivityProbeResult(
        source=source_container,
        target=target_host,
        port=port,
        reachable=False,
        latency_ms=None,
        error=result.stderr or result.error or "Connection failed",
    )


# --- Connectivity checks (model layer / OBSERVE tier) ---
#
# Topology-based reachability analysis. Operates on the model layer — no
# Docker API calls. Moved here from net_check.py.


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

    Returns results for every unique pair (A->B, not both A->B and B->A).
    """
    results: list[ConnectivityResult] = []
    containers = sorted(env.containers, key=lambda c: c.name)
    for i, source in enumerate(containers):
        for target_c in containers[i + 1 :]:
            results.append(check_connectivity(env, source.name, target_c.name))
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
