"""Collect Docker environment data via docker-py.

Reads the Docker socket, inspects every container, and returns
a DockerEnvironment with sorted, frozen model instances.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from roustabout.models import (
    DaemonInfo,
    HealthcheckConfig,
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
    daemon = _collect_daemon_info(client)

    return make_environment(
        containers=containers,
        generated_at=datetime.now(UTC).isoformat(),
        docker_version=version_info.get("Version", "unknown"),
        warnings=warnings,
        daemon=daemon,
    )


def _collect_container(container: Any) -> ContainerInfo:
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
        image_created = image.attrs.get("Created")
    else:
        image_tag = config.get("Image", "unknown")
        image_id = "unknown"
        image_digest = None
        image_created = None

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

    command = config.get("Cmd") or None
    entrypoint = config.get("Entrypoint") or None

    user = config.get("User") or None

    host_config = attrs.get("HostConfig", {})
    restart_info = host_config.get("RestartPolicy", {})
    restart_policy = restart_info.get("Name") or None
    privileged = host_config.get("Privileged", False)
    network_mode = host_config.get("NetworkMode") or None

    # Healthcheck config (the command/interval, not the status)
    healthcheck = _collect_healthcheck(config.get("Healthcheck"))

    # Device mappings (GPU passthrough, etc.)
    raw_devices = host_config.get("Devices") or []
    devices = [
        f"{d['PathOnHost']}:{d['PathInContainer']}:{d.get('CgroupPermissions', 'rwm')}"
        for d in raw_devices
        if isinstance(d, dict) and "PathOnHost" in d
    ]

    # Capabilities
    cap_add = host_config.get("CapAdd") or []
    cap_drop = host_config.get("CapDrop") or []

    # Runtime (nvidia, etc.)
    runtime = host_config.get("Runtime") or None

    # Shared memory size (bytes, None if default)
    shm_size = host_config.get("ShmSize")
    if shm_size == 67108864:  # 64MB is the default
        shm_size = None

    # Tmpfs mounts
    raw_tmpfs = host_config.get("Tmpfs") or {}
    tmpfs = [f"{path}:{opts}" if opts else path for path, opts in raw_tmpfs.items()]

    # Sysctls
    raw_sysctls = host_config.get("Sysctls") or {}
    sysctls = list(raw_sysctls.items())

    # Security options
    security_opt = host_config.get("SecurityOpt") or []

    # PID mode
    pid_mode = host_config.get("PidMode") or None

    # DNS
    dns = host_config.get("Dns") or []
    dns_search = host_config.get("DnsSearch") or []

    # Extra hosts
    extra_hosts = host_config.get("ExtraHosts") or []

    # Group add
    group_add = host_config.get("GroupAdd") or []

    # Hostname (only if explicitly set, not auto-generated)
    hostname = config.get("Hostname") or None

    # Stop signal and grace period
    stop_signal = config.get("StopSignal") or None
    stop_timeout = config.get("StopTimeout")
    stop_grace_period = stop_timeout if stop_timeout is not None else None

    # Resource limits
    mem_limit = host_config.get("Memory") or None
    nano_cpus = host_config.get("NanoCpus") or 0
    cpus = nano_cpus / 1e9 if nano_cpus else None

    # Logging configuration
    log_config = host_config.get("LogConfig") or {}
    log_type = log_config.get("Type") or None
    log_driver = log_type if log_type and log_type != "json-file" else log_type
    raw_log_opts = log_config.get("Config") or {}
    log_opts = list(raw_log_opts.items())

    # Read-only root filesystem
    read_only = host_config.get("ReadonlyRootfs", False)

    # Init process
    init = host_config.get("Init") or False

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
        privileged=privileged,
        network_mode=network_mode,
        healthcheck=healthcheck,
        devices=devices,
        cap_add=cap_add,
        cap_drop=cap_drop,
        runtime=runtime,
        shm_size=shm_size,
        tmpfs=tmpfs,
        sysctls=sysctls,
        security_opt=security_opt,
        pid_mode=pid_mode,
        dns=dns,
        dns_search=dns_search,
        extra_hosts=extra_hosts,
        group_add=group_add,
        hostname=hostname,
        stop_signal=stop_signal,
        stop_grace_period=stop_grace_period,
        mem_limit=mem_limit,
        cpus=cpus,
        init=init,
        log_driver=log_driver,
        log_opts=log_opts,
        read_only=read_only,
        image_created=image_created,
    )


def _collect_daemon_info(client: Any) -> DaemonInfo | None:
    """Collect Docker daemon configuration."""
    try:
        info = client.info()
    except Exception:
        return None

    log_driver = info.get("LoggingDriver", "json-file")
    # Docker daemon log opts are in the info dict under LogConfig (undocumented)
    # but more reliably available via daemon config. We use what's available.
    raw_log_opts = info.get("LogConfig", {})
    if isinstance(raw_log_opts, dict):
        log_opts = list(raw_log_opts.get("Config", {}).items())
    else:
        log_opts = []

    return DaemonInfo(
        live_restore=info.get("LiveRestoreEnabled", False),
        default_log_driver=log_driver,
        default_log_opts=tuple(sorted(log_opts, key=lambda o: o[0])),
        storage_driver=info.get("Driver", "unknown"),
        security_options=tuple(sorted(info.get("SecurityOptions", []))),
        cgroup_driver=info.get("CgroupDriver", "unknown"),
        server_version=info.get("ServerVersion", "unknown"),
    )


def _collect_healthcheck(hc_config: dict[str, Any] | None) -> HealthcheckConfig | None:
    """Extract healthcheck configuration from Config.Healthcheck."""
    if not hc_config:
        return None
    test = hc_config.get("Test")
    if not test:
        return None
    # Docker stores "NONE" as the test to indicate healthcheck is disabled
    if test == ["NONE"]:
        return None
    return HealthcheckConfig(
        test=tuple(test),
        interval_ns=hc_config.get("Interval", 0),
        timeout_ns=hc_config.get("Timeout", 0),
        retries=hc_config.get("Retries", 0),
        start_period_ns=hc_config.get("StartPeriod", 0),
    )


def _collect_ports(ports_dict: dict[str, Any]) -> list[PortBinding]:
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


def _collect_mounts(mounts_list: list[dict[str, Any]]) -> list[MountInfo]:
    return [
        MountInfo(
            source=m.get("Source", ""),
            destination=m.get("Destination", ""),
            mode=m.get("Mode", ""),
            type=m.get("Type", ""),
        )
        for m in mounts_list
    ]


def _collect_networks(networks_dict: dict[str, Any]) -> list[NetworkMembership]:
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
