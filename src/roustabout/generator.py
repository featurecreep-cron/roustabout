"""Generate docker-compose.yml from a DockerEnvironment snapshot.

Takes the same frozen model objects that the auditor and renderer use.
Produces a valid compose file that recreates the running environment.

LLD: docs/roustabout/designs/035-generate-stack-splitting.md
"""

from __future__ import annotations

from dataclasses import dataclass
from io import StringIO

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from roustabout.constants import COMPOSE_LABEL_PREFIXES, IMAGE_LABEL_PREFIXES
from roustabout.models import ContainerInfo, DockerEnvironment

# Default Docker networks that shouldn't be declared in top-level networks:
_DEFAULT_NETWORKS = {"bridge", "host", "none"}

# Default runtimes that shouldn't be emitted
_DEFAULT_RUNTIMES = {"runc", "io.containerd.runc.v2"}

# Docker volume internal path prefix — identifies anonymous volumes
_DOCKER_VOLUME_PATH = "/var/lib/docker/volumes/"

# Environment variables that are image-baked, not user-set.
# These appear on virtually every container and are never useful in compose files.
_IMAGE_ENV_VARS = {
    "PATH",
    "HOSTNAME",
    "HOME",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "TERM",
    # Python
    "GPG_KEY",
    "PYTHON_VERSION",
    "PYTHON_PIP_VERSION",
    "PYTHON_SETUPTOOLS_VERSION",
    "PYTHON_GET_PIP_URL",
    "PYTHON_GET_PIP_SHA256",
    "PYTHON_SHA256",
    # Go
    "GOPATH",
    "GOVERSION",
    "GOTOOLCHAIN",
    # Node
    "NODE_VERSION",
    "YARN_VERSION",
    # Java
    "JAVA_HOME",
    "JAVA_VERSION",
    # Ruby
    "RUBY_VERSION",
    "GEM_HOME",
    "BUNDLE_SILENCE_ROOT_WARNING",
    # Rust
    "RUSTUP_HOME",
    "CARGO_HOME",
    # Database version vars (image metadata)
    "PG_MAJOR",
    "PG_VERSION",
    "PG_SHA256",
    "GOSU_VERSION",
    "MARIADB_MAJOR",
    "MARIADB_VERSION",
    "MYSQL_MAJOR",
    "MYSQL_VERSION",
    # LinuxServer.io internals
    "LSIO_FIRST_PARTY",
    "S6_VERBOSITY",
    "S6_STAGE2_HOOK",
    "S6_CMD_WAIT_FOR_SERVICES_MAXTIME",
    "VIRTUAL_ENV",
    "PS1",
}


def generate(
    env: DockerEnvironment,
    *,
    include_stopped: bool = False,
    project_name: str | None = None,
) -> str:
    """Generate a docker-compose.yml from a DockerEnvironment.

    Args:
        env: The environment snapshot to convert.
        include_stopped: Include stopped containers (default: running only).
        project_name: Optional compose project name for the x-project comment.

    Returns:
        A valid docker-compose.yml as a string.
    """
    containers = list(env.containers)
    if not include_stopped:
        containers = [c for c in containers if c.status == "running"]

    if not containers:
        return "# No running containers found.\n"

    # Build a lookup from container name → service name for cross-references
    name_to_service: dict[str, str] = {}
    used_names: dict[str, int] = {}
    for container in containers:
        svc_name = _service_name(container)
        # Handle service name collisions
        if svc_name in used_names:
            used_names[svc_name] += 1
            svc_name = f"{svc_name}-{used_names[svc_name]}"
        else:
            used_names[svc_name] = 1
        name_to_service[container.name] = svc_name

    doc = CommentedMap()
    doc.yaml_set_comment_before_after_key(
        "services",
        before=_header_comment(env, containers, include_stopped),
    )

    # Build services
    services = CommentedMap()
    all_volumes: set[str] = set()
    all_networks: set[str] = set()

    for container in containers:
        service_name = name_to_service[container.name]
        service = _build_service(container, name_to_service)
        services[service_name] = service

        # Track volumes and networks for top-level declarations
        for mount in container.mounts:
            if mount.type == "volume" and not _is_anonymous_volume(mount.source):
                all_volumes.add(mount.source)
        for net in container.networks:
            if net.name not in _DEFAULT_NETWORKS:
                all_networks.add(net.name)

        # Add compose origin comment
        if container.compose_config_files:
            services.yaml_set_comment_before_after_key(
                service_name,
                before=f"Originally from compose file: {container.compose_config_files}",
            )

    doc["services"] = services

    # Top-level volumes (only named volumes, not anonymous)
    if all_volumes:
        volumes = CommentedMap()
        for vol_name in sorted(all_volumes):
            volumes[vol_name] = CommentedMap([("external", True)])
        doc["volumes"] = volumes
        doc.yaml_set_comment_before_after_key(
            "volumes",
            before=(
                "These volumes already exist on this host. To make this file portable,\n"
                "remove 'external: true' — but you'll need to migrate data separately."
            ),
        )

    # Top-level networks
    if all_networks:
        networks = CommentedMap()
        for net_name in sorted(all_networks):
            networks[net_name] = CommentedMap([("external", True)])
        doc["networks"] = networks
        doc.yaml_set_comment_before_after_key(
            "networks",
            before=(
                "These networks already exist on this host. To make this file portable,\n"
                "remove 'external: true' and let compose create them."
            ),
        )

    return _dump_yaml(doc)


def _header_comment(
    env: DockerEnvironment,
    containers: list[ContainerInfo],
    include_stopped: bool,
) -> str:
    running = sum(1 for c in env.containers if c.status == "running")
    stopped = len(env.containers) - running
    scope = f"{len(containers)} containers"
    if not include_stopped and stopped > 0:
        scope += f" ({stopped} stopped excluded)"

    lines = [
        "Generated by roustabout from Docker API snapshot",
        "WARNING: This file may contain secrets in environment variables.",
        "Review before committing to version control.",
        "",
        f"Docker version: {env.docker_version}",
        f"Generated: {env.generated_at}",
        f"Containers: {scope}",
    ]
    return "\n".join(lines)


def _service_name(container: ContainerInfo) -> str:
    """Derive a compose service name from a container."""
    # Use compose service name if available
    if container.compose_service:
        return container.compose_service

    # Sanitize container name for compose
    name = container.name.lstrip("/")
    # Compose service names: lowercase, alphanumeric, hyphens, underscores
    return name.lower().replace(".", "-")


def _is_default_network_mode(mode: str, compose_project: str | None = None) -> bool:
    """Check if a network mode is a default that shouldn't be emitted."""
    if mode in ("bridge", "default"):
        return True
    # Compose creates {project}_default networks — only suppress when we can
    # confirm it matches the container's own compose project
    if compose_project and mode == f"{compose_project}_default":
        return True
    return False


def _is_auto_hostname(hostname: str, container_id: str) -> bool:
    """Check if a hostname is auto-generated (matches container ID prefix)."""
    # Docker sets hostname to the first 12 chars of the container ID
    return hostname == container_id[:12]


def _is_anonymous_volume(source: str) -> bool:
    """Check if a volume source is an anonymous Docker volume (hash path)."""
    return source.startswith(_DOCKER_VOLUME_PATH)


def _build_service(
    c: ContainerInfo, name_to_service: dict[str, str] | None = None
) -> CommentedMap:
    """Build a compose service definition from a ContainerInfo."""
    svc = CommentedMap()

    svc["image"] = c.image
    svc["container_name"] = c.name

    if c.restart_policy and c.restart_policy != "no":
        svc["restart"] = c.restart_policy

    if c.user:
        svc["user"] = c.user

    if c.privileged:
        svc["privileged"] = True

    if c.init:
        svc["init"] = True

    if c.read_only:
        svc["read_only"] = True

    if c.network_mode and not _is_default_network_mode(c.network_mode, c.compose_project):
        # Handle container:X network mode → service:X in compose
        if c.network_mode.startswith("container:"):
            ref_container = c.network_mode.split(":", 1)[1]
            # Map container name to service name if known
            if name_to_service and ref_container in name_to_service:
                svc["network_mode"] = f"service:{name_to_service[ref_container]}"
            else:
                svc["network_mode"] = f"service:{ref_container}"
        else:
            svc["network_mode"] = c.network_mode

    if c.hostname and not _is_auto_hostname(c.hostname, c.id):
        svc["hostname"] = c.hostname

    if c.runtime and c.runtime not in _DEFAULT_RUNTIMES:
        svc["runtime"] = c.runtime

    if c.pid_mode and c.pid_mode != "":
        svc["pid"] = c.pid_mode

    if c.stop_signal and c.stop_signal not in ("SIGTERM",):
        svc["stop_signal"] = c.stop_signal

    if c.stop_grace_period is not None:
        svc["stop_grace_period"] = f"{c.stop_grace_period}s"

    if c.shm_size:
        svc["shm_size"] = _human_bytes(c.shm_size)

    # Ports — skip unpublished (empty host_port) ports
    if c.ports:
        ports = CommentedSeq()
        for p in c.ports:
            if not p.host_port:
                continue  # EXPOSE-only, not published
            host_ip = p.host_ip if p.host_ip and p.host_ip != "0.0.0.0" else ""
            ip_prefix = f"{host_ip}:" if host_ip else ""
            port_str = f"{ip_prefix}{p.host_port}:{p.container_port}"
            if p.protocol != "tcp":
                port_str += f"/{p.protocol}"
            ports.append(port_str)
        if ports:
            svc["ports"] = ports

    # Volumes
    volumes = _build_volumes(c)
    if volumes:
        svc["volumes"] = volumes

    # Tmpfs
    if c.tmpfs:
        svc["tmpfs"] = list(c.tmpfs)

    # Networks (skip if using non-default network_mode)
    if not (c.network_mode and not _is_default_network_mode(c.network_mode, c.compose_project)):
        nets = _build_networks(c)
        if nets:
            svc["networks"] = nets

    # Environment — filter out image-baked variables
    if c.env:
        user_env = [(k, v) for k, v in c.env if k not in _IMAGE_ENV_VARS]
        if user_env:
            env_map = CommentedMap()
            for key, value in user_env:
                env_map[key] = value
            svc["environment"] = env_map

    # Labels (excluding compose-internal and image metadata)
    user_labels = [
        (k, v)
        for k, v in c.labels
        if not any(k.startswith(p) for p in COMPOSE_LABEL_PREFIXES)
        and not any(k.startswith(p) for p in IMAGE_LABEL_PREFIXES)
    ]
    if user_labels:
        labels = CommentedMap()
        for key, value in user_labels:
            labels[key] = value
        svc["labels"] = labels

    # Healthcheck
    if c.healthcheck:
        svc["healthcheck"] = _build_healthcheck(c)

    # Capabilities
    if c.cap_add:
        svc["cap_add"] = list(c.cap_add)

    if c.cap_drop:
        svc["cap_drop"] = list(c.cap_drop)

    # Devices
    if c.devices:
        svc["devices"] = list(c.devices)

    # Security options
    if c.security_opt:
        svc["security_opt"] = list(c.security_opt)

    # Sysctls
    if c.sysctls:
        sysctls = CommentedMap()
        for key, value in c.sysctls:
            sysctls[key] = value
        svc["sysctls"] = sysctls

    # DNS
    if c.dns:
        svc["dns"] = list(c.dns)

    if c.dns_search:
        svc["dns_search"] = list(c.dns_search)

    # Extra hosts
    if c.extra_hosts:
        svc["extra_hosts"] = list(c.extra_hosts)

    # Group add
    if c.group_add:
        svc["group_add"] = list(c.group_add)

    # Logging
    if c.log_driver or c.log_opts:
        logging = CommentedMap()
        if c.log_driver and c.log_driver != "json-file":
            logging["driver"] = c.log_driver
        if c.log_opts:
            options = CommentedMap()
            for key, value in c.log_opts:
                options[key] = value
            logging["options"] = options
        if logging:
            svc["logging"] = logging

    # Resource limits
    if c.mem_limit or c.cpus:
        deploy = CommentedMap()
        resources = CommentedMap()
        limits = CommentedMap()
        if c.mem_limit:
            limits["memory"] = _human_bytes(c.mem_limit)
        if c.cpus:
            limits["cpus"] = str(c.cpus)
        resources["limits"] = limits
        deploy["resources"] = resources
        svc["deploy"] = deploy

    # depends_on — inferred from container:X network mode
    deps = _infer_depends_on(c, name_to_service)
    if deps:
        depends_on = CommentedMap()
        for dep in deps:
            depends_on[dep] = CommentedMap([("condition", "service_started")])
        svc["depends_on"] = depends_on

    # Command and entrypoint — use list form to preserve argument boundaries
    if c.entrypoint:
        svc["entrypoint"] = list(c.entrypoint) if len(c.entrypoint) > 1 else c.entrypoint[0]

    if c.command:
        svc["command"] = list(c.command) if len(c.command) > 1 else c.command[0]

    return svc


def _infer_depends_on(c: ContainerInfo, name_to_service: dict[str, str] | None) -> list[str]:
    """Infer service dependencies from container relationships."""
    deps: list[str] = []

    # container:X network mode implies dependency on X
    if c.network_mode and c.network_mode.startswith("container:"):
        ref_container = c.network_mode.split(":", 1)[1]
        if name_to_service and ref_container in name_to_service:
            deps.append(name_to_service[ref_container])
        else:
            deps.append(ref_container)

    return deps


def _build_volumes(c: ContainerInfo) -> CommentedSeq | None:
    """Build the volumes list for a service."""
    if not c.mounts:
        return None

    volumes = CommentedSeq()
    for m in c.mounts:
        if m.type == "bind":
            entry = f"{m.source}:{m.destination}"
            if m.mode and m.mode != "rw":
                entry += f":{m.mode}"
            volumes.append(entry)
        elif m.type == "volume":
            if _is_anonymous_volume(m.source):
                # Anonymous volume — emit just the destination to let compose
                # create a new anonymous volume
                volumes.append(m.destination)
            else:
                entry = f"{m.source}:{m.destination}"
                if m.mode and m.mode != "rw":
                    entry += f":{m.mode}"
                volumes.append(entry)
        # tmpfs mounts are handled separately

    return volumes if volumes else None


def _build_networks(c: ContainerInfo) -> CommentedMap | None:
    """Build the networks section for a service."""
    non_default = [n for n in c.networks if n.name not in _DEFAULT_NETWORKS]
    if not non_default:
        return None

    nets = CommentedMap()
    for n in non_default:
        net_config = CommentedMap()
        # Only include non-default aliases (exclude container name and ID)
        real_aliases = [
            a for a in n.aliases if a != c.name and not a.startswith(c.id[:12]) and a != c.id
        ]
        if real_aliases:
            net_config["aliases"] = list(real_aliases)
        nets[n.name] = net_config if net_config else CommentedMap()

    return nets if nets else None


def _build_healthcheck(c: ContainerInfo) -> CommentedMap:
    """Build healthcheck config from HealthcheckConfig."""
    assert c.healthcheck is not None
    hc = c.healthcheck
    result = CommentedMap()

    # Convert test command
    test = list(hc.test)
    if test and test[0] == "CMD-SHELL":
        # Single shell command — use the simpler string form
        result["test"] = test[1] if len(test) == 2 else test
    else:
        result["test"] = test

    if hc.interval_ns:
        result["interval"] = _ns_to_duration(hc.interval_ns)
    if hc.timeout_ns:
        result["timeout"] = _ns_to_duration(hc.timeout_ns)
    if hc.retries:
        result["retries"] = hc.retries
    if hc.start_period_ns:
        result["start_period"] = _ns_to_duration(hc.start_period_ns)

    return result


def _ns_to_duration(ns: int) -> str:
    """Convert nanoseconds to a human-readable duration string."""
    seconds = ns // 1_000_000_000
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _human_bytes(n: int) -> str:
    """Convert bytes to human-readable size."""
    if n >= 1073741824 and n % 1073741824 == 0:
        return f"{n // 1073741824}G"
    if n >= 1048576 and n % 1048576 == 0:
        return f"{n // 1048576}M"
    if n >= 1024 and n % 1024 == 0:
        return f"{n // 1024}K"
    return str(n)


def _dump_yaml(doc: CommentedMap) -> str:
    """Serialize a CommentedMap to YAML string."""
    yaml = YAML()
    yaml.default_flow_style = False
    yaml.width = 120
    yaml.indent(mapping=2, sequence=4, offset=2)

    stream = StringIO()
    yaml.dump(doc, stream)
    return stream.getvalue()


# --- Stack splitting (LLD-035) ---


@dataclass(frozen=True)
class CrossStackDependency:
    """A dependency that crosses stack boundaries."""

    source_service: str
    source_stack: str
    target_service: str
    target_stack: str
    dependency_type: str
    description: str


@dataclass(frozen=True)
class StackOutput:
    """Generated compose output for a single stack."""

    name: str
    compose_yaml: str
    services: tuple[str, ...]
    shared_networks: tuple[str, ...]
    shared_volumes: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class StackSplitResult:
    """Result of splitting a DockerEnvironment into per-stack compose files."""

    stacks: tuple[StackOutput, ...]
    cross_stack_deps: tuple[CrossStackDependency, ...]
    unmapped_services: tuple[str, ...]
    shared_networks: tuple[str, ...]
    shared_volumes: tuple[str, ...]


def generate_stacks(
    env: DockerEnvironment,
    *,
    include_stopped: bool = False,
    group_by: str = "project",
    stack_mapping: dict[str, str] | None = None,
) -> StackSplitResult:
    """Split a DockerEnvironment into per-stack compose outputs.

    group_by="project": groups by com.docker.compose.project label.
    group_by="mapping": uses stack_mapping (service_name → stack_name).
    """
    if group_by == "mapping" and stack_mapping is None:
        msg = "stack_mapping is required when group_by='mapping'"
        raise ValueError(msg)
    if group_by not in ("project", "mapping"):
        msg = f"group_by must be 'project' or 'mapping', got '{group_by}'"
        raise ValueError(msg)

    containers = list(env.containers)
    if not include_stopped:
        containers = [c for c in containers if c.status == "running"]

    # Build service name lookup (container.name → service_name)
    name_to_service: dict[str, str] = {}
    used_names: dict[str, int] = {}
    for container in containers:
        svc_name = _service_name(container)
        if svc_name in used_names:
            used_names[svc_name] += 1
            svc_name = f"{svc_name}-{used_names[svc_name]}"
        else:
            used_names[svc_name] = 1
        name_to_service[container.name] = svc_name

    # Group containers into stacks
    if group_by == "project":
        groups = _group_by_project(containers)
    else:
        groups = _group_by_mapping(containers, name_to_service, stack_mapping or {})

    # Build lookup: service_name → stack_name
    service_to_stack: dict[str, str] = {}
    stack_services: dict[str, list[str]] = {}
    for stack_name, stack_containers in groups.items():
        svc_names = []
        for c in stack_containers:
            svc = name_to_service[c.name]
            service_to_stack[svc] = stack_name
            svc_names.append(svc)
        stack_services[stack_name] = svc_names

    # Identify shared networks and volumes
    shared_nets, shared_vols = _classify_shared_resources(groups)

    # Detect cross-stack dependencies
    cross_deps = _detect_cross_stack_deps(groups, name_to_service, service_to_stack)

    # Generate per-stack compose YAML
    stacks: list[StackOutput] = []
    for stack_name in sorted(groups.keys()):
        stack_containers = groups[stack_name]
        stack_env = DockerEnvironment(
            containers=tuple(sorted(stack_containers, key=lambda c: c.name)),
            generated_at=env.generated_at,
            docker_version=env.docker_version,
            warnings=env.warnings,
        )

        yaml_str = generate(stack_env, include_stopped=include_stopped)

        # Post-process: mark shared resources as external
        stack_shared_nets = tuple(
            n for n in shared_nets if _stack_uses_network(stack_containers, n)
        )
        stack_shared_vols = tuple(
            v for v in shared_vols if _stack_uses_volume(stack_containers, v)
        )

        # Build warnings for this stack
        warnings: list[str] = []
        for dep in cross_deps:
            if dep.source_stack == stack_name:
                warnings.append(dep.description)

        svc_names = tuple(sorted(name_to_service[c.name] for c in stack_containers))

        stacks.append(
            StackOutput(
                name=stack_name,
                compose_yaml=yaml_str,
                services=svc_names,
                shared_networks=stack_shared_nets,
                shared_volumes=stack_shared_vols,
                warnings=tuple(warnings),
            )
        )

    # Collect unmapped services (mapping mode only)
    unmapped: tuple[str, ...] = ()
    if group_by == "mapping" and "_unmapped" in groups:
        unmapped = tuple(
            sorted(name_to_service[c.name] for c in groups["_unmapped"])
        )

    return StackSplitResult(
        stacks=tuple(stacks),
        cross_stack_deps=tuple(cross_deps),
        unmapped_services=unmapped,
        shared_networks=tuple(sorted(shared_nets)),
        shared_volumes=tuple(sorted(shared_vols)),
    )


def _group_by_project(
    containers: list[ContainerInfo],
) -> dict[str, list[ContainerInfo]]:
    """Group containers by compose project label."""
    groups: dict[str, list[ContainerInfo]] = {}
    for c in containers:
        project = c.compose_project or "_default"
        groups.setdefault(project, []).append(c)
    return groups


def _group_by_mapping(
    containers: list[ContainerInfo],
    name_to_service: dict[str, str],
    stack_mapping: dict[str, str],
) -> dict[str, list[ContainerInfo]]:
    """Group containers by explicit stack mapping (service_name → stack_name)."""
    groups: dict[str, list[ContainerInfo]] = {}
    for c in containers:
        svc_name = name_to_service[c.name]
        stack = stack_mapping.get(svc_name, "_unmapped")
        groups.setdefault(stack, []).append(c)
    return groups


def _classify_shared_resources(
    groups: dict[str, list[ContainerInfo]],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Identify networks and volumes shared across stacks."""
    net_stacks: dict[str, set[str]] = {}
    vol_stacks: dict[str, set[str]] = {}

    for stack_name, containers in groups.items():
        for c in containers:
            for n in c.networks:
                if n.name not in _DEFAULT_NETWORKS:
                    net_stacks.setdefault(n.name, set()).add(stack_name)
            for m in c.mounts:
                if m.type == "volume" and not _is_anonymous_volume(m.source):
                    vol_stacks.setdefault(m.source, set()).add(stack_name)

    shared_nets = tuple(sorted(n for n, stacks in net_stacks.items() if len(stacks) > 1))
    shared_vols = tuple(sorted(v for v, stacks in vol_stacks.items() if len(stacks) > 1))
    return shared_nets, shared_vols


def _detect_cross_stack_deps(
    groups: dict[str, list[ContainerInfo]],
    name_to_service: dict[str, str],
    service_to_stack: dict[str, str],
) -> tuple[CrossStackDependency, ...]:
    """Detect dependencies between services in different stacks."""
    deps: list[CrossStackDependency] = []

    for stack_name, containers in groups.items():
        for c in containers:
            svc_name = name_to_service[c.name]

            # Check network_mode: container:X / service:X
            if c.network_mode and c.network_mode.startswith("container:"):
                ref_container = c.network_mode.split(":", 1)[1]
                ref_service = name_to_service.get(ref_container, ref_container)
                ref_stack = service_to_stack.get(ref_service)
                if ref_stack and ref_stack != stack_name:
                    deps.append(
                        CrossStackDependency(
                            source_service=svc_name,
                            source_stack=stack_name,
                            target_service=ref_service,
                            target_stack=ref_stack,
                            dependency_type="network_mode",
                            description=(
                                f"{svc_name} uses network_mode: container:{ref_container}"
                                f" which is in stack '{ref_stack}'"
                            ),
                        )
                    )

    return tuple(deps)


def _stack_uses_network(containers: list[ContainerInfo], network: str) -> bool:
    """Check if any container in a stack uses a network."""
    return any(n.name == network for c in containers for n in c.networks)


def _stack_uses_volume(containers: list[ContainerInfo], volume: str) -> bool:
    """Check if any container in a stack uses a named volume."""
    return any(
        m.type == "volume" and m.source == volume
        for c in containers
        for m in c.mounts
    )
