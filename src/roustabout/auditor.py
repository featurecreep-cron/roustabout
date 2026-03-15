"""Security auditor for Docker environments.

Operates on the model layer (DockerEnvironment), not the Docker API.
Can audit live snapshots or saved/loaded environments.
All checks are deterministic and independently testable.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from roustabout.models import ContainerInfo, DaemonInfo, DockerEnvironment
from roustabout.redactor import is_secret_key, resolve_patterns

# Image name substrings that indicate sensitive services (databases, admin panels)
_SENSITIVE_IMAGE_PATTERNS = (
    "postgres",
    "mysql",
    "mariadb",
    "mongo",
    "redis",
    "memcached",
    "elasticsearch",
    "opensearch",
    "clickhouse",
    "influxdb",
    "cockroach",
    "mssql",
    "phpmyadmin",
    "adminer",
    "pgadmin",
    "portainer",
)

# Host paths that should not be bind-mounted into containers.
# These flag on exact match AND subdirectory mounts.
_SENSITIVE_HOST_PATHS = (
    "/etc",
    "/root",
    "/home",
    "/var/run/docker.sock",  # handled separately by docker-socket check
)

# These paths flag only on exact match (not subdirectories).
# /home is here because homelabbers commonly mount /home/user/docker/* for data.
_SENSITIVE_EXACT_ONLY = {"/home"}

# Specific files under sensitive paths that are safe to mount (read-only, no secrets)
_SAFE_MOUNT_EXCEPTIONS = (
    "/etc/localtime",
    "/etc/timezone",
    "/etc/hosts",
    "/etc/resolv.conf",
)

# Dangerous capabilities that warrant auditing
_DANGEROUS_CAPS = {
    "SYS_ADMIN": "mount namespace access — nearly equivalent to privileged mode",
    "NET_ADMIN": "full control over host networking",
    "SYS_PTRACE": "can trace any process — allows container escape techniques",
    "DAC_OVERRIDE": "bypasses file permission checks",
    "SYS_RAWIO": "raw I/O access to hardware devices",
    "SYS_MODULE": "can load kernel modules",
}


class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """A single security finding for a container."""

    severity: Severity
    category: str
    container: str
    explanation: str
    fix: str
    detail: str = field(default="", compare=True)

    @property
    def key(self) -> str:
        """Stable identifier for state tracking across runs."""
        parts = [self.container, self.category]
        if self.detail:
            parts.append(self.detail)
        return "|".join(parts)


_SEVERITY_MAP = {"critical": Severity.CRITICAL, "warning": Severity.WARNING, "info": Severity.INFO}


def audit(
    env: DockerEnvironment,
    patterns: tuple[str, ...] | None = None,
    severity_overrides: dict[str, str] | None = None,
) -> list[Finding]:
    """Run all security checks against a DockerEnvironment.

    Args:
        env: The environment to audit.
        patterns: Custom patterns to extend the defaults for secret detection.
            Merged with DEFAULT_PATTERNS via resolve_patterns.
        severity_overrides: Map of category name to severity level string.
            Overrides the default severity for matching checks.

    Returns findings sorted by severity (critical first), then container name.
    """
    active_patterns = resolve_patterns(patterns or ())
    findings: list[Finding] = []

    for container in env.containers:
        findings.extend(_check_docker_socket(container))
        findings.extend(_check_privileged_mode(container))
        findings.extend(_check_dangerous_capabilities(container))
        findings.extend(_check_sensitive_host_mounts(container))
        findings.extend(_check_host_network(container))
        findings.extend(_check_pid_mode(container))
        findings.extend(_check_secrets_in_env(container, active_patterns))
        findings.extend(_check_sensitive_port_binding(container))
        findings.extend(_check_no_health_check(container))
        findings.extend(_check_running_as_root(container))
        findings.extend(_check_restart_loops(container))
        findings.extend(_check_oom_killed(container))
        findings.extend(_check_no_restart_policy(container))
        findings.extend(_check_stale_images(container))
        findings.extend(_check_no_log_rotation(container))
        findings.extend(_check_no_resource_limits(container))
        findings.extend(_check_image_age(container))

    findings.extend(_check_flat_networking(env))

    if env.daemon:
        findings.extend(_check_daemon_config(env.daemon))

    if severity_overrides:
        findings = _apply_severity_overrides(findings, severity_overrides)

    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    findings.sort(key=lambda f: (severity_order[f.severity], f.container, f.category))

    return findings


def _apply_severity_overrides(findings: list[Finding], overrides: dict[str, str]) -> list[Finding]:
    """Replace severity on findings whose category matches an override."""
    result = []
    for f in findings:
        new_level = overrides.get(f.category)
        if new_level and new_level in _SEVERITY_MAP:
            f = dataclasses.replace(f, severity=_SEVERITY_MAP[new_level])
        result.append(f)
    return result


def _check_docker_socket(c: ContainerInfo) -> list[Finding]:
    """Check: Docker socket mounted — full host control."""
    for mount in c.mounts:
        if mount.destination == "/var/run/docker.sock" or mount.source == "/var/run/docker.sock":
            return [
                Finding(
                    severity=Severity.CRITICAL,
                    category="docker-socket",
                    container=c.name,
                    explanation="Docker socket is mounted, giving this container full control "
                    "over the Docker host.",
                    fix="Use a Docker socket proxy (e.g. tecnativa/docker-socket-proxy) to "
                    "limit API access to only the endpoints this container needs.",
                )
            ]
    return []


def _check_privileged_mode(c: ContainerInfo) -> list[Finding]:
    """Check: Container running in privileged mode."""
    if not c.privileged:
        return []
    return [
        Finding(
            severity=Severity.CRITICAL,
            category="privileged-mode",
            container=c.name,
            explanation="Container is running in privileged mode. It has full access to "
            "all host devices and can bypass all Docker isolation.",
            fix="Remove `privileged: true` from docker-compose.yml. If the container "
            "needs specific device access, use `devices:` to grant only what it needs. "
            "If it needs specific capabilities, use `cap_add:` instead.",
        )
    ]


def _check_dangerous_capabilities(c: ContainerInfo) -> list[Finding]:
    """Check: Container granted dangerous Linux capabilities."""
    if c.privileged:
        return []  # already caught by privileged-mode check
    findings = []
    for cap in c.cap_add:
        cap_upper = cap.upper()
        if cap_upper in _DANGEROUS_CAPS:
            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    category="dangerous-capability",
                    container=c.name,
                    explanation=f"Container has `{cap_upper}` capability: "
                    f"{_DANGEROUS_CAPS[cap_upper]}.",
                    fix=f"Remove `{cap_upper}` from `cap_add:` unless the container "
                    f"specifically requires it. Check the image documentation.",
                    detail=cap_upper,
                )
            )
    return findings


def _check_sensitive_host_mounts(c: ContainerInfo) -> list[Finding]:
    """Check: Sensitive host paths mounted into container."""
    # Docker socket is already caught by check #1 — skip it here
    findings = []
    for mount in c.mounts:
        if mount.type != "bind":
            continue
        source = mount.source.rstrip("/")
        # Skip known-safe individual file mounts (timezone, hosts, etc.)
        if source in _SAFE_MOUNT_EXCEPTIONS:
            continue
        for sensitive in _SENSITIVE_HOST_PATHS:
            if sensitive == "/var/run/docker.sock":
                continue  # handled by docker-socket check
            # Some paths only flag on exact match, not subdirectories
            if sensitive in _SENSITIVE_EXACT_ONLY:
                is_match = source == sensitive
            else:
                is_match = source == sensitive or source.startswith(sensitive + "/")
            if is_match:
                findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        category="sensitive-mount",
                        container=c.name,
                        explanation=f"Host path `{mount.source}` is mounted at "
                        f"`{mount.destination}`. This exposes sensitive host files "
                        f"to the container.",
                        fix=f"Mount only the specific subdirectory needed instead of "
                        f"`{mount.source}`. If the container needs host configuration, "
                        f"copy the specific files into the image at build time.",
                        detail=mount.source,
                    )
                )
                break  # one finding per mount is enough
    return findings


def _check_host_network(c: ContainerInfo) -> list[Finding]:
    """Check: Container using host network mode."""
    if c.status != "running":
        return []
    if c.network_mode != "host":
        return []
    return [
        Finding(
            severity=Severity.INFO,
            category="host-network",
            container=c.name,
            explanation="Container is using host network mode. It shares the host's "
            "network stack directly, bypassing Docker network isolation.",
            fix="Use a bridge network with explicit port mappings unless host network "
            "performance is specifically required.",
        )
    ]


def _check_pid_mode(c: ContainerInfo) -> list[Finding]:
    """Check: Container using host PID namespace."""
    if c.status != "running":
        return []
    if c.pid_mode != "host":
        return []
    return [
        Finding(
            severity=Severity.WARNING,
            category="host-pid",
            container=c.name,
            explanation="Container shares the host PID namespace. It can see and signal "
            "all processes on the host.",
            fix="Remove `pid: host` unless the container specifically requires "
            "visibility into host processes.",
        )
    ]


def _check_secrets_in_env(
    c: ContainerInfo,
    patterns: tuple[str, ...],
) -> list[Finding]:
    """Check: Secrets visible in environment variables."""
    findings = []
    for key, value in c.env:
        if not value or value == "[REDACTED]":
            continue
        if is_secret_key(key, value, patterns):
            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    category="secrets-in-env",
                    container=c.name,
                    explanation=f"`{key}` contains a secret passed as a plain environment "
                    f"variable. Visible via `docker inspect`.",
                    fix="Use Docker secrets, a mounted file, or a secrets manager instead "
                    "of environment variables for sensitive values.",
                    detail=key,
                )
            )
    return findings


def _check_sensitive_port_binding(c: ContainerInfo) -> list[Finding]:
    """Check: Database/admin ports bound to all interfaces."""
    image_lower = c.image.lower()
    is_sensitive = any(p in image_lower for p in _SENSITIVE_IMAGE_PATTERNS)
    if not is_sensitive:
        return []

    findings = []
    for port in c.ports:
        if port.host_ip in ("0.0.0.0", "::"):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="exposed-port",
                    container=c.name,
                    explanation=f"Port {port.container_port} ({c.image}) is bound to all "
                    f"interfaces ({port.host_ip}:{port.host_port}). On a multi-NIC host, "
                    f"this service is accessible from every network.",
                    fix="If this service should only be reachable from localhost, bind to "
                    "127.0.0.1 instead (e.g. `127.0.0.1:5432:5432`).",
                    detail=str(port.container_port),
                )
            )
    return findings


def _check_no_health_check(c: ContainerInfo) -> list[Finding]:
    """Check: No health check configured."""
    if c.status != "running":
        return []
    if c.health is None:
        return [
            Finding(
                severity=Severity.INFO,
                category="no-healthcheck",
                container=c.name,
                explanation="No health check configured. Docker cannot detect if this "
                "container's application has stopped responding.",
                fix="Add a HEALTHCHECK instruction to the Dockerfile or a `healthcheck` "
                "section in docker-compose.yml.",
            )
        ]
    return []


def _check_running_as_root(c: ContainerInfo) -> list[Finding]:
    """Check: Running as root with elevated access.

    Most containers run as root — that alone is info-level noise. But root
    combined with the Docker socket is already caught as critical. Root with
    host-network or privileged mounts is worth flagging.
    """
    if c.status != "running":
        return []
    # user is None or "" means root
    if c.user:
        return []

    # Check for Docker socket (already caught as critical, skip)
    has_socket = any(
        m.destination == "/var/run/docker.sock" or m.source == "/var/run/docker.sock"
        for m in c.mounts
    )
    if has_socket:
        return []

    return [
        Finding(
            severity=Severity.INFO,
            category="running-as-root",
            container=c.name,
            explanation="Container is running as root. While common, this increases impact "
            "if the container is compromised.",
            fix='Set `user: "1000:1000"` in docker-compose.yml or use the image\'s '
            "built-in non-root user if available.",
        )
    ]


def _check_restart_loops(c: ContainerInfo) -> list[Finding]:
    """Check: Container has restarted excessively."""
    if c.restart_count > 25:
        return [
            Finding(
                severity=Severity.WARNING,
                category="restart-loop",
                container=c.name,
                explanation=f"Container has restarted {c.restart_count} times. This usually "
                f"indicates a crash loop or misconfiguration.",
                fix=f"Check container logs with `docker logs {c.name}` to identify the root "
                "cause.",
            )
        ]
    return []


def _check_oom_killed(c: ContainerInfo) -> list[Finding]:
    """Check: Container was OOM killed."""
    if c.oom_killed:
        return [
            Finding(
                severity=Severity.WARNING,
                category="oom-killed",
                container=c.name,
                explanation="Container was killed by the OOM killer. It ran out of memory.",
                fix="Increase the container's memory limit or investigate memory usage. "
                "Set `mem_limit` in docker-compose.yml.",
            )
        ]
    return []


def _check_flat_networking(env: DockerEnvironment) -> list[Finding]:
    """Check: All containers on the same network (across multiple compose projects)."""
    running = [c for c in env.containers if c.status == "running"]
    if len(running) < 3:
        return []

    # Collect compose projects to understand if flat networking is intentional
    projects = {c.compose_project for c in running if c.compose_project}

    # Collect all networks used by running containers
    network_members: dict[str, list[str]] = {}
    for c in running:
        for n in c.networks:
            network_members.setdefault(n.name, []).append(c.name)

    # Only flag if containers from multiple compose projects share a network,
    # or if standalone containers share a network with everything else.
    # A single compose project with all services on one network is normal.
    for net_name, members in network_members.items():
        if net_name == "host":
            continue
        if len(members) < len(running):
            continue

        # All containers share this network — check if it's multi-project
        if len(projects) <= 1 and all(c.compose_project for c in running):
            continue  # single compose project, this is expected behavior

        return [
            Finding(
                severity=Severity.INFO,
                category="flat-network",
                container="(all)",
                explanation=f"All {len(running)} running containers share the "
                f"`{net_name}` network. This means every container can reach every "
                f"other container.",
                fix="Create separate networks for services that need to communicate. "
                "Containers that don't need to talk to each other shouldn't share a "
                "network.",
            )
        ]
    return []


def _check_no_restart_policy(c: ContainerInfo) -> list[Finding]:
    """Check: No restart policy configured."""
    if c.status != "running":
        return []
    if c.restart_policy is None or c.restart_policy == "no":
        return [
            Finding(
                severity=Severity.INFO,
                category="no-restart-policy",
                container=c.name,
                explanation="No restart policy configured. This container will not "
                "automatically restart after a host reboot or crash.",
                fix="Set `restart: unless-stopped` or `restart: always` in docker-compose.yml.",
            )
        ]
    return []


def _check_stale_images(c: ContainerInfo) -> list[Finding]:
    """Check: Using :latest or untagged image with no pinned digest."""
    if c.status != "running":
        return []
    image = c.image
    # Catch both ":latest" and untagged images (e.g. "postgres" with no ":")
    is_latest = ":latest" in image
    is_untagged = ":" not in image and "/" not in image.split(":")[-1]
    if (is_latest or is_untagged) and c.image_digest is None:
        tag_desc = ":latest" if is_latest else "no version tag"
        return [
            Finding(
                severity=Severity.INFO,
                category="stale-image",
                container=c.name,
                explanation=f"Image `{image}` uses {tag_desc} with no pinned "
                f"digest. You cannot verify which version is actually running.",
                fix="Pin to a specific version tag (e.g. `nginx:1.25-alpine`) or use "
                "image digests.",
            )
        ]
    return []


def _check_no_log_rotation(c: ContainerInfo) -> list[Finding]:
    """Check: No log rotation configured — can fill disk."""
    if c.status != "running":
        return []
    # Only relevant for json-file and local drivers (the ones that write to disk)
    # Other drivers (syslog, journald, fluentd, etc.) handle rotation externally
    disk_drivers = {None, "json-file", "local"}
    if c.log_driver not in disk_drivers:
        return []
    has_max_size = any(k == "max-size" for k, _ in c.log_opts)
    if has_max_size:
        return []
    return [
        Finding(
            severity=Severity.INFO,
            category="no-log-rotation",
            container=c.name,
            explanation="No log rotation configured. Container logs will grow "
            "without limit and can fill the host disk.",
            fix="Add `logging: {options: {max-size: '10m', max-file: '3'}}` in "
            "docker-compose.yml, or set default log options in the Docker daemon config.",
        )
    ]


def _check_no_resource_limits(c: ContainerInfo) -> list[Finding]:
    """Check: No memory limit — can OOM the host."""
    if c.status != "running":
        return []
    if c.mem_limit:
        return []
    return [
        Finding(
            severity=Severity.INFO,
            category="no-resource-limits",
            container=c.name,
            explanation="No memory limit configured. A memory leak in this container "
            "can consume all host memory and crash other services.",
            fix="Set `deploy: {resources: {limits: {memory: '512M'}}}` in "
            "docker-compose.yml. Choose a limit based on the service's actual needs.",
        )
    ]


# Default threshold for image age (days)
_IMAGE_AGE_THRESHOLD_DAYS = 90


def _check_image_age(c: ContainerInfo) -> list[Finding]:
    """Check: Image is old — may be missing security patches."""
    if c.status != "running":
        return []
    if not c.image_created:
        return []
    try:
        # Docker timestamps are ISO 8601 with optional fractional seconds
        created_str = c.image_created.split(".")[0].rstrip("Z")
        created = datetime.fromisoformat(created_str).replace(tzinfo=UTC)
        age_days = (datetime.now(UTC) - created).days
    except (ValueError, TypeError):
        return []
    if age_days < _IMAGE_AGE_THRESHOLD_DAYS:
        return []
    return [
        Finding(
            severity=Severity.INFO,
            category="image-age",
            container=c.name,
            explanation=f"Image `{c.image}` was built {age_days} days ago. "
            f"It may be missing security patches.",
            fix="Pull the latest version of this image or rebuild from an updated base.",
        )
    ]


def _check_daemon_config(d: DaemonInfo) -> list[Finding]:
    """Check Docker daemon-level configuration."""
    findings: list[Finding] = []

    if not d.live_restore:
        findings.append(
            Finding(
                severity=Severity.INFO,
                category="daemon-live-restore",
                container="(daemon)",
                explanation="Live restore is disabled. Containers will stop when the "
                "Docker daemon restarts (e.g., during upgrades).",
                fix='Add `"live-restore": true` to /etc/docker/daemon.json.',
            )
        )

    # Check if daemon has default log rotation
    disk_drivers = {"json-file", "local"}
    if d.default_log_driver in disk_drivers:
        has_max_size = any(k == "max-size" for k, _ in d.default_log_opts)
        if not has_max_size:
            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    category="daemon-no-log-rotation",
                    container="(daemon)",
                    explanation=f"Docker daemon uses `{d.default_log_driver}` logging "
                    f"without default max-size. Every container without explicit log "
                    f"config will write unbounded logs to disk.",
                    fix='Add `"log-opts": {"max-size": "10m", "max-file": "3"}` to '
                    "/etc/docker/daemon.json.",
                )
            )

    return findings
