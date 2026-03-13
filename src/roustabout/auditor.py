"""Security auditor for Docker environments.

Operates on the model layer (DockerEnvironment), not the Docker API.
Can audit live snapshots or saved/loaded environments.
All checks are deterministic and independently testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from roustabout.models import ContainerInfo, DockerEnvironment
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

# Host paths that should not be bind-mounted into containers
_SENSITIVE_HOST_PATHS = (
    "/etc",
    "/root",
    "/home",
    "/var/run/docker.sock",  # handled separately by docker-socket check
)

# Specific files under sensitive paths that are safe to mount (read-only, no secrets)
_SAFE_MOUNT_EXCEPTIONS = (
    "/etc/localtime",
    "/etc/timezone",
    "/etc/hosts",
    "/etc/resolv.conf",
)


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
        findings.extend(_check_sensitive_host_mounts(container))
        findings.extend(_check_host_network(container))
        findings.extend(_check_secrets_in_env(container, active_patterns))
        findings.extend(_check_sensitive_port_binding(container))
        findings.extend(_check_no_health_check(container))
        findings.extend(_check_running_as_root(container))
        findings.extend(_check_restart_loops(container))
        findings.extend(_check_oom_killed(container))
        findings.extend(_check_no_restart_policy(container))
        findings.extend(_check_stale_images(container))

    findings.extend(_check_flat_networking(env))

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
            f = Finding(
                severity=_SEVERITY_MAP[new_level],
                category=f.category,
                container=f.container,
                explanation=f.explanation,
                fix=f.fix,
                detail=f.detail,
            )
        result.append(f)
    return result


def _check_docker_socket(c: ContainerInfo) -> list[Finding]:
    """Check #1: Docker socket mounted — full host control."""
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
    """Check #11: Container running in privileged mode."""
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


def _check_sensitive_host_mounts(c: ContainerInfo) -> list[Finding]:
    """Check #12: Sensitive host paths mounted into container."""
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
            if source == sensitive or source.startswith(sensitive + "/"):
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
    """Check #13: Container using host network mode."""
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


def _check_secrets_in_env(
    c: ContainerInfo,
    patterns: tuple[str, ...],
) -> list[Finding]:
    """Check #2: Secrets visible in environment variables."""
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
    """Check #3: Database/admin ports bound to all interfaces."""
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
    """Check #4: No health check configured."""
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
    """Check #5: Running as root with elevated access.

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
    """Check #6: Container has restarted excessively."""
    if c.restart_count > 5:
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
    """Check #7: Container was OOM killed."""
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
    """Check #8: All containers on the same network."""
    running = [c for c in env.containers if c.status == "running"]
    if len(running) < 3:
        return []

    # Collect all networks used by running containers
    network_members: dict[str, list[str]] = {}
    for c in running:
        for n in c.networks:
            network_members.setdefault(n.name, []).append(c.name)

    # Check if there's one network that contains all running containers
    for net_name, members in network_members.items():
        if len(members) == len(running) and net_name != "host":
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
    """Check #9: No restart policy configured."""
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
    """Check #10: Using :latest tag with no pinned digest."""
    if c.status != "running":
        return []
    if ":latest" in c.image and c.image_digest is None:
        return [
            Finding(
                severity=Severity.INFO,
                category="stale-image",
                container=c.name,
                explanation=f"Image `{c.image}` uses the `:latest` tag with no pinned "
                f"digest. You cannot verify which version is actually running.",
                fix="Pin to a specific version tag (e.g. `nginx:1.25-alpine`) or use "
                "image digests.",
            )
        ]
    return []


def render_findings(
    findings: list[Finding],
    state_entries: dict | None = None,
    hide_accepted: bool = False,
) -> str:
    """Render audit findings as structured markdown.

    Args:
        findings: List of findings from audit().
        state_entries: Optional dict mapping finding keys to StateEntry objects.
        hide_accepted: If True, suppress accepted and false-positive findings.
    """
    from roustabout.state import FindingState, apply_state

    if state_entries is None:
        state_entries = {}

    annotated = apply_state(findings, state_entries)

    # Separate actionable from dismissed
    _suppressed_states = {FindingState.ACCEPTED, FindingState.FALSE_POSITIVE}
    if hide_accepted:
        annotated = [
            (f, s) for f, s in annotated if s is None or s.state not in _suppressed_states
        ]

    if not annotated:
        return "# Security Audit\n\nNo findings.\n"

    actionable = [(f, s) for f, s in annotated if s is None or s.state not in _suppressed_states]
    dismissed = [(f, s) for f, s in annotated if s is not None and s.state in _suppressed_states]

    lines = ["# Security Audit", ""]

    # Summary counts
    all_findings = [f for f, _ in annotated]
    critical = [f for f in all_findings if f.severity == Severity.CRITICAL]
    warnings = [f for f in all_findings if f.severity == Severity.WARNING]
    infos = [f for f in all_findings if f.severity == Severity.INFO]

    summary = (
        f"**{len(all_findings)} findings:** "
        f"{len(critical)} critical, {len(warnings)} warning, {len(infos)} info"
    )
    if dismissed:
        summary += f" ({len(actionable)} actionable, {len(dismissed)} accepted)"
    lines.append(summary)
    lines.append("")

    # Summary table
    lines.append("| Container | Category | Severity | Status |")
    lines.append("|-----------|----------|----------|--------|")
    for finding, state in annotated:
        status = "Open"
        if state is not None:
            status = state.state.value.title()
        lines.append(
            f"| {finding.container} | {finding.category} "
            f"| {finding.severity.value.title()} | {status} |"
        )
    lines.append("")

    # Table of contents
    lines.append("## Contents")
    lines.append("")
    for sev_label in ("Critical", "Warning", "Info"):
        sev_findings = [(f, s) for f, s in annotated if f.severity.value.title() == sev_label]
        if sev_findings:
            lines.append(f"- [{sev_label} ({len(sev_findings)})](#{sev_label.lower()})")
    lines.append("")

    # Findings by severity
    current_severity = None
    for finding, state in annotated:
        if finding.severity != current_severity:
            current_severity = finding.severity
            lines.append(f"## {current_severity.value.title()}")
            lines.append("")

        state_label = ""
        if state is not None:
            state_label = f" [{state.state.value.upper()}]"
        lines.append(f"### {finding.container} — {finding.category}{state_label}")
        lines.append("")
        lines.append(finding.explanation)
        lines.append("")
        if state is not None:
            label = "Accepted" if state.state == FindingState.ACCEPTED else "False positive"
            lines.append(f"**{label}:** {state.reason}")
            lines.append("")
        else:
            lines.append(f"**Fix:** {finding.fix}")
            lines.append("")

    return "\n".join(lines) + "\n"
