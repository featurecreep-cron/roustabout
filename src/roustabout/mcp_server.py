"""MCP server for Docker environment access with session isolation.

All output passes through sanitization and redaction before leaving.
Handlers are async, dispatching sync Docker API calls to threads.
"""

from __future__ import annotations

import re

import anyio
from mcp.server.fastmcp import FastMCP

from roustabout.audit_renderer import render_findings
from roustabout.auditor import audit
from roustabout.collector import collect
from roustabout.config import Config, load_config
from roustabout.connection import connect
from roustabout.dr_plan import generate as gen_dr_plan
from roustabout.generator import generate
from roustabout.models import DockerEnvironment, make_environment
from roustabout.redactor import redact, resolve_patterns, sanitize, sanitize_environment
from roustabout.renderer import render

RESPONSE_ENVELOPE = "[roustabout]"

mcp = FastMCP(
    "roustabout",
    instructions="Safe, read-only Docker environment visibility. Secrets are redacted.",
)


def _load_cfg() -> Config:
    """Load config, falling back to defaults on any error."""
    try:
        return load_config()
    except (FileNotFoundError, ValueError):
        return Config()


def _collect_redacted() -> tuple[DockerEnvironment, Config]:
    """Collect, sanitize, and redact the Docker environment."""
    cfg = _load_cfg()
    client = connect(cfg.docker_host)
    try:
        env = collect(client)
    finally:
        client.close()
    env = sanitize_environment(env)
    patterns = resolve_patterns(cfg.redact_patterns)
    return redact(env, patterns=patterns), cfg


def _envelope(text: str) -> str:
    """Wrap response in roustabout envelope for structural framing."""
    return f"{RESPONSE_ENVELOPE} {text}"


def _safe_error(exc: Exception) -> str:
    """Return a sanitized error string, stripping potential credential leaks."""
    msg = sanitize(str(exc))
    # Strip URL credentials (user:pass@host patterns)
    msg = re.sub(r"://[^@\s]+@", "://***@", msg)
    return msg


def _enforce_size_limit(text: str, cap: int = 262144) -> str:
    """Truncate response if it exceeds the byte limit."""
    encoded = text.encode("utf-8")
    if len(encoded) <= cap:
        return text
    truncated = encoded[:cap].decode("utf-8", errors="ignore")
    return truncated + "\n\n[Response truncated. Use container-specific queries for details.]"


@mcp.tool()
async def docker_snapshot(show_env: bool = False, show_labels: bool = True) -> str:
    """[OBSERVE] Generate a markdown snapshot of the Docker environment.

    Use when: you need an overview of all running containers.
    Returns: markdown with containers, ports, volumes, networks.

    Args:
        show_env: Include environment variables in output (redacted).
        show_labels: Include container labels in output.
    """
    try:
        env, cfg = await anyio.to_thread.run_sync(
            _collect_redacted, abandon_on_cancel=False
        )
    except Exception as exc:
        return _envelope(f"Error: Cannot connect to Docker: {_safe_error(exc)}")
    result = render(env, show_env=show_env, show_labels=show_labels)
    return _enforce_size_limit(result, cfg.response_size_cap)


@mcp.tool()
async def docker_audit() -> str:
    """[OBSERVE] Run security checks against the Docker environment.

    Use when: you want to find security issues in the Docker setup.
    Returns: prioritized findings with severity, explanation, and fix.
    """
    try:
        cfg = _load_cfg()

        def _run_audit() -> str:
            client = connect(cfg.docker_host)
            try:
                env = collect(client)
            finally:
                client.close()
            findings = audit(env, patterns=cfg.redact_patterns)
            return render_findings(findings)

        result = await anyio.to_thread.run_sync(
            _run_audit, abandon_on_cancel=False
        )
    except Exception as exc:
        return _envelope(f"Error: Cannot connect to Docker: {_safe_error(exc)}")
    return _enforce_size_limit(result, cfg.response_size_cap)


@mcp.tool()
async def docker_container(name: str) -> str:
    """[OBSERVE] Get details for a single named container.

    Use when: you need full details on one specific container.
    Returns: markdown for that container with env vars and labels.

    Args:
        name: The container name to look up.
    """
    name = sanitize(name)[:128]
    try:
        env, _cfg = await anyio.to_thread.run_sync(
            _collect_redacted, abandon_on_cancel=False
        )
    except Exception as exc:
        return _envelope(f"Error: Cannot connect to Docker: {_safe_error(exc)}")
    matches = [c for c in env.containers if c.name == name]
    if not matches:
        available = ", ".join(c.name for c in env.containers)
        return _envelope(f"Container '{name}' not found. Available: {available}")

    single_env = make_environment(
        containers=matches,
        generated_at=env.generated_at,
        docker_version=env.docker_version,
    )
    return render(single_env, show_env=True, show_labels=True)


@mcp.tool()
async def docker_networks() -> str:
    """[OBSERVE] Get network topology showing container connectivity.

    Use when: you need to understand which containers can talk to each other.
    Returns: network list with container memberships.
    """
    try:
        env, _cfg = await anyio.to_thread.run_sync(
            _collect_redacted, abandon_on_cancel=False
        )
    except Exception as exc:
        return _envelope(f"Error: Cannot connect to Docker: {_safe_error(exc)}")

    from roustabout.renderer import render_network_topology

    return render_network_topology(env)


@mcp.tool()
async def docker_generate(include_stopped: bool = False) -> str:
    """[OBSERVE] Generate docker-compose.yml from running containers.

    Use when: you need a compose file reconstructed from live state.
    Returns: YAML with secrets redacted.

    Args:
        include_stopped: Include stopped containers (default: running only).
    """
    try:
        env, cfg = await anyio.to_thread.run_sync(
            _collect_redacted, abandon_on_cancel=False
        )
    except Exception as exc:
        return _envelope(f"Error: Cannot connect to Docker: {_safe_error(exc)}")
    return generate(env, include_stopped=include_stopped)


@mcp.tool()
async def docker_dr_plan() -> str:
    """[OBSERVE] Generate a disaster recovery plan summary.

    Use when: you need rebuild instructions for the Docker environment.
    Returns: summary with one line per container showing name, image,
    volume count, network, and restore order position. Use
    docker_dr_detail for full per-container instructions.
    """
    try:
        env, cfg = await anyio.to_thread.run_sync(
            _collect_redacted, abandon_on_cancel=False
        )
    except Exception as exc:
        return _envelope(f"Error: Cannot connect to Docker: {_safe_error(exc)}")

    def _build_summary() -> str:
        from roustabout.dr_plan import _resolve_dependency_order

        ordered = _resolve_dependency_order(env)
        lines = [
            f"# DR Plan Summary ({len(ordered)} containers)",
            f"Generated: {env.generated_at}",
            "",
            "| # | Container | Image | Volumes | Networks | Status |",
            "|---|-----------|-------|---------|----------|--------|",
        ]
        for i, c in enumerate(ordered, 1):
            nets = ", ".join(n.name for n in c.networks) or c.network_mode or "default"
            lines.append(
                f"| {i} | {c.name} | {c.image} | {len(c.mounts)} | {nets} | {c.status} |"
            )
        lines.append("")
        lines.append("Use `docker_dr_detail(container_name)` for full restore steps.")
        return "\n".join(lines)

    return _enforce_size_limit(_build_summary(), cfg.response_size_cap)


@mcp.tool()
async def docker_dr_detail(name: str) -> str:
    """[OBSERVE] Get full DR restore instructions for one container.

    Use when: you need step-by-step restore commands for a specific container.
    Returns: volumes, docker run command, network setup, verification steps.

    Args:
        name: The container name to get DR detail for.
    """
    name = sanitize(name)[:128]
    try:
        env, cfg = await anyio.to_thread.run_sync(
            _collect_redacted, abandon_on_cancel=False
        )
    except Exception as exc:
        return _envelope(f"Error: Cannot connect to Docker: {_safe_error(exc)}")

    matches = [c for c in env.containers if c.name == name]
    if not matches:
        available = ", ".join(c.name for c in env.containers)
        return _envelope(f"Container '{name}' not found. Available: {available}")

    single_env = make_environment(
        containers=matches,
        generated_at=env.generated_at,
        docker_version=env.docker_version,
    )
    return _enforce_size_limit(gen_dr_plan(single_env), cfg.response_size_cap)


@mcp.tool()
async def docker_findings(
    severity: str | None = None,
    container: str | None = None,
) -> str:
    """[OBSERVE] Get structured security findings with remediation actions.

    Use when: you need machine-readable audit findings or want to fix issues.
    Returns: JSON array of findings with keys, severity, remediation actions.

    Args:
        severity: Filter by severity (critical, warning, info).
        container: Filter by container name.
    """
    import json as _json

    try:
        env, cfg = await anyio.to_thread.run_sync(
            _collect_redacted, abandon_on_cancel=False
        )
    except Exception as exc:
        return _envelope(f"Error: {_safe_error(exc)}")

    from roustabout.auditor import audit as run_audit

    findings = run_audit(
        env, patterns=cfg.redact_patterns,
        severity_overrides=cfg.severity_overrides,
    )

    if severity:
        severity = sanitize(severity).lower()
        findings = [f for f in findings if f.severity.value == severity]

    if container:
        container = sanitize(container)[:128]
        findings = [f for f in findings if f.container == container]

    result = [
        {
            "key": f.key,
            "severity": f.severity.value,
            "category": f.category,
            "container": f.container,
            "explanation": f.explanation,
            "fix": f.fix,
            "remediation": f.remediation,
            "remediation_action": f.remediation_action,
            "remediation_tier": f.remediation_tier,
        }
        for f in findings
    ]

    return _enforce_size_limit(
        _json.dumps(result, indent=2), cfg.response_size_cap,
    )


@mcp.tool()
async def docker_manage(
    action: str,
    container_name: str,
    dry_run: bool = False,
) -> str:
    """[OPERATE] Start, stop, or restart a container.

    Use when: you need to manage container lifecycle.
    Returns: result of the operation.

    Args:
        action: One of 'start', 'stop', 'restart'.
        container_name: The container to act on.
        dry_run: Preview without executing (default: false).
    """
    container_name = sanitize(container_name)[:128]
    action = sanitize(action)[:32]

    valid_actions = {"start", "stop", "restart"}
    if action not in valid_actions:
        return _envelope(
            f"Invalid action '{action}'. Must be one of: {', '.join(sorted(valid_actions))}"
        )

    def _run() -> str:
        from roustabout.gateway import MutationCommand
        from roustabout.gateway import execute as gw_execute
        from roustabout.session import (
            DockerSession,
            PermissionTier,
            RateLimiter,
            Session,
            _capabilities_for_tier,
        )

        cfg = _load_cfg()
        client = connect(cfg.docker_host)
        docker_session = DockerSession(
            client=client, host=cfg.docker_host or "localhost",
        )
        session = Session(
            id="mcp",
            docker=docker_session,
            tier=PermissionTier.OPERATE,
            capabilities=_capabilities_for_tier(PermissionTier.OPERATE),
            rate_limiter=RateLimiter(),
            created_at="",
        )

        cmd = MutationCommand(
            action=action,
            target=container_name,
            dry_run=dry_run,
        )

        try:
            result = gw_execute(cmd, session=session)
        finally:
            client.close()

        if result.success:
            if result.result == "dry-run":
                return f"[dry-run] Would {action} {container_name}"
            return f"{action.capitalize()}ed {container_name}"
        return f"Failed: {result.error or result.gate_failed}"

    try:
        msg = await anyio.to_thread.run_sync(_run, abandon_on_cancel=False)
    except Exception as exc:
        return _envelope(f"Error: {_safe_error(exc)}")
    return _envelope(msg)


def main() -> None:
    """Entry point for roustabout-mcp."""
    mcp.run()


if __name__ == "__main__":
    main()
