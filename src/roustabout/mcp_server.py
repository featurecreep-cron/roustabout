"""MCP server for safe, read-only Docker environment access.

All output passes through the redactor before leaving. Secrets never
reach the AI model. No mutation operations are exposed.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from roustabout.audit_renderer import render_findings
from roustabout.auditor import audit
from roustabout.collector import collect
from roustabout.config import load_config
from roustabout.connection import connect
from roustabout.generator import generate
from roustabout.models import make_environment
from roustabout.redactor import redact, resolve_patterns
from roustabout.renderer import render

mcp = FastMCP(
    "roustabout",
    instructions="Safe, read-only Docker environment visibility. Secrets are redacted.",
)


def _load_cfg():
    """Load config, falling back to defaults on any error."""
    try:
        return load_config()
    except (FileNotFoundError, ValueError):
        from roustabout.config import Config

        return Config()


def _collect_redacted():
    """Collect and redact the Docker environment using config patterns."""
    cfg = _load_cfg()
    client = connect(cfg.docker_host)
    try:
        env = collect(client)
    finally:
        client.close()
    patterns = resolve_patterns(cfg.redact_patterns)
    return redact(env, patterns=patterns), cfg


@mcp.tool()
def docker_snapshot(show_env: bool = False, show_labels: bool = True) -> str:
    """Generate a complete markdown snapshot of the Docker environment.

    Returns structured markdown with all containers, their configuration,
    ports, volumes, networks, and metadata. Secrets are automatically redacted.

    Args:
        show_env: Include environment variables in output (redacted).
        show_labels: Include container labels in output.
    """
    try:
        env, _cfg = _collect_redacted()
    except Exception as exc:
        return f"Error: Cannot connect to Docker: {exc}"
    return render(env, show_env=show_env, show_labels=show_labels)


@mcp.tool()
def docker_audit() -> str:
    """Run security checks against the Docker environment.

    Returns prioritized findings covering: Docker socket exposure, secrets in
    environment variables, exposed sensitive ports, missing health checks,
    running as root, restart loops, OOM kills, flat networking, missing
    restart policies, and stale images.
    """
    # Audit needs unredacted env to detect secrets by key name.
    # Rendered output only includes key names, never secret values.
    try:
        cfg = _load_cfg()
        client = connect(cfg.docker_host)
        try:
            env = collect(client)
        finally:
            client.close()
    except Exception as exc:
        return f"Error: Cannot connect to Docker: {exc}"
    findings = audit(env, patterns=cfg.redact_patterns)
    return render_findings(findings)


@mcp.tool()
def docker_container(name: str) -> str:
    """Get details for a single named container.

    Args:
        name: The container name to look up.

    Returns markdown for that container, or an error message if not found.
    Secrets are automatically redacted.
    """
    try:
        env, _cfg = _collect_redacted()
    except Exception as exc:
        return f"Error: Cannot connect to Docker: {exc}"
    matches = [c for c in env.containers if c.name == name]
    if not matches:
        available = ", ".join(c.name for c in env.containers)
        return f"Container '{name}' not found. Available: {available}"

    single_env = make_environment(
        containers=matches,
        generated_at=env.generated_at,
        docker_version=env.docker_version,
    )
    return render(single_env, show_env=True, show_labels=True)


@mcp.tool()
def docker_networks() -> str:
    """Get network topology showing which containers share which networks.

    Returns a summary of Docker networks and their container memberships.
    Useful for understanding container connectivity and isolation.
    """
    try:
        env, _cfg = _collect_redacted()
    except Exception as exc:
        return f"Error: Cannot connect to Docker: {exc}"

    from roustabout.renderer import render_network_topology

    return render_network_topology(env)


@mcp.tool()
def docker_generate(include_stopped: bool = False) -> str:
    """Generate a docker-compose.yml from running containers.

    Reconstructs a compose file from the live Docker environment. Environment
    variable secrets are automatically redacted — the output is safe to share
    but will need real values filled in before use.

    Args:
        include_stopped: Include stopped containers (default: running only).
    """
    try:
        env, cfg = _collect_redacted()
    except Exception as exc:
        return f"Error: Cannot connect to Docker: {exc}"
    return generate(env, include_stopped=include_stopped)


def main():
    """Entry point for roustabout-mcp."""
    mcp.run()


if __name__ == "__main__":
    main()
