"""CLI entry point for roustabout.

Provides `roustabout snapshot` and `roustabout audit` commands for generating
Docker environment documentation and security findings.
"""

from __future__ import annotations

import json as _json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import click
import docker

from roustabout.audit_renderer import render_findings
from roustabout.auditor import audit as run_audit
from roustabout.cli.backend import get_backend
from roustabout.collector import collect
from roustabout.config import Config, load_config
from roustabout.connection import connect
from roustabout.generator import generate as run_generate
from roustabout.json_output import environment_to_json, findings_to_json
from roustabout.models import filter_by_project
from roustabout.redactor import redact as redact_env
from roustabout.redactor import resolve_patterns
from roustabout.renderer import render
from roustabout.state import FindingState, load_state, set_finding_state

F = TypeVar("F", bound=Callable[..., Any])


_CONNECTION_CONFIG = Path.home() / ".config" / "roustabout" / "config.toml"


def _is_remote() -> bool:
    """True when CLI should route commands through the REST API."""
    return bool(os.environ.get("ROUSTABOUT_URL"))


def _load_connection_config() -> tuple[str | None, str | None]:
    """Load URL and API key from user config file."""
    import tomllib

    if not _CONNECTION_CONFIG.exists():
        return None, None
    try:
        data = tomllib.loads(_CONNECTION_CONFIG.read_text())
        return data.get("url"), data.get("api_key")
    except Exception:
        return None, None


def _run_remote(
    method_name: str,
    output: str | None = None,
    text_key: str | None = None,
    **kwargs: Any,
) -> None:
    """Execute a read command via HTTPBackend and print the result."""
    try:
        backend = get_backend(command_is_mutation=False)
        data = getattr(backend, method_name)(**kwargs)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    if text_key and text_key in data:
        text = data[text_key]
    else:
        text = _json.dumps(data, indent=2)

    if output:
        Path(output).write_text(text)
        click.echo(f"Output written to {output}")
    else:
        click.echo(text)


def _connect(docker_host: str | None) -> docker.DockerClient:
    """Connect to Docker, raising ClickException on failure."""
    try:
        return connect(docker_host)
    except Exception as exc:
        raise click.ClickException(f"Cannot connect to Docker: {exc}")


def _load_cfg(config_path: str | None, **overrides: Any) -> Config:
    """Load config and apply overrides."""
    try:
        cfg = load_config(Path(config_path) if config_path else None)
    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(str(exc))
    return cfg.merge(**{k: v for k, v in overrides.items() if v is not None})


def _state_path_option() -> Callable[[F], F]:
    return click.option(
        "--state-file",
        type=click.Path(),
        default=None,
        help="Path to state file (default: roustabout.state.toml).",
    )


@click.group()
@click.version_option(package_name="roustabout")
@click.option(
    "--url",
    envvar="ROUSTABOUT_URL",
    default=None,
    help="Roustabout server URL for remote mode (env: ROUSTABOUT_URL).",
)
@click.option(
    "--api-key",
    envvar="ROUSTABOUT_API_KEY",
    default=None,
    help="API key for server authentication (env: ROUSTABOUT_API_KEY).",
)
def main(url: str | None, api_key: str | None) -> None:
    """Roustabout — structured markdown documentation of Docker environments.

    Local mode (default): connects directly to the Docker socket.

    Remote mode: pass --url to connect to a roustabout server.

    \b
    Examples:
      roustabout snapshot                          # local Docker
      roustabout --url http://server:8077 snapshot # remote server
      ROUSTABOUT_URL=http://server:8077 roustabout snapshot
    """
    # Load URL/key from config file if not provided via flags or env
    if not url and not os.environ.get("ROUSTABOUT_URL"):
        url, api_key_from_config = _load_connection_config()
        if not api_key:
            api_key = api_key_from_config

    if url:
        os.environ["ROUSTABOUT_URL"] = url
    if api_key:
        os.environ["ROUSTABOUT_API_KEY"] = api_key


@main.command()
@click.option("--show-env", is_flag=True, default=None, help="Include environment variables.")
@click.option("--no-labels", is_flag=True, default=False, help="Exclude container labels.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
@click.option("--project", "filter_project", default=None, help="Filter by compose project.")
@click.option(
    "--containers",
    default=None,
    help="Comma-separated container names to include.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format.",
)
def snapshot(
    show_env: bool | None,
    no_labels: bool,
    output: str | None,
    config_path: str | None,
    docker_host: str | None,
    filter_project: str | None,
    containers: str | None,
    output_format: str,
) -> None:
    """Generate a markdown snapshot of the Docker environment."""
    if _is_remote():
        try:
            backend = get_backend(command_is_mutation=False)
            raw = backend.snapshot(fmt=output_format)
        except RuntimeError as exc:
            raise click.ClickException(str(exc))

        text = raw if isinstance(raw, str) else _json.dumps(raw, indent=2)

        if output:
            Path(output).write_text(text)
            click.echo(f"Snapshot written to {output}")
        else:
            click.echo(text)
        return

    overrides: dict[str, Any] = {
        "show_env": show_env,
        "output": output,
        "docker_host": docker_host,
    }
    if no_labels:
        overrides["show_labels"] = False
    cfg = _load_cfg(config_path, **overrides)

    client = _connect(cfg.docker_host)
    container_filter = containers.split(",") if containers else None
    env = collect(client, containers=container_filter)

    if filter_project:
        env = filter_by_project(env, filter_project)

    patterns = resolve_patterns(cfg.redact_patterns)
    env = redact_env(env, patterns=patterns)

    if output_format == "json":
        result = environment_to_json(env)
    else:
        result = render(env, show_env=cfg.show_env, show_labels=cfg.show_labels)

    if cfg.output:
        Path(cfg.output).write_text(result)
        click.echo(f"Snapshot written to {cfg.output}")
    else:
        click.echo(result)


@main.command()
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
@click.option("--project", "filter_project", default=None, help="Filter by compose project.")
@click.option(
    "--containers",
    default=None,
    help="Comma-separated container names to include.",
)
@_state_path_option()
@click.option(
    "--hide-accepted",
    is_flag=True,
    default=False,
    help="Hide accepted and false-positive findings.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format.",
)
def audit(
    output: str | None,
    config_path: str | None,
    docker_host: str | None,
    filter_project: str | None,
    containers: str | None,
    state_file: str | None,
    hide_accepted: bool,
    output_format: str,
) -> None:
    """Run security checks against the Docker environment."""
    if _is_remote():
        try:
            backend = get_backend(command_is_mutation=False)
            raw = backend.audit(fmt=output_format)
        except RuntimeError as exc:
            raise click.ClickException(str(exc))

        text = raw if isinstance(raw, str) else _json.dumps(raw, indent=2)

        if output:
            Path(output).write_text(text)
            click.echo(f"Audit written to {output}")
        else:
            click.echo(text)
        return

    cfg = _load_cfg(config_path, output=output, docker_host=docker_host)

    client = _connect(cfg.docker_host)
    container_filter = containers.split(",") if containers else None
    env = collect(client, containers=container_filter)

    if filter_project:
        env = filter_by_project(env, filter_project)

    findings = run_audit(
        env, patterns=cfg.redact_patterns, severity_overrides=cfg.severity_overrides
    )

    if output_format == "json":
        result = findings_to_json(findings)
    else:
        state_entries = load_state(Path(state_file) if state_file else None)
        result = render_findings(
            findings, state_entries=state_entries, hide_accepted=hide_accepted
        )

    if cfg.output:
        Path(cfg.output).write_text(result)
        click.echo(f"Audit written to {cfg.output}")
    else:
        click.echo(result)


@main.command("generate")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
@click.option(
    "--include-stopped",
    is_flag=True,
    default=False,
    help="Include stopped containers.",
)
@click.option("--project", default=None, help="Set compose project name.")
@click.option(
    "--filter-project", default=None, help="Only include containers from this compose project."
)
@click.option(
    "--containers",
    default=None,
    help="Comma-separated container names to include.",
)
@click.option(
    "--services",
    default=None,
    help="Comma-separated service names to include in output.",
)
@click.option(
    "--redact/--no-redact",
    default=True,
    help="Redact secrets in environment variables (default: redact).",
)
def generate(
    output: str | None,
    config_path: str | None,
    docker_host: str | None,
    include_stopped: bool,
    project: str | None,
    filter_project: str | None,
    containers: str | None,
    services: str | None,
    redact: bool,
) -> None:
    """Generate a docker-compose.yml from running containers."""
    cfg = _load_cfg(config_path, output=output, docker_host=docker_host)

    client = _connect(cfg.docker_host)
    container_filter = containers.split(",") if containers else None
    env = collect(client, containers=container_filter)

    if filter_project:
        env = filter_by_project(env, filter_project)

    if redact:
        patterns = resolve_patterns(cfg.redact_patterns)
        env = redact_env(env, patterns=patterns)

    svc_list = services.split(",") if services else None
    yaml_output = run_generate(
        env, include_stopped=include_stopped, project_name=project, services=svc_list
    )

    if cfg.output:
        Path(cfg.output).write_text(yaml_output)
        click.echo(f"Compose file written to {cfg.output}")
    else:
        click.echo(yaml_output)


@main.command("dr-plan")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
@click.option("--project", "filter_project", default=None, help="Filter by compose project.")
@click.option(
    "--containers",
    default=None,
    help="Comma-separated container names to include.",
)
@click.option(
    "--strip-versions",
    is_flag=True,
    default=False,
    help="Remove image version tags from output (useful when sharing externally).",
)
def dr_plan(
    output: str | None,
    config_path: str | None,
    docker_host: str | None,
    filter_project: str | None,
    containers: str | None,
    strip_versions: bool,
) -> None:
    """Generate a disaster recovery plan from running containers."""
    if _is_remote():
        _run_remote("dr_plan", output=output, text_key="plan")
        return

    from roustabout.dr_plan import generate as gen_dr
    from roustabout.redactor import sanitize_environment

    cfg = _load_cfg(config_path, output=output, docker_host=docker_host)
    # CLI flag overrides config; config default is False
    should_strip = strip_versions or cfg.strip_versions

    client = _connect(cfg.docker_host)
    container_filter = containers.split(",") if containers else None
    env = collect(client, containers=container_filter)

    if filter_project:
        env = filter_by_project(env, filter_project)

    env = sanitize_environment(env)
    patterns = resolve_patterns(cfg.redact_patterns)
    env = redact_env(env, patterns=patterns)

    result = gen_dr(env, strip_versions=should_strip)

    if cfg.output:
        Path(cfg.output).write_text(result)
        click.echo(f"DR plan written to {cfg.output}")
    else:
        click.echo(result)


@main.command("health")
@click.option("--container", default=None, help="Filter to a single container.")
@click.option("--deep", is_flag=True, default=False, help="Deep health checks (port + probes).")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def health_cmd(
    container: str | None,
    deep: bool,
    config_path: str | None,
    docker_host: str | None,
    as_json: bool,
) -> None:
    """Show container health status.

    \b
    Without --deep: Docker health status (restart count, OOM, healthcheck).
    With --deep: adds port checks and service probes.
    """
    if _is_remote() and not deep:
        _run_remote("health", name=container)
        return

    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)

    if deep:
        from roustabout.deep_health import (
            check_container_health,
            check_environment_health,
        )
        from roustabout.session import DockerSession

        docker_session = DockerSession(client=client, host=cfg.docker_host or "localhost")

        if container:
            result = check_container_health(client, container, docker_session=docker_session)
            results = [result]
        else:
            env_health = check_environment_health(client, docker_session=docker_session)
            results = list(env_health.results)

        if as_json:
            click.echo(
                _json.dumps(
                    [
                        {
                            "container_name": r.container_name,
                            "profile": r.profile,
                            "docker_health": r.docker_health,
                            "port_open": r.port_open,
                            "service_healthy": r.service_healthy,
                            "overall": r.overall,
                            "checks_performed": list(r.checks_performed),
                        }
                        for r in results
                    ],
                    indent=2,
                )
            )
        else:
            for r in results:
                icon = {"healthy": "✓", "degraded": "~", "unhealthy": "✗"}.get(r.overall, "?")
                click.echo(f"  {icon} {r.container_name}: {r.overall} (profile={r.profile})")
                if r.docker_health:
                    click.echo(f"    Docker health: {r.docker_health}")
                if r.port_open is not None:
                    click.echo(f"    Port open: {r.port_open}")
                if r.service_healthy is not None:
                    click.echo(f"    Service healthy: {r.service_healthy}")
    else:
        from roustabout.health_stats import collect_health, render_health

        healths = collect_health(client)
        if container:
            healths = [h for h in healths if h.name == container]
        click.echo(render_health(healths))


@main.command("stats")
@click.option("--container", default=None, help="Filter to a single container.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
def stats_cmd(
    container: str | None,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Show container resource usage."""
    from roustabout.health_stats import collect_stats, render_stats

    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)
    stats = collect_stats(client, target=container)
    click.echo(render_stats(stats))


@main.command("logs")
@click.argument("container_name")
@click.option("--tail", default=100, help="Number of lines (default 100).")
@click.option("--since", default=None, help="Time filter (5m, 1h, or ISO 8601).")
@click.option("--grep", default=None, help="Substring filter.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
def logs_cmd(
    container_name: str,
    tail: int,
    since: str | None,
    grep: str | None,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Read container logs."""
    if _is_remote():
        _run_remote(
            "logs", text_key="lines", name=container_name, tail=tail, since=since, grep=grep
        )
        return

    from roustabout.log_access import (
        ContainerNotFoundError,
        UnsupportedLogDriver,
        collect_logs,
    )

    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)
    try:
        result = collect_logs(
            client,
            container_name,
            tail=tail,
            since=since,
            grep=grep,
        )
        click.echo(result)
    except ContainerNotFoundError:
        raise click.ClickException(f"Container '{container_name}' not found")
    except UnsupportedLogDriver as e:
        raise click.ClickException(str(e))


@main.command("stop")
@click.argument("container_name")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without executing.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
def stop_cmd(
    container_name: str,
    dry_run: bool,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Stop a running container."""
    _run_mutation("stop", container_name, dry_run, config_path, docker_host)


@main.command("start")
@click.argument("container_name")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without executing.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
def start_cmd(
    container_name: str,
    dry_run: bool,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Start a stopped container."""
    _run_mutation("start", container_name, dry_run, config_path, docker_host)


@main.command("restart")
@click.argument("container_name")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without executing.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
def restart_cmd(
    container_name: str,
    dry_run: bool,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Restart a container."""
    _run_mutation("restart", container_name, dry_run, config_path, docker_host)


@main.command("recreate")
@click.argument("container_name")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without executing.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
def recreate_cmd(
    container_name: str,
    dry_run: bool,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Recreate a container (stop, remove, create with same config, start)."""
    _run_mutation("recreate", container_name, dry_run, config_path, docker_host)


def _run_mutation(
    action: str,
    container_name: str,
    dry_run: bool,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Execute a mutation through the backend (remote) or gateway (local)."""
    try:
        backend = get_backend(command_is_mutation=True)
    except RuntimeError as exc:
        if "No roustabout server found" in str(exc):
            # No server available — fall back to direct gateway
            _run_mutation_direct(action, container_name, dry_run, config_path, docker_host)
            return
        raise click.ClickException(str(exc))

    try:
        result = backend.mutate(container_name, action, dry_run=dry_run)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    status = result.get("result", "")
    if status == "dry-run":
        click.echo(f"[dry-run] Would {action} {container_name}")
    elif status == "success":
        click.echo(f"{action.capitalize()}ed {container_name}")
    else:
        error = result.get("error", result.get("gate_failed", "unknown error"))
        raise click.ClickException(f"{action} failed: {error}")


def _run_mutation_direct(
    action: str,
    container_name: str,
    dry_run: bool,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Execute a mutation via direct gateway call (local Docker only)."""
    from roustabout.gateway import MutationCommand
    from roustabout.gateway import execute as gw_execute
    from roustabout.session import (
        DockerSession,
        PermissionTier,
        RateLimiter,
        Session,
        capabilities_for_tier,
    )

    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)

    docker_session = DockerSession(client=client, host=cfg.docker_host or "localhost")
    session = Session(
        id="cli",
        docker=docker_session,
        tier=PermissionTier.OPERATE,
        capabilities=capabilities_for_tier(PermissionTier.OPERATE),
        rate_limiter=RateLimiter(),
        created_at="",
    )

    cmd = MutationCommand(
        action=action,
        target=container_name,
        dry_run=dry_run,
    )

    result = gw_execute(cmd, session=session)

    if result.success:
        if result.result == "dry-run":
            click.echo(f"[dry-run] Would {action} {container_name}")
        else:
            click.echo(f"{action.capitalize()}ed {container_name}")
    else:
        raise click.ClickException(f"{action} failed: {result.error or result.gate_failed}")


@main.command("diff")
@click.argument("old_snapshot", type=click.Path(exists=True))
@click.argument("new_snapshot", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def diff_cmd(old_snapshot: str, new_snapshot: str, output: str | None) -> None:
    """Compare two JSON snapshots and show what changed.

    Usage: roustabout diff snapshot-old.json snapshot-new.json
    """
    from roustabout.diff import diff_snapshots, render_diff

    result = diff_snapshots(Path(old_snapshot), Path(new_snapshot))
    markdown = render_diff(result)

    if output:
        Path(output).write_text(markdown)
        click.echo(f"Diff written to {output}")
    else:
        click.echo(markdown)


@main.command("accept")
@click.argument("finding_key")
@click.argument("reason")
@_state_path_option()
def accept_finding(finding_key: str, reason: str, state_file: str | None) -> None:
    """Mark a finding as accepted (known risk, reviewed)."""
    path = set_finding_state(
        finding_key,
        FindingState.ACCEPTED,
        reason,
        Path(state_file) if state_file else None,
    )
    click.echo(f"Marked {finding_key} as accepted. State saved to {path}")


@main.command("false-positive")
@click.argument("finding_key")
@click.argument("reason")
@_state_path_option()
def false_positive_finding(finding_key: str, reason: str, state_file: str | None) -> None:
    """Mark a finding as a false positive."""
    path = set_finding_state(
        finding_key,
        FindingState.FALSE_POSITIVE,
        reason,
        Path(state_file) if state_file else None,
    )
    click.echo(f"Marked {finding_key} as false-positive. State saved to {path}")


@main.command("resolve")
@click.argument("finding_key")
@click.argument("reason")
@_state_path_option()
def resolve_finding(finding_key: str, reason: str, state_file: str | None) -> None:
    """Mark a finding as resolved (fixed)."""
    path = set_finding_state(
        finding_key,
        FindingState.RESOLVED,
        reason,
        Path(state_file) if state_file else None,
    )
    click.echo(f"Marked {finding_key} as resolved. State saved to {path}")


@main.command("connect")
@click.argument("url")
@click.option("--api-key", "key", prompt=True, hide_input=True, help="API key for authentication.")
def connect_cmd(url: str, key: str) -> None:
    """Save a server connection for future commands.

    \b
    Example:
      roustabout connect http://server:8077
      roustabout snapshot   # now uses the saved server
    """
    import httpx

    # Verify the connection
    try:
        resp = httpx.get(
            f"{url.rstrip('/')}/health",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10.0,
        )
    except httpx.ConnectError:
        raise click.ClickException(f"Cannot reach {url}")

    if not resp.is_success:
        raise click.ClickException(f"Server returned {resp.status_code}")

    health = resp.json()
    server_version = health.get("version", "unknown")

    # Write config
    config_dir = _CONNECTION_CONFIG.parent
    config_dir.mkdir(parents=True, exist_ok=True)

    # Preserve existing config, update connection fields
    existing = ""
    if _CONNECTION_CONFIG.exists():
        existing = _CONNECTION_CONFIG.read_text()

    # Simple TOML write — only url and api_key at top level
    import tomllib

    try:
        data = tomllib.loads(existing) if existing else {}
    except Exception:
        data = {}

    data["url"] = url.rstrip("/")
    data["api_key"] = key

    # Write back as TOML
    lines = []
    for k, v in data.items():
        if isinstance(v, str):
            lines.append(f'{k} = "{v}"')
        elif isinstance(v, bool):
            lines.append(f"{k} = {'true' if v else 'false'}")
        elif isinstance(v, dict):
            lines.append(f"\n[{k}]")
            for sk, sv in v.items():
                lines.append(f'{sk} = "{sv}"' if isinstance(sv, str) else f"{sk} = {sv}")
        else:
            lines.append(f"{k} = {v}")

    _CONNECTION_CONFIG.write_text("\n".join(lines) + "\n")

    click.echo(f"Connected to {url} (server v{server_version})")
    click.echo(f"Config saved to {_CONNECTION_CONFIG}")
    click.echo("Run 'roustabout snapshot' to verify.")


@main.command("disconnect")
def disconnect_cmd() -> None:
    """Remove saved server connection."""
    if not _CONNECTION_CONFIG.exists():
        click.echo("No saved connection.")
        return

    import tomllib

    try:
        data = tomllib.loads(_CONNECTION_CONFIG.read_text())
    except Exception:
        data = {}

    removed = False
    for key in ("url", "api_key"):
        if key in data:
            del data[key]
            removed = True

    if not removed:
        click.echo("No saved connection.")
        return

    if data:
        # Other config remains — rewrite without connection fields
        lines = []
        for k, v in data.items():
            if isinstance(v, str):
                lines.append(f'{k} = "{v}"')
            elif isinstance(v, dict):
                lines.append(f"\n[{k}]")
                for sk, sv in v.items():
                    lines.append(f'{sk} = "{sv}"' if isinstance(sv, str) else f"{sk} = {sv}")
            else:
                lines.append(f"{k} = {v}")
        _CONNECTION_CONFIG.write_text("\n".join(lines) + "\n")
    else:
        _CONNECTION_CONFIG.unlink()

    click.echo("Disconnected. Commands will use local Docker.")


@main.command("net-check")
@click.argument("source", required=False, default=None)
@click.argument("target", required=False, default=None)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
@click.option("--project", "filter_project", default=None, help="Filter by compose project.")
@click.option(
    "--containers",
    default=None,
    help="Comma-separated container names to include.",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def net_check_cmd(
    source: str | None,
    target: str | None,
    config_path: str | None,
    docker_host: str | None,
    filter_project: str | None,
    containers: str | None,
    as_json: bool,
) -> None:
    """Check network connectivity between containers.

    \b
    With two arguments: check if SOURCE can reach TARGET.
    With no arguments: check all container pairs.

    \b
    Examples:
      roustabout net-check app db       # check specific pair
      roustabout net-check              # check all pairs
      roustabout net-check --json       # all pairs as JSON
    """
    from roustabout.network_inspect import check_all_connectivity, check_connectivity

    if (source is None) != (target is None):
        raise click.ClickException("Provide both SOURCE and TARGET, or neither for all pairs.")

    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)
    container_filter = containers.split(",") if containers else None
    env = collect(client, containers=container_filter)

    if filter_project:
        env = filter_by_project(env, filter_project)

    if source and target:
        results = [check_connectivity(env, source, target)]
    else:
        results = check_all_connectivity(env)

    if as_json:
        data = [
            {
                "source": r.source,
                "target": r.target,
                "reachable": r.reachable,
                "shared_networks": list(r.shared_networks),
                "reason": r.reason,
            }
            for r in results
        ]
        click.echo(_json.dumps(data, indent=2))
    else:
        if not results:
            click.echo("No container pairs to check.")
            return
        for r in results:
            icon = "✓" if r.reachable else "✗"
            click.echo(f"  {icon} {r.source} → {r.target}: {r.reason}")


@main.command("network")
@click.argument("container", required=False, default=None)
@click.option("--inspect-network", "network_name", default=None, help="Inspect a Docker network.")
@click.option(
    "--probe-dns",
    "probe_dns_host",
    default=None,
    help="Resolve hostname from inside container (requires --container).",
)
@click.option(
    "--probe-connect",
    "probe_connect_target",
    default=None,
    help="Test TCP connectivity: HOST:PORT (requires --container).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def network_cmd(
    container: str | None,
    network_name: str | None,
    probe_dns_host: str | None,
    probe_connect_target: str | None,
    config_path: str | None,
    docker_host: str | None,
    as_json: bool,
) -> None:
    """Network inspection — DNS, aliases, ports, connectivity.

    \b
    Examples:
      roustabout network myapp                              # full network view
      roustabout network --inspect-network bridge           # network details
      roustabout network myapp --probe-dns othercontainer   # DNS probe
      roustabout network myapp --probe-connect db:5432      # TCP probe
    """
    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)

    if network_name:
        from roustabout.network_inspect import inspect_network

        detail = inspect_network(client, network_name)
        if as_json:
            click.echo(
                _json.dumps(
                    {
                        "name": detail.name,
                        "driver": detail.driver,
                        "subnet": detail.subnet,
                        "gateway": detail.gateway,
                        "internal": detail.internal,
                        "containers": [
                            {"name": m.container_name, "ipv4": m.ipv4_address}
                            for m in detail.containers
                        ],
                    },
                    indent=2,
                )
            )
        else:
            click.echo(f"Network: {detail.name} ({detail.driver})")
            if detail.subnet:
                click.echo(f"  Subnet: {detail.subnet}  Gateway: {detail.gateway}")
            click.echo(f"  Internal: {detail.internal}")
            for m in detail.containers:
                click.echo(f"  {m.container_name}: {m.ipv4_address or 'no IP'}")
        return

    if not container:
        raise click.ClickException("Provide a container name, or use --inspect-network.")

    if probe_dns_host:
        from roustabout.network_inspect import probe_dns
        from roustabout.session import DockerSession

        docker_session = DockerSession(client=client, host=cfg.docker_host or "localhost")
        result = probe_dns(docker_session, container, probe_dns_host)
        if as_json:
            click.echo(
                _json.dumps(
                    {
                        "source": result.source,
                        "query": result.query,
                        "resolved": result.resolved,
                        "addresses": list(result.addresses),
                        "error": result.error,
                    },
                    indent=2,
                )
            )
        elif result.resolved:
            click.echo(f"✓ {result.query} → {', '.join(result.addresses)}")
        else:
            click.echo(f"✗ {result.query}: {result.error}")
        return

    if probe_connect_target:
        parts = probe_connect_target.rsplit(":", 1)
        if len(parts) != 2:
            raise click.ClickException("Use HOST:PORT format for --probe-connect.")
        target_host, port_str = parts
        try:
            port = int(port_str)
        except ValueError:
            raise click.ClickException(f"Invalid port: {port_str}")  # noqa: B904

        from roustabout.network_inspect import probe_connectivity
        from roustabout.session import DockerSession

        docker_session = DockerSession(client=client, host=cfg.docker_host or "localhost")
        result = probe_connectivity(docker_session, container, target_host, port)
        if as_json:
            click.echo(
                _json.dumps(
                    {
                        "source": result.source,
                        "target": result.target,
                        "port": result.port,
                        "reachable": result.reachable,
                        "error": result.error,
                    },
                    indent=2,
                )
            )
        elif result.reachable:
            click.echo(f"✓ {result.source} → {result.target}:{result.port} reachable")
        else:
            click.echo(f"✗ {result.source} → {result.target}:{result.port}: {result.error}")
        return

    # Default: full network view
    from roustabout.network_inspect import inspect_container_network

    view = inspect_container_network(client, container)
    if as_json:
        click.echo(
            _json.dumps(
                {
                    "container_name": view.container_name,
                    "network_mode": view.network_mode,
                    "networks": [
                        {"name": n.name, "ip_address": n.ip_address, "aliases": list(n.aliases)}
                        for n in view.networks
                    ],
                    "published_ports": [
                        {
                            "container_port": p.container_port,
                            "protocol": p.protocol,
                            "host_ip": p.host_ip,
                            "host_port": p.host_port,
                        }
                        for p in view.published_ports
                    ],
                },
                indent=2,
            )
        )
    else:
        click.echo(f"Network View: {view.container_name}")
        if view.network_mode:
            click.echo(f"  Mode: {view.network_mode}")
        click.echo()
        if view.networks:
            click.echo("  Networks:")
            for n in view.networks:
                aliases = f" (aliases: {', '.join(n.aliases)})" if n.aliases else ""
                click.echo(f"    {n.name}: {n.ip_address}{aliases}")
        if view.published_ports:
            click.echo("  Ports:")
            for p in view.published_ports:
                host = p.host_ip or "0.0.0.0"
                binding = f"{host}:{p.host_port}" if p.published else "not published"
                click.echo(f"    {p.container_port}/{p.protocol} → {binding}")
        if view.dns_servers:
            click.echo(f"  DNS: {', '.join(view.dns_servers)}")
        if view.network_details:
            click.echo()
            for d in view.network_details:
                click.echo(f"  Network {d.name} ({d.driver}):")
                if d.subnet:
                    click.echo(f"    Subnet: {d.subnet}  Gateway: {d.gateway}")
                for m in d.containers:
                    click.echo(f"    {m.container_name}: {m.ipv4_address or 'no IP'}")


@main.command("ports")
@click.argument("container")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def ports_cmd(
    container: str,
    config_path: str | None,
    docker_host: str | None,
    as_json: bool,
) -> None:
    """Show exposed and published ports for a container."""
    from roustabout.network_inspect import list_container_ports

    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)
    ports = list_container_ports(client, container)

    if as_json:
        click.echo(
            _json.dumps(
                [
                    {
                        "container_port": p.container_port,
                        "protocol": p.protocol,
                        "host_ip": p.host_ip,
                        "host_port": p.host_port,
                        "exposed": p.exposed,
                        "published": p.published,
                    }
                    for p in ports
                ],
                indent=2,
            )
        )
    else:
        if not ports:
            click.echo("No ports exposed or published.")
            return
        for p in ports:
            flags = []
            if p.exposed:
                flags.append("EXPOSE")
            if p.published:
                flags.append(f"→ {p.host_ip or '0.0.0.0'}:{p.host_port}")
            click.echo(f"  {p.container_port}/{p.protocol}  {' '.join(flags)}")


@main.command("migrate")
@click.option(
    "--output-dir",
    "-o",
    required=True,
    type=click.Path(),
    help="Directory for compose and .env files.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
@click.option("--services", default=None, help="Comma-separated service names to include.")
@click.option("--include-stopped", is_flag=True, default=False, help="Include stopped containers.")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without writing files.")
def migrate(
    output_dir: str,
    config_path: str | None,
    docker_host: str | None,
    services: str | None,
    include_stopped: bool,
    dry_run: bool,
) -> None:
    """Generate compose file with secrets extracted to .env."""
    from roustabout.supply_chain import generate_and_extract

    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)
    env = collect(client)

    svc_list = services.split(",") if services else None
    result = generate_and_extract(
        env,
        Path(output_dir),
        services=svc_list,
        include_stopped=include_stopped,
        dry_run=dry_run,
    )

    click.echo(f"Services: {', '.join(result.services)}")
    click.echo(f"Secrets extracted: {result.secrets_extracted}")
    click.echo(f"Compose: {result.compose_path}")
    click.echo(f"Env file: {result.env_file_path}")
    if result.warnings:
        for w in result.warnings:
            click.echo(f"  ⚠ {w}", err=True)
    if dry_run:
        click.echo("(dry run — no files written)")


@main.command("version")
def version_cmd() -> None:
    """Show roustabout version."""
    from importlib.metadata import version

    click.echo(f"roustabout {version('roustabout')}")
