"""CLI entry point for roustabout.

Provides `roustabout snapshot` and `roustabout audit` commands for generating
Docker environment documentation and security findings.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import click
import docker

from roustabout.audit_renderer import render_findings
from roustabout.auditor import audit as run_audit
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
def main() -> None:
    """Roustabout — structured markdown documentation of Docker environments."""


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
    output_format: str,
) -> None:
    """Generate a markdown snapshot of the Docker environment."""
    overrides: dict[str, Any] = {
        "show_env": show_env,
        "output": output,
        "docker_host": docker_host,
    }
    if no_labels:
        overrides["show_labels"] = False
    cfg = _load_cfg(config_path, **overrides)

    client = _connect(cfg.docker_host)
    env = collect(client)

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
    state_file: str | None,
    hide_accepted: bool,
    output_format: str,
) -> None:
    """Run security checks against the Docker environment."""
    cfg = _load_cfg(config_path, output=output, docker_host=docker_host)

    client = _connect(cfg.docker_host)
    env = collect(client)

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
    redact: bool,
) -> None:
    """Generate a docker-compose.yml from running containers."""
    cfg = _load_cfg(config_path, output=output, docker_host=docker_host)

    client = _connect(cfg.docker_host)
    env = collect(client)

    if filter_project:
        env = filter_by_project(env, filter_project)

    if redact:
        patterns = resolve_patterns(cfg.redact_patterns)
        env = redact_env(env, patterns=patterns)

    yaml_output = run_generate(env, include_stopped=include_stopped, project_name=project)

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
def dr_plan(
    output: str | None,
    config_path: str | None,
    docker_host: str | None,
    filter_project: str | None,
) -> None:
    """Generate a disaster recovery plan from running containers."""
    from roustabout.dr_plan import generate as gen_dr
    from roustabout.redactor import sanitize_environment

    cfg = _load_cfg(config_path, output=output, docker_host=docker_host)

    client = _connect(cfg.docker_host)
    env = collect(client)

    if filter_project:
        env = filter_by_project(env, filter_project)

    env = sanitize_environment(env)
    patterns = resolve_patterns(cfg.redact_patterns)
    env = redact_env(env, patterns=patterns)

    result = gen_dr(env)

    if cfg.output:
        Path(cfg.output).write_text(result)
        click.echo(f"DR plan written to {cfg.output}")
    else:
        click.echo(result)


@main.command("health")
@click.option("--container", default=None, help="Filter to a single container.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option("--docker-host", default=None, help="Docker host URL.")
def health_cmd(
    container: str | None,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Show container health status."""
    from roustabout.health_stats import collect_health, render_health

    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)
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
    from roustabout.log_access import (
        ContainerNotFoundError,
        UnsupportedLogDriver,
        collect_logs,
    )

    cfg = _load_cfg(config_path, docker_host=docker_host)
    client = _connect(cfg.docker_host)
    try:
        result = collect_logs(
            client, container_name,
            tail=tail, since=since, grep=grep,
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


def _run_mutation(
    action: str,
    container_name: str,
    dry_run: bool,
    config_path: str | None,
    docker_host: str | None,
) -> None:
    """Execute a mutation through the gateway."""
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
        raise click.ClickException(
            f"{action} failed: {result.error or result.gate_failed}"
        )


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


@main.command("version")
def version_cmd() -> None:
    """Show roustabout version."""
    from importlib.metadata import version

    click.echo(f"roustabout {version('roustabout')}")
