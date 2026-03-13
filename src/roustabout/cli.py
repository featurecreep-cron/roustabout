"""CLI entry point for roustabout.

Provides `roustabout snapshot` and `roustabout audit` commands for generating
Docker environment documentation and security findings.
"""

from __future__ import annotations

from pathlib import Path

import click
import docker

from roustabout.audit_renderer import render_findings
from roustabout.auditor import audit as run_audit
from roustabout.collector import collect
from roustabout.config import load_config
from roustabout.connection import connect
from roustabout.generator import generate as run_generate
from roustabout.redactor import redact as redact_env
from roustabout.redactor import resolve_patterns
from roustabout.renderer import render
from roustabout.state import FindingState, load_state, set_finding_state


def _connect(docker_host: str | None) -> docker.DockerClient:
    """Connect to Docker, raising ClickException on failure."""
    try:
        return connect(docker_host)
    except Exception as exc:
        raise click.ClickException(f"Cannot connect to Docker: {exc}")


def _load_cfg(config_path, **overrides):
    """Load config and apply overrides."""
    try:
        cfg = load_config(Path(config_path) if config_path else None)
    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(str(exc))
    return cfg.merge(**{k: v for k, v in overrides.items() if v is not None})


def _state_path_option():
    return click.option(
        "--state-file",
        type=click.Path(),
        default=None,
        help="Path to state file (default: roustabout.state.toml).",
    )


@click.group()
@click.version_option(package_name="roustabout")
def main():
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
def snapshot(show_env, no_labels, output, config_path, docker_host):
    """Generate a markdown snapshot of the Docker environment."""
    overrides = {"show_env": show_env, "output": output, "docker_host": docker_host}
    if no_labels:
        overrides["show_labels"] = False
    cfg = _load_cfg(config_path, **overrides)

    client = _connect(cfg.docker_host)
    env = collect(client)

    patterns = resolve_patterns(cfg.redact_patterns)
    env = redact_env(env, patterns=patterns)

    markdown = render(env, show_env=cfg.show_env, show_labels=cfg.show_labels)

    if cfg.output:
        Path(cfg.output).write_text(markdown)
        click.echo(f"Snapshot written to {cfg.output}")
    else:
        click.echo(markdown)


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
@_state_path_option()
@click.option(
    "--hide-accepted",
    is_flag=True,
    default=False,
    help="Hide accepted and false-positive findings.",
)
def audit(output, config_path, docker_host, state_file, hide_accepted):
    """Run security checks against the Docker environment."""
    cfg = _load_cfg(config_path, output=output, docker_host=docker_host)

    client = _connect(cfg.docker_host)
    env = collect(client)

    findings = run_audit(
        env, patterns=cfg.redact_patterns, severity_overrides=cfg.severity_overrides
    )

    state_entries = load_state(Path(state_file) if state_file else None)
    markdown = render_findings(findings, state_entries=state_entries, hide_accepted=hide_accepted)

    if cfg.output:
        Path(cfg.output).write_text(markdown)
        click.echo(f"Audit written to {cfg.output}")
    else:
        click.echo(markdown)


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
    "--redact/--no-redact",
    default=True,
    help="Redact secrets in environment variables (default: redact).",
)
def generate(output, config_path, docker_host, include_stopped, project, redact):
    """Generate a docker-compose.yml from running containers."""
    cfg = _load_cfg(config_path, output=output, docker_host=docker_host)

    client = _connect(cfg.docker_host)
    env = collect(client)

    if redact:
        patterns = resolve_patterns(cfg.redact_patterns)
        env = redact_env(env, patterns=patterns)

    yaml_output = run_generate(env, include_stopped=include_stopped, project_name=project)

    if cfg.output:
        Path(cfg.output).write_text(yaml_output)
        click.echo(f"Compose file written to {cfg.output}")
    else:
        click.echo(yaml_output)


@main.command("accept")
@click.argument("finding_key")
@click.argument("reason")
@_state_path_option()
def accept_finding(finding_key, reason, state_file):
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
def false_positive_finding(finding_key, reason, state_file):
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
def resolve_finding(finding_key, reason, state_file):
    """Mark a finding as resolved (fixed)."""
    path = set_finding_state(
        finding_key,
        FindingState.RESOLVED,
        reason,
        Path(state_file) if state_file else None,
    )
    click.echo(f"Marked {finding_key} as resolved. State saved to {path}")
