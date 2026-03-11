"""CLI entry point for roustabout.

Provides `roustabout snapshot` and `roustabout audit` commands for generating
Docker environment documentation and security findings.
"""

from __future__ import annotations

from pathlib import Path

import click
import docker

from roustabout.auditor import audit as run_audit
from roustabout.auditor import render_findings
from roustabout.collector import collect
from roustabout.config import load_config
from roustabout.connection import connect
from roustabout.redactor import redact, resolve_patterns
from roustabout.renderer import render


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
    env = redact(env, patterns=patterns)

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
def audit(output, config_path, docker_host):
    """Run security checks against the Docker environment."""
    cfg = _load_cfg(config_path, output=output, docker_host=docker_host)

    client = _connect(cfg.docker_host)
    env = collect(client)

    findings = run_audit(env, patterns=cfg.redact_patterns)
    markdown = render_findings(findings)

    if cfg.output:
        Path(cfg.output).write_text(markdown)
        click.echo(f"Audit written to {cfg.output}")
    else:
        click.echo(markdown)
