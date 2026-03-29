"""CLI entry point for roustabout.

All commands go through the REST API via HTTPBackend. The API server is the
sole Docker gateway — the CLI does not access Docker directly.
"""

from __future__ import annotations

import json as _json
import os
from pathlib import Path
from typing import Any

import click

from roustabout.cli.backend import get_backend
from roustabout.state import FindingState, set_finding_state

_CONNECTION_CONFIG = Path.home() / ".config" / "roustabout" / "config.toml"


def _format_bytes(n: int) -> str:
    """Format byte count as human-readable string."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TiB"


def _backend() -> Any:
    """Get HTTPBackend, converting RuntimeError to ClickException."""
    try:
        return get_backend()
    except RuntimeError as exc:
        raise click.ClickException(str(exc))


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


def _output_result(text: str, output: str | None) -> None:
    """Print or write result to file."""
    if output:
        Path(output).write_text(text)
        click.echo(f"Output written to {output}")
    else:
        click.echo(text)


def _state_path_option():  # noqa: ANN202
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
    help="Roustabout server URL (env: ROUSTABOUT_URL).",
)
@click.option(
    "--api-key",
    envvar="ROUSTABOUT_API_KEY",
    default=None,
    help="API key for server authentication (env: ROUSTABOUT_API_KEY).",
)
def main(url: str | None, api_key: str | None) -> None:
    """Roustabout — Docker environment management via API server.

    All commands require a running roustabout API server. The CLI does not
    access Docker directly.

    \b
    Examples:
      roustabout --url http://server:8077 snapshot
      roustabout connect http://server:8077       # save for future use
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


# ---------------------------------------------------------------------------
# Read commands
# ---------------------------------------------------------------------------


@main.command()
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format.",
)
def snapshot(output: str | None, output_format: str) -> None:
    """Generate a snapshot of the Docker environment."""
    backend = _backend()
    try:
        raw = backend.snapshot(fmt=output_format)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    text = raw if isinstance(raw, str) else _json.dumps(raw, indent=2)
    _output_result(text, output)


@main.command()
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format.",
)
def audit(output: str | None, output_format: str) -> None:
    """Run security checks against the Docker environment."""
    backend = _backend()
    try:
        raw = backend.audit(fmt=output_format)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    text = raw if isinstance(raw, str) else _json.dumps(raw, indent=2)
    _output_result(text, output)


@main.command("generate")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--include-stopped",
    is_flag=True,
    default=False,
    help="Include stopped containers.",
)
@click.option("--project", default=None, help="Set compose project name.")
@click.option(
    "--services",
    default=None,
    help="Comma-separated service names to include in output.",
)
def generate(
    output: str | None,
    include_stopped: bool,
    project: str | None,
    services: str | None,
) -> None:
    """Generate a docker-compose.yml from running containers."""
    backend = _backend()
    try:
        yaml_output = backend.generate(
            project=project,
            include_stopped=include_stopped,
            services=services,
        )
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    _output_result(yaml_output, output)


@main.command("dr-plan")
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def dr_plan(output: str | None) -> None:
    """Generate a disaster recovery plan from running containers."""
    backend = _backend()
    try:
        data = backend.dr_plan()
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    text = data.get("plan", _json.dumps(data, indent=2))
    _output_result(text, output)


@main.command("health")
@click.option("--container", default=None, help="Filter to a single container.")
@click.option("--deep", is_flag=True, default=False, help="Deep health checks (port + probes).")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def health_cmd(container: str | None, deep: bool, as_json: bool) -> None:
    """Show container health status.

    \b
    Without --deep: Docker health status (restart count, OOM, healthcheck).
    With --deep: adds port checks and service probes.
    """
    backend = _backend()
    try:
        if deep:
            data = backend.deep_health(name=container)
        else:
            data = backend.health(name=container)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    if as_json:
        click.echo(_json.dumps(data, indent=2))
        return

    if deep:
        results = data.get("results", [data] if "container_name" in data else [])
        for r in results:
            icon = {"healthy": "✓", "degraded": "~", "unhealthy": "✗"}.get(
                r.get("overall", ""), "?"
            )
            click.echo(f"  {icon} {r['container_name']}: {r['overall']} (profile={r['profile']})")
            if r.get("docker_health"):
                click.echo(f"    Docker health: {r['docker_health']}")
            if r.get("port_open") is not None:
                click.echo(f"    Port open: {r['port_open']}")
            if r.get("service_healthy") is not None:
                click.echo(f"    Service healthy: {r['service_healthy']}")
    else:
        entries = data.get("entries", [])
        if not entries:
            click.echo("No health data available.")
        else:
            click.echo(_json.dumps(data, indent=2))


@main.command("stats")
@click.option("--container", default=None, help="Filter to a single container.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def stats_cmd(container: str | None, as_json: bool) -> None:
    """Show container resource usage."""
    backend = _backend()
    try:
        data = backend.stats(container=container)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    stats = data.get("stats", [])

    if as_json:
        click.echo(_json.dumps(stats, indent=2))
    else:
        if not stats:
            click.echo("No stats available.")
            return
        # Simple table output
        cols = f"{'Container':<25} {'CPU%':>6} {'Mem%':>6} {'Mem':>10} {'RX':>10} {'TX':>10}"
        click.echo(cols)
        click.echo("-" * 75)
        for s in stats:
            mem = _format_bytes(s.get("memory_usage_bytes", 0))
            rx = _format_bytes(s.get("network_rx_bytes", 0))
            tx = _format_bytes(s.get("network_tx_bytes", 0))
            click.echo(
                f"{s['name']:<25} {s.get('cpu_percent', 0):>5.1f}%"
                f" {s.get('memory_percent', 0):>5.1f}%"
                f" {mem:>10} {rx:>10} {tx:>10}"
            )


@main.command("logs")
@click.argument("container_name")
@click.option("--tail", default=100, help="Number of lines (default 100).")
@click.option("--since", default=None, help="Time filter (5m, 1h, or ISO 8601).")
@click.option("--grep", default=None, help="Substring filter.")
def logs_cmd(
    container_name: str,
    tail: int,
    since: str | None,
    grep: str | None,
) -> None:
    """Read container logs."""
    backend = _backend()
    try:
        data = backend.logs(name=container_name, tail=tail, since=since, grep=grep)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    text = data.get("lines", _json.dumps(data, indent=2))
    click.echo(text)


# ---------------------------------------------------------------------------
# Mutation commands
# ---------------------------------------------------------------------------


@main.command("stop")
@click.argument("container_name")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without executing.")
def stop_cmd(container_name: str, dry_run: bool) -> None:
    """Stop a running container."""
    _run_mutation("stop", container_name, dry_run)


@main.command("start")
@click.argument("container_name")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without executing.")
def start_cmd(container_name: str, dry_run: bool) -> None:
    """Start a stopped container."""
    _run_mutation("start", container_name, dry_run)


@main.command("restart")
@click.argument("container_name")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without executing.")
def restart_cmd(container_name: str, dry_run: bool) -> None:
    """Restart a container."""
    _run_mutation("restart", container_name, dry_run)


@main.command("recreate")
@click.argument("container_name")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without executing.")
def recreate_cmd(container_name: str, dry_run: bool) -> None:
    """Recreate a container (stop, remove, create with same config, start)."""
    _run_mutation("recreate", container_name, dry_run)


def _run_mutation(action: str, container_name: str, dry_run: bool) -> None:
    """Execute a mutation through the API server."""
    backend = _backend()
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


# ---------------------------------------------------------------------------
# Network commands
# ---------------------------------------------------------------------------


@main.command("net-check")
@click.argument("source", required=False, default=None)
@click.argument("target", required=False, default=None)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def net_check_cmd(
    source: str | None,
    target: str | None,
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
    if (source is None) != (target is None):
        raise click.ClickException("Provide both SOURCE and TARGET, or neither for all pairs.")

    backend = _backend()
    try:
        data = backend.net_check(source=source, target=target)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    results = data.get("connectivity", [])

    if as_json:
        click.echo(_json.dumps(results, indent=2))
    else:
        if not results:
            click.echo("No container pairs to check.")
            return
        for r in results:
            icon = "✓" if r["reachable"] else "✗"
            click.echo(f"  {icon} {r['source']} → {r['target']}: {r['reason']}")


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
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def network_cmd(
    container: str | None,
    network_name: str | None,
    probe_dns_host: str | None,
    probe_connect_target: str | None,
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
    backend = _backend()

    if network_name:
        try:
            detail = backend.inspect_network(network_name)
        except RuntimeError as exc:
            raise click.ClickException(str(exc))

        if as_json:
            click.echo(_json.dumps(detail, indent=2))
        else:
            click.echo(f"Network: {detail['name']} ({detail.get('driver', 'unknown')})")
            subnet = detail.get("subnet")
            if subnet:
                click.echo(f"  Subnet: {subnet}  Gateway: {detail.get('gateway', '')}")
            click.echo(f"  Internal: {detail.get('internal', False)}")
            for m in detail.get("containers", []):
                click.echo(f"  {m['container_name']}: {m.get('ipv4_address') or 'no IP'}")
        return

    if not container:
        raise click.ClickException("Provide a container name, or use --inspect-network.")

    if probe_dns_host:
        try:
            result = backend.probe_dns(container, probe_dns_host)
        except RuntimeError as exc:
            raise click.ClickException(str(exc))

        if as_json:
            click.echo(_json.dumps(result, indent=2))
        elif result.get("resolved"):
            addrs = ", ".join(result.get("addresses", []))
            click.echo(f"✓ {result['query']} → {addrs}")
        else:
            click.echo(f"✗ {result['query']}: {result.get('error', 'unknown')}")
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

        try:
            conn = backend.probe_connect(container, target_host, port)
        except RuntimeError as exc:
            raise click.ClickException(str(exc))

        if as_json:
            click.echo(_json.dumps(conn, indent=2))
        elif conn.get("reachable"):
            click.echo(f"✓ {conn['source']} → {conn['target']}:{conn['port']} reachable")
        else:
            click.echo(
                f"✗ {conn['source']} → {conn['target']}:{conn['port']}: "
                f"{conn.get('error', 'unknown')}"
            )
        return

    # Default: full network view
    try:
        view = backend.container_network(container)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    if as_json:
        click.echo(_json.dumps(view, indent=2))
    else:
        click.echo(f"Network View: {view['container_name']}")
        if view.get("network_mode"):
            click.echo(f"  Mode: {view['network_mode']}")
        click.echo()
        networks = view.get("networks", [])
        if networks:
            click.echo("  Networks:")
            for n in networks:
                aliases = n.get("aliases", [])
                alias_str = f" (aliases: {', '.join(aliases)})" if aliases else ""
                click.echo(f"    {n['name']}: {n.get('ip_address', '')}{alias_str}")
        ports = view.get("published_ports", [])
        if ports:
            click.echo("  Ports:")
            for p in ports:
                host = p.get("host_ip") or "0.0.0.0"
                if p.get("published"):
                    binding = f"{host}:{p.get('host_port', '')}"
                else:
                    binding = "not published"
                click.echo(f"    {p['container_port']}/{p['protocol']} → {binding}")
        dns = view.get("dns_servers", [])
        if dns:
            click.echo(f"  DNS: {', '.join(dns)}")
        details = view.get("network_details", [])
        if details:
            click.echo()
            for d in details:
                click.echo(f"  Network {d['name']} ({d.get('driver', 'unknown')}):")
                if d.get("subnet"):
                    click.echo(f"    Subnet: {d['subnet']}  Gateway: {d.get('gateway', '')}")
                for m in d.get("containers", []):
                    click.echo(f"    {m['container_name']}: {m.get('ipv4_address') or 'no IP'}")


@main.command("ports")
@click.argument("container")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON.")
def ports_cmd(container: str, as_json: bool) -> None:
    """Show exposed and published ports for a container."""
    backend = _backend()
    try:
        data = backend.ports(container)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    port_list = data.get("ports", [])

    if as_json:
        click.echo(_json.dumps(port_list, indent=2))
    else:
        if not port_list:
            click.echo("No ports exposed or published.")
            return
        for p in port_list:
            flags = []
            if p.get("exposed"):
                flags.append("EXPOSE")
            if p.get("published"):
                flags.append(f"→ {p.get('host_ip') or '0.0.0.0'}:{p.get('host_port', '')}")
            click.echo(f"  {p['container_port']}/{p['protocol']}  {' '.join(flags)}")


# ---------------------------------------------------------------------------
# Local-only commands (no Docker access needed)
# ---------------------------------------------------------------------------


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
    _output_result(markdown, output)


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


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------


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

    click.echo("Disconnected.")


# ---------------------------------------------------------------------------
# Commands pending API endpoints (TODO: rule-0)
# ---------------------------------------------------------------------------


@main.command("exec")
@click.argument("container_name")
@click.argument("command", nargs=-1, required=True)
@click.option("--user", default=None, help="User to run as inside the container.")
@click.option("--workdir", default=None, help="Working directory inside the container.")
@click.option("--timeout", default=30, type=int, help="Timeout in seconds (default 30).")
def exec_cmd(
    container_name: str,
    command: tuple[str, ...],
    user: str | None,
    workdir: str | None,
    timeout: int,
) -> None:
    """Run a command inside a container.

    Uses denylist safety model — blocked binaries and patterns are rejected.

    \b
    Examples:
      roustabout exec myapp -- cat /etc/nginx/conf.d/default.conf
      roustabout exec myapp -- getent hosts othercontainer
      roustabout exec myapp --user nobody -- ls /tmp
    """
    backend = _backend()
    try:
        result = backend.exec(
            container_name,
            list(command),
            user=user,
            workdir=workdir,
            timeout=timeout,
        )
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    if result.get("denied"):
        raise click.ClickException(result.get("error", "Command denied"))

    if result.get("stdout"):
        click.echo(result["stdout"])
    if result.get("stderr"):
        click.echo(result["stderr"], err=True)
    if result.get("error"):
        raise click.ClickException(result["error"])
    if result.get("truncated"):
        click.echo("(output truncated)", err=True)

    raise SystemExit(result.get("exit_code") or 0)


@main.command("file-read")
@click.argument("path")
def file_read_cmd(path: str) -> None:
    """Read a file from the Docker host.

    Paths are relative to the server's configured file_root.
    Content is redacted for secrets. Large files are truncated.

    \b
    Examples:
      roustabout file-read compose.yml
      roustabout file-read nginx/conf.d/default.conf
    """
    backend = _backend()
    try:
        result = backend.file_read(path)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    if not result.get("success"):
        raise click.ClickException(result.get("error") or "Read failed")

    click.echo(result.get("content", ""))
    if result.get("truncated"):
        click.echo(f"(truncated — file is {result.get('size', 0)} bytes)", err=True)


@main.command("file-write")
@click.argument("path")
@click.argument("content_file", type=click.File("r"))
@click.option(
    "--direct",
    is_flag=True,
    default=False,
    help="Write directly instead of staging.",
)
def file_write_cmd(
    path: str,
    content_file: Any,
    direct: bool,
) -> None:
    """Write a file to the Docker host.

    Paths are relative to the server's configured file_root.
    By default, writes are staged for operator review. Use --direct to
    write immediately (with automatic backup).

    \b
    Examples:
      roustabout file-write myapp/compose.yml new-compose.yml
      roustabout file-write config.yml updated.yml --direct
    """
    content = content_file.read()
    backend = _backend()
    try:
        result = backend.file_write(path, content, direct=direct)
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    if not result.get("success"):
        raise click.ClickException(result.get("error") or "Write failed")

    if result.get("staged"):
        click.echo(f"Staged at {result.get('staging_path', '')}")
        if result.get("diff"):
            click.echo(result["diff"])
        if result.get("apply_command"):
            click.echo(f"To apply: {result['apply_command']}")
    else:
        click.echo(f"Written to {result.get('path', '')}")
        if result.get("backup_path"):
            click.echo(f"Backup at {result['backup_path']}")


@main.command("migrate")
@click.option(
    "--output-dir",
    "-o",
    required=True,
    type=click.Path(),
    help="Directory for compose and .env files.",
)
@click.option("--services", default=None, help="Comma-separated service names to include.")
@click.option("--include-stopped", is_flag=True, default=False, help="Include stopped containers.")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without writing files.")
def migrate(
    output_dir: str,
    services: str | None,
    include_stopped: bool,
    dry_run: bool,
) -> None:
    """Generate compose file with secrets extracted to .env."""
    backend = _backend()
    try:
        result = backend.migrate(
            output_dir,
            services=services,
            include_stopped=include_stopped,
            dry_run=dry_run,
        )
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    click.echo(f"Services: {', '.join(result.get('services', []))}")
    click.echo(f"Secrets extracted: {result.get('secrets_extracted', 0)}")
    click.echo(f"Compose: {result.get('compose_path', '')}")
    click.echo(f"Env file: {result.get('env_file_path', '')}")
    for w in result.get("warnings", []):
        click.echo(f"  ⚠ {w}", err=True)
    if result.get("dry_run"):
        click.echo("(dry run — no files written)")


@main.command("version")
def version_cmd() -> None:
    """Show roustabout version."""
    from importlib.metadata import version

    click.echo(f"roustabout {version('roustabout')}")
