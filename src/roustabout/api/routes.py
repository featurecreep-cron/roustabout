"""API route handlers — delegates to core logic, never calls Docker directly."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from roustabout.api.auth import KeyInfo
from roustabout.redactor import sanitize
from roustabout.session import PermissionTier, RateLimiter, capabilities_for_tier

router = APIRouter(prefix="/v1")

_VALID_MUTATIONS = frozenset({"start", "stop", "restart", "recreate"})

_TIER_ORDER = {"observe": 0, "operate": 1, "elevate": 2}

# Server-wide shared rate limiter — set by server.py at startup
_rate_limiter: RateLimiter | None = None


def set_rate_limiter(limiter: RateLimiter) -> None:
    """Set the server-wide rate limiter. Called once at startup."""
    global _rate_limiter  # noqa: PLW0603
    _rate_limiter = limiter


def _has_tier(key_tier: str, required: str) -> bool:
    """Check if key's tier meets or exceeds the required tier."""
    return _TIER_ORDER.get(key_tier, -1) >= _TIER_ORDER.get(required, 99)


def _load_cfg_simple() -> str | None:
    """Load docker host from config. Returns host string or None."""
    try:
        from roustabout.config import load_config

        return load_config().docker_host
    except Exception:  # noqa: BLE001
        return None


# Read helpers — ephemeral Docker client per request, no gateway


def _snapshot(fmt: str = "json") -> dict[str, Any] | str:
    """Execute snapshot via core logic."""
    from roustabout.collector import collect
    from roustabout.config import load_config
    from roustabout.connection import connect
    from roustabout.json_output import environment_to_dict
    from roustabout.redactor import redact, resolve_patterns
    from roustabout.renderer import render

    config = load_config()
    client = connect()
    try:
        env = collect(client)
        patterns = resolve_patterns(config.redact_patterns)
        redacted = redact(env, patterns)
        if fmt == "markdown":
            return render(redacted, show_env=config.show_env, show_labels=config.show_labels)
        return environment_to_dict(redacted)
    finally:
        client.close()


def _audit(fmt: str = "json") -> dict[str, Any] | str:
    """Execute audit via core logic."""
    from roustabout.audit_renderer import render_findings
    from roustabout.auditor import audit
    from roustabout.collector import collect
    from roustabout.config import load_config
    from roustabout.connection import connect
    from roustabout.redactor import resolve_patterns

    config = load_config()
    client = connect()
    try:
        env = collect(client)
        patterns = resolve_patterns(config.redact_patterns)
        findings = audit(env, patterns)
        if fmt == "markdown":
            return render_findings(findings)
        return {
            "findings": [
                {
                    "check": f.category,
                    "severity": f.severity.value,
                    "container": f.container,
                    "message": f.explanation,
                }
                for f in findings
            ],
        }
    finally:
        client.close()


def _container_detail(container_name: str) -> dict[str, Any] | None:
    """Get detail for a single container."""
    from roustabout.collector import collect
    from roustabout.config import load_config
    from roustabout.connection import connect
    from roustabout.redactor import redact, resolve_patterns

    config = load_config()
    client = connect()
    try:
        env = collect(client)
        patterns = resolve_patterns(config.redact_patterns)
        redacted = redact(env, patterns)
        for c in redacted.containers:
            if c.name == container_name:
                return {
                    "name": c.name,
                    "image": c.image,
                    "status": c.status,
                    "health": c.health,
                    "restart_count": c.restart_count,
                    "ports": [
                        {
                            "host": p.host_port,
                            "container": p.container_port,
                            "protocol": p.protocol,
                        }
                        for p in c.ports
                    ],
                    "networks": [n.name for n in c.networks],
                }
        return None
    finally:
        client.close()


def _health(container_name: str) -> dict[str, Any]:
    """Collect health stats for a single container."""
    from roustabout.connection import connect
    from roustabout.health_stats import collect_health

    client = connect()
    try:
        healths = collect_health(client)
        for h in healths:
            if h.name == container_name:
                return {
                    "name": h.name,
                    "status": h.status,
                    "health": h.health,
                    "restart_count": h.restart_count,
                    "oom_killed": h.oom_killed,
                }
        return None  # type: ignore[return-value]
    finally:
        client.close()


def _logs(
    container_name: str,
    tail: int,
    since: str | None = None,
    grep: str | None = None,
) -> dict[str, Any]:
    """Collect logs for a single container."""
    from roustabout.connection import connect
    from roustabout.log_access import collect_logs

    client = connect()
    try:
        text = collect_logs(client, container_name, tail=tail, since=since, grep=grep)
        return {"container": container_name, "lines": text}
    finally:
        client.close()


def _dr_plan(*, strip_versions: bool = False) -> dict[str, Any]:
    """Generate disaster recovery plan."""
    from roustabout.collector import collect
    from roustabout.config import load_config
    from roustabout.connection import connect
    from roustabout.dr_plan import generate
    from roustabout.redactor import redact, resolve_patterns

    config = load_config()
    should_strip = strip_versions or config.strip_versions
    client = connect()
    try:
        env = collect(client)
        patterns = resolve_patterns(config.redact_patterns)
        redacted = redact(env, patterns)
        plan = generate(redacted, strip_versions=should_strip)
        return {"plan": plan}
    finally:
        client.close()


# Mutation helper — routes through gateway with full gate sequence

# Gateway exception → HTTP status mapping
_GATEWAY_ERROR_MAP: dict[str, int] = {
    "LockdownError": 503,
    "PermissionDenied": 403,
    "RateLimitExceeded": 429,
    "CircuitOpen": 503,
    "BlastRadiusExceeded": 403,
    "TargetNotFound": 404,
    "ConcurrentMutation": 409,
}


def _mutate(container_name: str, action: str, key_info: KeyInfo) -> tuple[int, dict[str, Any]]:
    """Execute mutation via gateway. Returns (status_code, response_dict)."""
    from uuid import uuid4

    from roustabout.gateway import GatewayResult, MutationCommand, execute
    from roustabout.session import create_session, destroy_session

    tier = PermissionTier(key_info.tier)
    session = create_session(tier=tier, session_id=f"api-{uuid4().hex[:8]}")

    # Inject server-wide rate limiter if available
    if _rate_limiter is not None:
        # Session is frozen, but gateway reads rate_limiter from it.
        # We replace it via object.__setattr__ on the frozen dataclass.
        object.__setattr__(session, "rate_limiter", _rate_limiter)

    try:
        command = MutationCommand(action=action, target=container_name)
        result: GatewayResult = execute(command, session=session)

        response = {
            "result": result.result,
            "container": container_name,
            "action": action,
            "pre_hash": result.pre_state_hash,
            "post_hash": result.post_state_hash,
        }

        if not result.success:
            status = _GATEWAY_ERROR_MAP.get(result.gate_failed or "", 500)
            response["error"] = result.error
            return status, response

        return 200, response
    except ConnectionError:
        return 503, {
            "result": "failed",
            "container": container_name,
            "action": action,
            "error": "Docker daemon unavailable",
        }
    finally:
        destroy_session(session)


# Route handlers


@router.get("/snapshot")
async def snapshot(request: Request, format: str = "json") -> Any:
    """Collect and return redacted Docker environment state."""
    import anyio
    from fastapi.responses import PlainTextResponse

    result = await anyio.to_thread.run_sync(lambda: _snapshot(fmt=format))
    if isinstance(result, str):
        return PlainTextResponse(result)
    return result


@router.get("/audit")
async def audit_route(request: Request, format: str = "json") -> Any:
    """Run security audit and return findings."""
    import anyio
    from fastapi.responses import PlainTextResponse

    result = await anyio.to_thread.run_sync(lambda: _audit(fmt=format))
    if isinstance(result, str):
        return PlainTextResponse(result)
    return result


@router.get("/containers/{name}")
async def container_detail_route(name: str, request: Request) -> JSONResponse:
    """Get detail for a single container."""
    import anyio

    name = sanitize(name)[:128]
    result = await anyio.to_thread.run_sync(lambda: _container_detail(name))
    if result is None:
        return JSONResponse(status_code=404, content={"error": f"container '{name}' not found"})
    return JSONResponse(content=result)


@router.get("/health/{name}")
async def health_route(name: str, request: Request) -> JSONResponse:
    """Get health status for a specific container."""
    import anyio

    name = sanitize(name)[:128]
    result = await anyio.to_thread.run_sync(lambda: _health(name))
    if result is None:
        return JSONResponse(status_code=404, content={"error": f"container '{name}' not found"})
    return JSONResponse(content=result)


@router.get("/logs/{name}")
async def logs_route(
    name: str,
    request: Request,
    tail: int = 100,
    since: str | None = None,
    grep: str | None = None,
) -> JSONResponse:
    """Get recent logs for a specific container."""
    import anyio

    name = sanitize(name)[:128]
    try:
        result = await anyio.to_thread.run_sync(lambda: _logs(name, tail, since=since, grep=grep))
        return JSONResponse(content=result)
    except Exception as exc:
        error_name = type(exc).__name__
        if error_name == "ContainerNotFoundError":
            return JSONResponse(
                status_code=404,
                content={"error": f"container '{name}' not found"},
            )
        if error_name == "UnsupportedLogDriver":
            return JSONResponse(status_code=400, content={"error": str(exc)})
        raise


@router.get("/dr-plan")
async def dr_plan_route(request: Request, strip_versions: bool = False) -> dict[str, Any]:
    """Generate disaster recovery plan."""
    import anyio

    return await anyio.to_thread.run_sync(lambda: _dr_plan(strip_versions=strip_versions))


@router.get("/net-check")
async def net_check_route(
    request: Request,
    source: str | None = None,
    target: str | None = None,
) -> JSONResponse:
    """Check network connectivity between containers."""
    import anyio

    if (source is None) != (target is None):
        return JSONResponse(
            status_code=400,
            content={"error": "Provide both source and target, or neither for all pairs."},
        )

    def _run() -> list[dict[str, Any]]:
        from roustabout.collector import collect
        from roustabout.connection import connect
        from roustabout.network_inspect import check_all_connectivity, check_connectivity

        client = connect()
        try:
            env = collect(client)
            if source and target:
                results = [check_connectivity(env, source, target)]
            else:
                results = check_all_connectivity(env)
            return [
                {
                    "source": r.source,
                    "target": r.target,
                    "reachable": r.reachable,
                    "shared_networks": list(r.shared_networks),
                    "reason": r.reason,
                }
                for r in results
            ]
        finally:
            client.close()

    data = await anyio.to_thread.run_sync(_run)
    return JSONResponse(content={"connectivity": data})


@router.get("/containers/{name}/network")
async def container_network_route(name: str, request: Request) -> JSONResponse:
    """Get detailed network configuration for a container."""
    import anyio

    name = sanitize(name)[:128]

    def _run() -> dict[str, Any]:
        from roustabout.connection import connect
        from roustabout.network_inspect import inspect_container_network

        client = connect()
        try:
            view = inspect_container_network(client, name)
            return {
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
                        "exposed": p.exposed,
                        "published": p.published,
                    }
                    for p in view.published_ports
                ],
                "dns_servers": list(view.dns_servers),
                "dns_search": list(view.dns_search),
                "extra_hosts": list(view.extra_hosts),
                "network_details": [
                    {
                        "name": d.name,
                        "id": d.id,
                        "driver": d.driver,
                        "scope": d.scope,
                        "subnet": d.subnet,
                        "gateway": d.gateway,
                        "internal": d.internal,
                        "containers": [
                            {
                                "container_name": m.container_name,
                                "container_id": m.container_id,
                                "ipv4_address": m.ipv4_address,
                                "ipv6_address": m.ipv6_address,
                            }
                            for m in d.containers
                        ],
                    }
                    for d in view.network_details
                ],
            }
        finally:
            client.close()

    try:
        data = await anyio.to_thread.run_sync(_run)
        return JSONResponse(content=data)
    except Exception as exc:
        if type(exc).__name__ == "NotFound":
            return JSONResponse(
                status_code=404, content={"error": f"container '{name}' not found"}
            )
        raise


@router.get("/networks/{name}")
async def network_detail_route(name: str, request: Request) -> JSONResponse:
    """Get details about a Docker network."""
    import anyio

    name = sanitize(name)[:128]

    def _run() -> dict[str, Any]:
        from roustabout.connection import connect
        from roustabout.network_inspect import inspect_network

        client = connect()
        try:
            detail = inspect_network(client, name)
            return {
                "name": detail.name,
                "id": detail.id,
                "driver": detail.driver,
                "scope": detail.scope,
                "subnet": detail.subnet,
                "gateway": detail.gateway,
                "internal": detail.internal,
                "containers": [
                    {
                        "container_name": m.container_name,
                        "container_id": m.container_id,
                        "ipv4_address": m.ipv4_address,
                        "ipv6_address": m.ipv6_address,
                    }
                    for m in detail.containers
                ],
            }
        finally:
            client.close()

    try:
        data = await anyio.to_thread.run_sync(_run)
        return JSONResponse(content=data)
    except Exception as exc:
        if type(exc).__name__ == "NotFound":
            return JSONResponse(status_code=404, content={"error": f"network '{name}' not found"})
        raise


@router.get("/containers/{name}/ports")
async def container_ports_route(name: str, request: Request) -> JSONResponse:
    """Get port exposure details for a container."""
    import anyio

    name = sanitize(name)[:128]

    def _run() -> list[dict[str, Any]]:
        from roustabout.connection import connect
        from roustabout.network_inspect import list_container_ports

        client = connect()
        try:
            ports = list_container_ports(client, name)
            return [
                {
                    "container_port": p.container_port,
                    "protocol": p.protocol,
                    "host_ip": p.host_ip,
                    "host_port": p.host_port,
                    "exposed": p.exposed,
                    "published": p.published,
                }
                for p in ports
            ]
        finally:
            client.close()

    try:
        data = await anyio.to_thread.run_sync(_run)
        return JSONResponse(content={"ports": data})
    except Exception as exc:
        if type(exc).__name__ == "NotFound":
            return JSONResponse(
                status_code=404, content={"error": f"container '{name}' not found"}
            )
        raise


@router.post("/containers/{name}/probe/dns")
async def probe_dns_route(name: str, request: Request) -> JSONResponse:
    """Resolve a hostname from inside a container. ELEVATE tier."""
    import anyio

    name = sanitize(name)[:128]
    key_info: KeyInfo = request.state.key_info
    if not _has_tier(key_info.tier, "elevate"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "insufficient permissions",
                "required_tier": "elevate",
                "your_tier": key_info.tier,
            },
        )

    body = await request.json()
    hostname = body.get("hostname")
    if not hostname:
        return JSONResponse(status_code=400, content={"error": "hostname is required"})

    def _run() -> dict[str, Any]:
        from roustabout.connection import connect
        from roustabout.network_inspect import probe_dns
        from roustabout.session import DockerSession

        cfg_local = _load_cfg_simple()
        client = connect(cfg_local)
        docker_session = DockerSession(
            client=client,
            host=cfg_local or "localhost",
        )
        try:
            result = probe_dns(docker_session, name, hostname)
            return {
                "source": result.source,
                "query": result.query,
                "resolved": result.resolved,
                "addresses": list(result.addresses),
                "error": result.error,
            }
        finally:
            client.close()

    try:
        data = await anyio.to_thread.run_sync(_run)
        return JSONResponse(content=data)
    except Exception as exc:
        if type(exc).__name__ == "NotFound":
            return JSONResponse(
                status_code=404, content={"error": f"container '{name}' not found"}
            )
        raise


@router.post("/containers/{name}/probe/connect")
async def probe_connect_route(name: str, request: Request) -> JSONResponse:
    """Test TCP connectivity from a container. ELEVATE tier."""
    import anyio

    name = sanitize(name)[:128]
    key_info: KeyInfo = request.state.key_info
    if not _has_tier(key_info.tier, "elevate"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "insufficient permissions",
                "required_tier": "elevate",
                "your_tier": key_info.tier,
            },
        )

    body = await request.json()
    target_host = body.get("target_host")
    port = body.get("port")
    if not target_host or port is None:
        return JSONResponse(
            status_code=400, content={"error": "target_host and port are required"}
        )

    def _run() -> dict[str, Any]:
        from roustabout.connection import connect
        from roustabout.network_inspect import probe_connectivity
        from roustabout.session import DockerSession

        cfg_local = _load_cfg_simple()
        client = connect(cfg_local)
        docker_session = DockerSession(
            client=client,
            host=cfg_local or "localhost",
        )
        try:
            result = probe_connectivity(
                docker_session,
                name,
                target_host,
                int(port),
            )
            return {
                "source": result.source,
                "target": result.target,
                "port": result.port,
                "reachable": result.reachable,
                "latency_ms": result.latency_ms,
                "error": result.error,
            }
        finally:
            client.close()

    try:
        data = await anyio.to_thread.run_sync(_run)
        return JSONResponse(content=data)
    except Exception as exc:
        if type(exc).__name__ == "NotFound":
            return JSONResponse(
                status_code=404, content={"error": f"container '{name}' not found"}
            )
        raise


@router.get("/deep-health")
async def deep_health_route(request: Request) -> JSONResponse:
    """Get deep health status for all containers."""
    import anyio

    def _run() -> dict[str, Any]:
        from roustabout.connection import connect
        from roustabout.deep_health import check_environment_health

        client = connect()
        try:
            health = check_environment_health(client)
            return {
                "total": health.total,
                "healthy": health.healthy,
                "degraded": health.degraded,
                "unhealthy": health.unhealthy,
                "unknown": health.unknown,
                "results": [
                    {
                        "container_name": r.container_name,
                        "profile": r.profile,
                        "docker_health": r.docker_health,
                        "port_open": r.port_open,
                        "service_healthy": r.service_healthy,
                        "overall": r.overall,
                        "checks_performed": list(r.checks_performed),
                    }
                    for r in health.results
                ],
            }
        finally:
            client.close()

    data = await anyio.to_thread.run_sync(_run)
    return JSONResponse(content=data)


@router.get("/deep-health/{name}")
async def deep_health_container_route(
    name: str,
    request: Request,
    deep: bool = False,
) -> JSONResponse:
    """Get deep health status for a specific container."""
    import anyio

    name = sanitize(name)[:128]

    if deep:
        key_info: KeyInfo = request.state.key_info
        if not _has_tier(key_info.tier, "elevate"):
            return JSONResponse(
                status_code=403,
                content={
                    "error": "deep health probes require elevate tier",
                    "required_tier": "elevate",
                    "your_tier": key_info.tier,
                },
            )

    def _run() -> dict[str, Any]:
        from roustabout.connection import connect
        from roustabout.deep_health import check_container_health

        client = connect()
        docker_session = None
        if deep:
            from roustabout.session import DockerSession

            docker_session = DockerSession(client=client, host="localhost")
        try:
            result = check_container_health(
                client,
                name,
                docker_session=docker_session,
            )
            return {
                "container_name": result.container_name,
                "profile": result.profile,
                "docker_health": result.docker_health,
                "port_open": result.port_open,
                "service_healthy": result.service_healthy,
                "service_output": result.service_output,
                "overall": result.overall,
                "checks_performed": list(result.checks_performed),
            }
        finally:
            client.close()

    try:
        data = await anyio.to_thread.run_sync(_run)
        return JSONResponse(content=data)
    except Exception as exc:
        if type(exc).__name__ == "NotFound":
            return JSONResponse(
                status_code=404, content={"error": f"container '{name}' not found"}
            )
        raise


@router.get("/", tags=["discovery"])
async def api_root(request: Request) -> JSONResponse:
    """API discovery endpoint. Lists all available routes with tier requirements."""
    from roustabout.api.discovery import get_api_info

    config = getattr(request.app.state, "config", {})
    if not isinstance(config, dict):
        config = {}
    info = get_api_info(request.app, config)
    return JSONResponse(
        content={
            "roustabout": info.version,
            "api": info.api_version,
            "hosts": info.host_count,
            "capabilities": info.capabilities,
            "routes": [
                {
                    "path": r.path,
                    "method": r.method,
                    "summary": r.summary,
                    "tier": r.tier,
                }
                for r in info.routes
            ],
        }
    )


@router.post("/containers/{name}/{action}")
async def container_mutation(name: str, action: str, request: Request) -> JSONResponse:
    """Execute a container mutation through the gateway."""
    name = sanitize(name)[:128]
    action = sanitize(action)[:32]

    if action not in _VALID_MUTATIONS:
        return JSONResponse(
            status_code=400,
            content={
                "error": f"unknown action '{action}'",
                "valid_actions": sorted(_VALID_MUTATIONS),
            },
        )

    key_info: KeyInfo = request.state.key_info
    if not _has_tier(key_info.tier, "operate"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "insufficient permissions",
                "required_tier": "operate",
                "your_tier": key_info.tier,
            },
        )

    import anyio

    status, result = await anyio.to_thread.run_sync(lambda: _mutate(name, action, key_info))
    return JSONResponse(status_code=status, content=result)


@router.get("/capabilities")
async def capabilities(request: Request) -> dict[str, Any]:
    """Return capabilities available to the authenticated key."""
    key_info: KeyInfo = request.state.key_info
    tier = key_info.tier

    tier_enum = PermissionTier(tier)
    available = capabilities_for_tier(tier_enum)

    return {
        "tier": tier,
        "label": key_info.label,
        "capabilities": sorted(available),
    }


# --- Generate (compose from live state) ---


def _generate_single(
    project: str | None, include_stopped: bool, services: list[str] | None = None
) -> str:
    """Generate compose YAML (redacted), optionally filtered by services."""
    from roustabout.collector import collect
    from roustabout.config import load_config
    from roustabout.connection import connect
    from roustabout.generator import generate
    from roustabout.models import filter_by_project
    from roustabout.redactor import redact, resolve_patterns

    config = load_config()
    client = connect()
    try:
        env = collect(client)
        patterns = resolve_patterns(config.redact_patterns)
        redacted = redact(env, patterns)
        if project:
            redacted = filter_by_project(redacted, project)
        return generate(redacted, include_stopped=include_stopped, services=services)
    finally:
        client.close()


@router.get("/generate")
async def generate_route(
    request: Request,
    project: str | None = None,
    include_stopped: bool = False,
    services: str | None = None,
) -> Any:
    """Generate compose YAML from current container state (redacted)."""
    import anyio
    from fastapi.responses import PlainTextResponse

    svc_list = services.split(",") if services else None
    result = await anyio.to_thread.run_sync(
        lambda: _generate_single(project, include_stopped, svc_list)
    )
    return PlainTextResponse(result, media_type="text/yaml")


# --- Secret-Safe Migration Pipeline (LLD-036) ---


def _migrate_handler(body: dict[str, Any]) -> dict[str, Any]:
    """Run generate-and-extract pipeline."""
    from pathlib import Path

    from roustabout.collector import collect
    from roustabout.connection import connect
    from roustabout.supply_chain import generate_and_extract

    svc_list = body.get("services")

    client = connect()
    try:
        env = collect(client)
        result = generate_and_extract(
            env,
            Path(body["output_dir"]),
            services=svc_list,
            include_stopped=body.get("include_stopped", False),
            dry_run=body.get("dry_run", True),
        )
        return {
            "compose_path": result.compose_path,
            "env_file_path": result.env_file_path,
            "secrets_extracted": result.secrets_extracted,
            "env_files_consumed": result.env_files_consumed,
            "services": list(result.services),
            "warnings": list(result.warnings),
            "dry_run": result.dry_run,
        }
    finally:
        client.close()


@router.post("/supply-chain/migrate")
async def migrate_route(request: Request) -> JSONResponse:
    """Generate compose file with secrets extracted to .env."""
    import anyio

    key_info: KeyInfo = request.state.key_info
    if not _has_tier(key_info.tier, "elevate"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "insufficient permissions",
                "required_tier": "elevate",
                "your_tier": key_info.tier,
            },
        )

    body = await request.json()
    if "output_dir" not in body:
        return JSONResponse(
            status_code=400,
            content={"error": "output_dir is required"},
        )

    try:
        result = await anyio.to_thread.run_sync(lambda: _migrate_handler(body))
        return JSONResponse(content=result)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})


# --- DockStarter .env Import (LLD-037) ---


def _import_env_handler(body: dict[str, Any]) -> dict[str, Any]:
    """Parse and map DockStarter .env to per-stack files."""
    from pathlib import Path

    from roustabout.dockstarter_env import map_env_to_stacks, parse_dockstarter_env

    service_names = body.get("service_names")
    parsed = parse_dockstarter_env(
        Path(body["env_path"]),
        service_names=tuple(service_names) if service_names else None,
    )
    result = map_env_to_stacks(
        parsed,
        body["stack_mapping"],
        Path(body["output_dir"]),
        dry_run=body.get("dry_run", True),
    )
    return {
        "stacks_written": result.stacks_written,
        "vars_mapped": result.vars_mapped,
        "vars_duplicated": result.vars_duplicated,
        "unmapped_vars": list(result.unmapped_vars),
        "warnings": list(result.warnings),
        "dry_run": result.dry_run,
    }


def _parse_env_handler(env_path: str, service_names: list[str] | None) -> dict[str, Any]:
    """Parse DockStarter .env and return classification (no values)."""
    from pathlib import Path

    from roustabout.dockstarter_env import parse_dockstarter_env

    parsed = parse_dockstarter_env(
        Path(env_path),
        service_names=tuple(service_names) if service_names else None,
    )
    return {
        "source_path": parsed.source_path,
        "shared_vars": [v.key for v in parsed.shared_vars],
        "per_service": {
            svc: [v.key for v in vars_list] for svc, vars_list in parsed.per_service_vars.items()
        },
        "unmapped_vars": [v.key for v in parsed.unmapped_vars],
        "total_vars": (
            len(parsed.shared_vars)
            + sum(len(v) for v in parsed.per_service_vars.values())
            + len(parsed.unmapped_vars)
        ),
    }


@router.post("/supply-chain/import-env")
async def import_env_route(request: Request) -> JSONResponse:
    """Import DockStarter .env variables into per-stack .env files."""
    import anyio

    key_info: KeyInfo = request.state.key_info
    if not _has_tier(key_info.tier, "elevate"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "insufficient permissions",
                "required_tier": "elevate",
                "your_tier": key_info.tier,
            },
        )

    body = await request.json()
    for field in ("env_path", "stack_mapping", "output_dir"):
        if field not in body:
            return JSONResponse(
                status_code=400,
                content={"error": f"{field} is required"},
            )

    try:
        result = await anyio.to_thread.run_sync(lambda: _import_env_handler(body))
        return JSONResponse(content=result)
    except (ValueError, FileNotFoundError) as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})


@router.get("/supply-chain/parse-env")
async def parse_env_route(
    request: Request,
    path: str = "",
    service_names: str | None = None,
) -> JSONResponse:
    """Parse a DockStarter .env file and return classification (no values)."""
    import anyio

    if not path:
        return JSONResponse(
            status_code=400,
            content={"error": "path query parameter is required"},
        )

    svc_list = service_names.split(",") if service_names else None

    try:
        result = await anyio.to_thread.run_sync(lambda: _parse_env_handler(path, svc_list))
        return JSONResponse(content=result)
    except FileNotFoundError as exc:
        return JSONResponse(status_code=404, content={"error": str(exc)})


# --- Container Exec (Rule 0) ---


@router.post("/containers/{name}/exec")
async def exec_route(name: str, request: Request) -> JSONResponse:
    """Execute a command inside a container. ELEVATE tier."""
    import anyio

    name = sanitize(name)[:128]
    key_info: KeyInfo = request.state.key_info
    if not _has_tier(key_info.tier, "elevate"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "exec requires elevate tier",
                "required_tier": "elevate",
                "your_tier": key_info.tier,
            },
        )

    body = await request.json()
    command = body.get("command")
    if not command or not isinstance(command, list):
        return JSONResponse(
            status_code=400,
            content={"error": "command is required (list of strings)"},
        )

    user = body.get("user")
    workdir = body.get("workdir")
    timeout = body.get("timeout", 30)

    def _run() -> dict[str, Any]:
        from roustabout.connection import connect
        from roustabout.exec import (
            DeniedCommand,
            ExecCommand,
            execute,
            load_exec_config,
        )
        from roustabout.permissions import FrictionMechanism
        from roustabout.session import DockerSession

        cfg = _load_cfg_simple()
        client = connect(cfg)
        docker_session = DockerSession(client=client, host=cfg or "localhost")
        try:
            cmd = ExecCommand(
                target=name,
                command=tuple(command),
                user=user,
                workdir=workdir,
                timeout=timeout,
            )
            # Use allowlist when configured, denylist as fallback
            exec_config = load_exec_config(name)
            friction = (
                FrictionMechanism.ALLOWLIST
                if exec_config and exec_config.allowed
                else FrictionMechanism.DENYLIST
            )
            result = execute(docker_session, cmd, friction=friction)
            return {
                "success": result.success,
                "target": result.target,
                "command": list(result.command),
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "truncated": result.truncated,
                "error": result.error,
                "timed_out": result.timed_out,
            }
        except DeniedCommand as exc:
            return {
                "success": False,
                "target": name,
                "command": list(command),
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "truncated": False,
                "error": str(exc),
                "timed_out": False,
                "denied": True,
                "reason": exc.reason,
            }
        finally:
            client.close()

    try:
        data = await anyio.to_thread.run_sync(_run)
        return JSONResponse(content=data)
    except Exception as exc:
        if type(exc).__name__ == "NotFound":
            return JSONResponse(
                status_code=404, content={"error": f"container '{name}' not found"}
            )
        raise


# --- File Operations (Rule 0) ---


@router.post("/files/read")
async def file_read_route(request: Request) -> JSONResponse:
    """Read a file from the Docker host. ELEVATE tier."""
    import anyio

    key_info: KeyInfo = request.state.key_info
    if not _has_tier(key_info.tier, "elevate"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "file operations require elevate tier",
                "required_tier": "elevate",
                "your_tier": key_info.tier,
            },
        )

    body = await request.json()
    path = body.get("path")
    if not path:
        return JSONResponse(status_code=400, content={"error": "path is required"})

    def _run() -> dict[str, Any]:
        from pathlib import Path

        from roustabout.config import load_config
        from roustabout.file_ops import FileOpsConfig, read_file

        cfg = load_config()
        root = Path(cfg.file_root).resolve()
        config = FileOpsConfig(
            root=root,
            read_root=root,
            staging_root=root / ".roustabout-staging",
        )
        result = read_file(path, config=config)
        return {
            "success": result.success,
            "path": result.path,
            "content": result.content,
            "size": result.size,
            "truncated": result.truncated,
            "error": result.error,
        }

    data = await anyio.to_thread.run_sync(_run)
    if not data["success"]:
        return JSONResponse(status_code=400, content=data)
    return JSONResponse(content=data)


@router.post("/files/write")
async def file_write_route(request: Request) -> JSONResponse:
    """Write a file to the Docker host. ELEVATE tier, staged by default."""
    import anyio

    key_info: KeyInfo = request.state.key_info
    if not _has_tier(key_info.tier, "elevate"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "file operations require elevate tier",
                "required_tier": "elevate",
                "your_tier": key_info.tier,
            },
        )

    body = await request.json()
    path = body.get("path")
    content = body.get("content")
    if not path or content is None:
        return JSONResponse(
            status_code=400, content={"error": "path and content are required"}
        )

    direct = body.get("direct", False)
    session_id = body.get("session_id", "api")

    def _run() -> dict[str, Any]:
        from pathlib import Path

        from roustabout.config import load_config
        from roustabout.file_ops import FileOpsConfig, write_file
        from roustabout.permissions import FrictionMechanism

        cfg = load_config()
        root = Path(cfg.file_root).resolve()
        config = FileOpsConfig(
            root=root,
            read_root=root,
            staging_root=root / ".roustabout-staging",
        )
        friction = FrictionMechanism.DIRECT if direct else FrictionMechanism.STAGE
        result = write_file(
            path, content, config=config, friction=friction, session_id=session_id
        )
        return {
            "success": result.success,
            "path": result.path,
            "staged": result.staged,
            "staging_path": result.staging_path,
            "backup_path": result.backup_path,
            "diff": result.diff,
            "apply_command": result.apply_command,
            "error": result.error,
        }

    data = await anyio.to_thread.run_sync(_run)
    if not data["success"]:
        return JSONResponse(status_code=400, content=data)
    return JSONResponse(content=data)


# --- Stats (Rule 0) ---


@router.get("/stats")
async def stats_route(
    request: Request,
    container: str | None = None,
) -> JSONResponse:
    """Get container resource usage stats."""
    import anyio

    def _run() -> list[dict[str, Any]]:
        from roustabout.connection import connect
        from roustabout.health_stats import collect_stats

        client = connect()
        try:
            stats = collect_stats(client, target=container)
            return [
                {
                    "name": s.name,
                    "cpu_percent": s.cpu_percent,
                    "memory_usage_bytes": s.memory_usage_bytes,
                    "memory_limit_bytes": s.memory_limit_bytes,
                    "memory_percent": s.memory_percent,
                    "network_rx_bytes": s.network_rx_bytes,
                    "network_tx_bytes": s.network_tx_bytes,
                    "block_read_bytes": s.block_read_bytes,
                    "block_write_bytes": s.block_write_bytes,
                }
                for s in stats
            ]
        finally:
            client.close()

    data = await anyio.to_thread.run_sync(_run)
    return JSONResponse(content={"stats": data})
