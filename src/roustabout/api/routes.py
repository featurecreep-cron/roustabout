"""API route handlers — delegates to core logic, never calls Docker directly."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from roustabout.api.auth import KeyInfo
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


def _audit() -> dict[str, Any]:
    """Execute audit via core logic."""
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


def _dr_plan() -> dict[str, Any]:
    """Generate disaster recovery plan."""
    from roustabout.collector import collect
    from roustabout.config import load_config
    from roustabout.connection import connect
    from roustabout.dr_plan import generate
    from roustabout.redactor import redact, resolve_patterns

    config = load_config()
    client = connect()
    try:
        env = collect(client)
        patterns = resolve_patterns(config.redact_patterns)
        redacted = redact(env, patterns)
        plan = generate(redacted)
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
async def audit_route(request: Request) -> dict[str, Any]:
    """Run security audit and return findings."""
    import anyio

    return await anyio.to_thread.run_sync(_audit)


@router.get("/containers/{name}")
async def container_detail_route(name: str, request: Request) -> JSONResponse:
    """Get detail for a single container."""
    import anyio

    result = await anyio.to_thread.run_sync(lambda: _container_detail(name))
    if result is None:
        return JSONResponse(status_code=404, content={"error": f"container '{name}' not found"})
    return JSONResponse(content=result)


@router.get("/health/{name}")
async def health_route(name: str, request: Request) -> JSONResponse:
    """Get health status for a specific container."""
    import anyio

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
async def dr_plan_route(request: Request) -> dict[str, Any]:
    """Generate disaster recovery plan."""
    import anyio

    return await anyio.to_thread.run_sync(_dr_plan)


@router.post("/containers/{name}/{action}")
async def container_mutation(name: str, action: str, request: Request) -> JSONResponse:
    """Execute a container mutation through the gateway."""
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
