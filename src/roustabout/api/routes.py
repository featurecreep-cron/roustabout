"""API route handlers — delegates to core logic, never calls Docker directly."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from roustabout.api.auth import KeyInfo
from roustabout.session import PermissionTier, capabilities_for_tier

router = APIRouter(prefix="/v1")

_VALID_MUTATIONS = frozenset({"start", "stop", "restart", "recreate"})

_MUTATION_TIERS = frozenset({"operate", "elevate"})

_TIER_ORDER = {"observe": 0, "operate": 1, "elevate": 2}


def _has_tier(key_tier: str, required: str) -> bool:
    """Check if key's tier meets or exceeds the required tier."""
    return _TIER_ORDER.get(key_tier, -1) >= _TIER_ORDER.get(required, 99)


def _snapshot() -> dict:
    """Execute snapshot via core logic. Separated for testability."""
    from roustabout.collector import collect
    from roustabout.config import load_config
    from roustabout.connection import connect
    from roustabout.redactor import redact, resolve_patterns

    config = load_config()
    client = connect()
    try:
        env = collect(client)
        patterns = resolve_patterns(config)
        redacted = redact(env, patterns)
        return {
            "containers": [
                {"name": c.name, "image": c.image, "status": c.status}
                for c in redacted.containers
            ],
            "daemon": None,
        }
    finally:
        client.close()


def _audit() -> dict:
    """Execute audit via core logic. Separated for testability."""
    from roustabout.auditor import audit
    from roustabout.collector import collect
    from roustabout.config import load_config
    from roustabout.connection import connect
    from roustabout.redactor import resolve_patterns

    config = load_config()
    client = connect()
    try:
        env = collect(client)
        patterns = resolve_patterns(config)
        findings = audit(env, patterns)
        return {
            "findings": [
                {
                    "check": f.check,
                    "severity": f.severity.value,
                    "container": f.container,
                    "message": f.message,
                }
                for f in findings
            ],
        }
    finally:
        client.close()


def _mutate(container_name: str, action: str) -> dict:
    """Execute mutation via gateway. Separated for testability."""
    # Gateway integration — will wire to gateway.execute() in next step
    return {"result": "success", "container": container_name, "action": action}


@router.get("/snapshot")
async def snapshot(request: Request) -> dict:
    """Collect and return redacted Docker environment state."""
    import anyio

    return await anyio.to_thread.run_sync(_snapshot)


@router.get("/audit")
async def audit_route(request: Request) -> dict:
    """Run security audit and return findings."""
    import anyio

    return await anyio.to_thread.run_sync(_audit)


@router.post("/containers/{name}/{action}")
async def container_mutation(name: str, action: str, request: Request) -> JSONResponse:
    """Execute a container mutation through the gateway."""
    if action not in _VALID_MUTATIONS:
        return JSONResponse(
            status_code=400,
            content={"error": f"unknown action '{action}'", "valid_actions": sorted(_VALID_MUTATIONS)},
        )

    key_info: KeyInfo = request.state.key_info
    if not _has_tier(key_info.tier, "operate"):
        return JSONResponse(
            status_code=403,
            content={"error": "insufficient permissions", "required_tier": "operate", "your_tier": key_info.tier},
        )

    import anyio

    result = await anyio.to_thread.run_sync(lambda: _mutate(name, action))
    return JSONResponse(content=result)


@router.get("/capabilities")
async def capabilities(request: Request) -> dict:
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
