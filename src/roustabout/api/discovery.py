"""API discovery — route listing and capability summary.

Provides a root endpoint that returns all available API routes,
their methods, required tier, and documentation.

LLD: docs/roustabout/designs/033-api-discovery.md
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from fastapi.routing import APIRoute


# Data types


@dataclass(frozen=True)
class RouteInfo:
    """Information about a single API route."""

    path: str
    method: str
    summary: str
    tier: str  # observe, operate, elevate, none
    tags: tuple[str, ...]


@dataclass(frozen=True)
class APIInfo:
    """API discovery information."""

    version: str
    api_version: str
    host_count: int
    routes: tuple[RouteInfo, ...]
    capabilities: dict[str, str]


# Tier derivation

_TIER_TAGS = frozenset({"observe", "operate", "elevate", "none"})


def _get_route_tier(route: APIRoute) -> str:
    """Derive tier from route tags or dependency names.

    Checks route.tags for known tier names, then falls back to inspecting
    the dependency chain for require_observe/require_operate/require_elevate.
    Returns "none" for unauthenticated routes (tagged "discovery" or /metrics).
    """
    for tag in getattr(route, "tags", []):
        if tag in _TIER_TAGS:
            return tag

    if "discovery" in getattr(route, "tags", []):
        return "none"

    for dep in getattr(route, "dependencies", []):
        dep_name = getattr(getattr(dep, "dependency", None), "__name__", "")
        if dep_name.startswith("require_"):
            return dep_name.replace("require_", "")

    return "observe"


def _get_version() -> str:
    """Get roustabout version."""
    try:
        from roustabout import __version__

        return __version__
    except (ImportError, AttributeError):
        return "unknown"


# Public API


def get_api_info(app: FastAPI, config: dict[str, Any]) -> APIInfo:
    """Build API info from FastAPI route table."""
    routes: list[RouteInfo] = []

    for route in app.routes:
        if isinstance(route, APIRoute):
            path = route.path
            tier = _get_route_tier(route)
            for method in route.methods or []:
                routes.append(
                    RouteInfo(
                        path=path,
                        method=method,
                        summary=route.summary or (route.name or "").replace("_", " "),
                        tier=tier,
                        tags=tuple(route.tags or []),
                    )
                )

    host_count = len(config.get("hosts", {})) or 1

    return APIInfo(
        version=_get_version(),
        api_version="v1",
        host_count=host_count,
        routes=tuple(sorted(routes, key=lambda r: (r.path, r.method))),
        capabilities={
            "observe": "snapshot, audit, health, logs, dr-plan, network, ports, drift",
            "operate": "observe + start, stop, restart, recreate",
            "elevate": "operate + exec, probes, image updates, secrets, compose",
        },
    )
