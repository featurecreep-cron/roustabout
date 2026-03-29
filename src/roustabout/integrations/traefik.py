"""Traefik reverse proxy adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from roustabout.integrations.manager import ServiceHealth


@dataclass(frozen=True)
class TraefikRoute:
    """A Traefik HTTP route."""

    rule: str
    service: str
    entrypoints: tuple[str, ...]
    tls: bool
    middlewares: tuple[str, ...]


@dataclass
class TraefikAdapter:
    """Traefik integration — reads proxy routes."""

    url: str
    name: str = "traefik"

    @property
    def configured(self) -> bool:
        return bool(self.url)

    def health_check(self) -> ServiceHealth:
        resp = httpx.get(f"{self.url}/api/overview", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return ServiceHealth(
            name=self.name,
            healthy=True,
            version=data.get("version"),
        )

    def enrich_container(self, container_name: str) -> dict[str, str]:
        """Find Traefik routes that point to this container's service."""
        try:
            routers = httpx.get(f"{self.url}/api/http/routers", timeout=5).json()
        except Exception:
            return {}

        routes = [r for r in routers if _matches_container(r, container_name)]
        if routes:
            return {
                "traefik.routes": ", ".join(r.get("rule", "") for r in routes),
                "traefik.entrypoints": ", ".join(
                    ep for r in routes for ep in r.get("entryPoints", [])
                ),
                "traefik.tls": str(any(r.get("tls") for r in routes)),
            }
        return {}

    def list_routes(self) -> tuple[TraefikRoute, ...]:
        """All configured HTTP routes."""
        routers = httpx.get(f"{self.url}/api/http/routers", timeout=5).json()
        return tuple(
            TraefikRoute(
                rule=r.get("rule", ""),
                service=r.get("service", ""),
                entrypoints=tuple(r.get("entryPoints", [])),
                tls=bool(r.get("tls")),
                middlewares=tuple(r.get("middlewares", [])),
            )
            for r in routers
        )


def _matches_container(router: dict[str, Any], container_name: str) -> bool:
    """Check if a Traefik router likely belongs to a container."""
    service = router.get("service", "").lower()
    return container_name.lower() in service
