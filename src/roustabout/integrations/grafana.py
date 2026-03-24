"""Grafana adapter."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from roustabout.integrations.manager import ServiceHealth


@dataclass(frozen=True)
class GrafanaDashboard:
    """A Grafana dashboard."""

    uid: str
    title: str
    url: str
    tags: tuple[str, ...]


@dataclass
class GrafanaAdapter:
    """Grafana integration — reads dashboards."""

    url: str
    api_key: str
    name: str = "grafana"

    @property
    def configured(self) -> bool:
        return bool(self.url and self.api_key)

    def health_check(self) -> ServiceHealth:
        resp = httpx.get(
            f"{self.url}/api/health",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        return ServiceHealth(
            name=self.name,
            healthy=True,
            version=data.get("version"),
        )

    def enrich_container(self, container_name: str) -> dict[str, str]:
        """Find Grafana dashboards tagged with this container's name."""
        dashboards = self._search_dashboards(query=container_name)
        if dashboards:
            d = dashboards[0]
            return {
                "grafana.dashboard": d.title,
                "grafana.url": f"{self.url}{d.url}",
            }
        return {}

    def list_dashboards(self) -> tuple[GrafanaDashboard, ...]:
        """All dashboards."""
        return tuple(self._search_dashboards())

    def _search_dashboards(self, query: str = "") -> list[GrafanaDashboard]:
        params = {"type": "dash-db"}
        if query:
            params["query"] = query
        resp = httpx.get(
            f"{self.url}/api/search",
            headers={"Authorization": f"Bearer {self.api_key}"},
            params=params,
            timeout=5,
        )
        resp.raise_for_status()
        return [
            GrafanaDashboard(
                uid=d.get("uid", ""),
                title=d.get("title", ""),
                url=d.get("url", ""),
                tags=tuple(d.get("tags", [])),
            )
            for d in resp.json()
        ]
