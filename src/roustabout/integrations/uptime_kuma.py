"""Uptime Kuma adapter."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from roustabout.integrations.manager import ServiceHealth


@dataclass(frozen=True)
class UptimeStatus:
    """Monitor status from Uptime Kuma."""

    monitor_name: str
    status: str  # up, down, pending
    uptime_24h: float | None
    avg_ping_ms: float | None
    url: str


@dataclass
class UptimeKumaAdapter:
    """Uptime Kuma integration — reads monitor status."""

    url: str
    api_key: str
    name: str = "uptime-kuma"

    @property
    def configured(self) -> bool:
        return bool(self.url and self.api_key)

    def health_check(self) -> ServiceHealth:
        resp = httpx.get(
            f"{self.url}/api/status-page/heartbeat/default",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=5,
        )
        resp.raise_for_status()
        return ServiceHealth(name=self.name, healthy=True)

    def enrich_container(self, container_name: str) -> dict[str, str]:
        """Match container to Uptime Kuma monitors by exact name."""
        monitors = self._get_monitors()
        matched = [m for m in monitors if container_name == m.monitor_name.lower()]
        if matched:
            m = matched[0]
            return {
                "uptime.status": m.status,
                "uptime.24h": f"{m.uptime_24h:.1f}%" if m.uptime_24h is not None else "unknown",
                "uptime.monitor": m.monitor_name,
            }
        return {}

    def list_monitors(self) -> tuple[UptimeStatus, ...]:
        """All configured monitors with current status."""
        return tuple(self._get_monitors())

    def _get_monitors(self) -> list[UptimeStatus]:
        resp = httpx.get(
            f"{self.url}/api/monitors",
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        monitors = data if isinstance(data, list) else data.get("monitors", [])
        return [
            UptimeStatus(
                monitor_name=m.get("name", ""),
                status="up" if m.get("active") else "down",
                uptime_24h=m.get("uptime24"),
                avg_ping_ms=m.get("avgPing"),
                url=m.get("url", ""),
            )
            for m in monitors
        ]
