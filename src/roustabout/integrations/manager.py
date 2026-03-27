"""Integration manager — loads and manages service adapters."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# Circuit breaker settings
MAX_FAILURES = 3
BREAKER_RESET_SECONDS = 300  # 5 minutes


@dataclass(frozen=True)
class ServiceHealth:
    """Health check result for a service adapter."""

    name: str
    healthy: bool
    version: str | None = None
    error: str | None = None


@runtime_checkable
class ServiceAdapter(Protocol):
    """Protocol for service integrations."""

    name: str
    configured: bool

    def health_check(self) -> ServiceHealth: ...

    def enrich_container(self, container_name: str) -> dict[str, str]: ...


@dataclass
class _CircuitBreaker:
    consecutive_failures: int = 0
    last_failure: float = 0.0

    @property
    def open(self) -> bool:
        if self.consecutive_failures < MAX_FAILURES:
            return False
        return (time.monotonic() - self.last_failure) < BREAKER_RESET_SECONDS

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        self.last_failure = time.monotonic()

    def record_success(self) -> None:
        self.consecutive_failures = 0


@dataclass
class IntegrationManager:
    """Loads and manages configured service adapters."""

    adapters: dict[str, ServiceAdapter] = field(default_factory=dict)
    _breakers: dict[str, _CircuitBreaker] = field(default_factory=dict)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> IntegrationManager:
        """Create adapters from roustabout.toml [integrations] section."""
        from roustabout.integrations.grafana import GrafanaAdapter
        from roustabout.integrations.traefik import TraefikAdapter
        from roustabout.integrations.uptime_kuma import UptimeKumaAdapter

        adapters: dict[str, ServiceAdapter] = {}
        integrations = config.get("integrations", {})

        if "traefik" in integrations:
            cfg = integrations["traefik"]
            adapters["traefik"] = TraefikAdapter(url=cfg.get("url", ""))

        if "uptime_kuma" in integrations:
            cfg = integrations["uptime_kuma"]
            adapters["uptime_kuma"] = UptimeKumaAdapter(
                url=cfg.get("url", ""),
                api_key=cfg.get("api_key", ""),
            )

        if "grafana" in integrations:
            cfg = integrations["grafana"]
            adapters["grafana"] = GrafanaAdapter(
                url=cfg.get("url", ""),
                api_key=cfg.get("api_key", ""),
            )

        return cls(adapters=adapters)

    def enrich_container(self, container_name: str) -> dict[str, str]:
        """Aggregate enrichment from all configured adapters."""
        enrichment: dict[str, str] = {}
        for name, adapter in self.adapters.items():
            if not adapter.configured:
                continue

            breaker = self._breakers.setdefault(name, _CircuitBreaker())
            if breaker.open:
                continue

            try:
                enrichment.update(adapter.enrich_container(container_name))
                breaker.record_success()
            except Exception:
                breaker.record_failure()
                logger.debug("Adapter %s failed for %s", name, container_name)

        return enrichment

    def health_check_all(self) -> dict[str, ServiceHealth]:
        """Check all configured adapters."""
        results: dict[str, ServiceHealth] = {}
        for name, adapter in self.adapters.items():
            if not adapter.configured:
                continue
            try:
                results[name] = adapter.health_check()
            except Exception as e:
                results[name] = ServiceHealth(name=name, healthy=False, error=str(e))
        return results
