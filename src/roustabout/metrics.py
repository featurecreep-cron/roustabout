"""Prometheus metrics — container and operational metrics.

Exposes metrics at /metrics in Prometheus exposition format.
Container metrics refresh on a configurable interval.
Operational counters increment in real-time.

LLD: docs/roustabout/designs/029-prometheus-metrics.md
"""

from __future__ import annotations

import logging
from typing import Any

from roustabout.health_stats import collect_health, collect_stats
from roustabout.redactor import sanitize

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Counter, Gauge, Histogram
except ImportError:
    # prometheus_client is optional — metrics disabled if not installed
    Counter = None  # type: ignore[assignment,misc]
    Gauge = None  # type: ignore[assignment,misc]
    Histogram = None  # type: ignore[assignment,misc]


def _available() -> bool:
    """Check if prometheus_client is installed."""
    return Gauge is not None


# --- Container metrics ---

if _available():
    roustabout_container_up = Gauge(
        "roustabout_container_up",
        "Whether the container is running (1) or not (0)",
        ["container", "host"],
    )
    roustabout_container_health = Gauge(
        "roustabout_container_health",
        "Container health status: 1=healthy, 0=unhealthy, -1=no healthcheck",
        ["container", "host"],
    )
    roustabout_container_restarts_total = Gauge(
        "roustabout_container_restarts_total",
        "Total restart count for the container",
        ["container", "host"],
    )
    roustabout_container_cpu_percent = Gauge(
        "roustabout_container_cpu_percent",
        "CPU usage percentage",
        ["container", "host"],
    )
    roustabout_container_memory_bytes = Gauge(
        "roustabout_container_memory_bytes",
        "Current memory usage in bytes",
        ["container", "host"],
    )
    roustabout_container_memory_limit_bytes = Gauge(
        "roustabout_container_memory_limit_bytes",
        "Memory limit in bytes",
        ["container", "host"],
    )
    roustabout_container_network_rx_bytes = Gauge(
        "roustabout_container_network_rx_bytes",
        "Network bytes received",
        ["container", "host"],
    )
    roustabout_container_network_tx_bytes = Gauge(
        "roustabout_container_network_tx_bytes",
        "Network bytes transmitted",
        ["container", "host"],
    )
    roustabout_container_image_age_seconds = Gauge(
        "roustabout_container_image_age_seconds",
        "Age of the container's image in seconds",
        ["container", "host", "image"],
    )

    # --- Operational metrics ---

    roustabout_mutations_total = Counter(
        "roustabout_mutations_total",
        "Total mutations executed through the gateway",
        ["action", "result", "host"],
    )
    roustabout_mutation_duration_seconds = Histogram(
        "roustabout_mutation_duration_seconds",
        "Duration of mutation execution",
        ["action", "host"],
        buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0),
    )
    roustabout_gate_rejections_total = Counter(
        "roustabout_gate_rejections_total",
        "Total gateway gate rejections",
        ["gate", "host"],
    )
    roustabout_audit_log_entries_total = Counter(
        "roustabout_audit_log_entries_total",
        "Total audit log entries written",
    )
    roustabout_exec_total = Counter(
        "roustabout_exec_total",
        "Total exec commands executed",
        ["result", "host"],
    )
    roustabout_drift_detected = Gauge(
        "roustabout_drift_detected",
        "Number of compose drift findings by severity",
        ["project", "severity"],
    )
else:
    # Stub objects when prometheus_client is not installed
    roustabout_container_up = None  # type: ignore[assignment]
    roustabout_container_health = None  # type: ignore[assignment]
    roustabout_container_restarts_total = None  # type: ignore[assignment]
    roustabout_container_cpu_percent = None  # type: ignore[assignment]
    roustabout_container_memory_bytes = None  # type: ignore[assignment]
    roustabout_container_memory_limit_bytes = None  # type: ignore[assignment]
    roustabout_container_network_rx_bytes = None  # type: ignore[assignment]
    roustabout_container_network_tx_bytes = None  # type: ignore[assignment]
    roustabout_container_image_age_seconds = None  # type: ignore[assignment]
    roustabout_mutations_total = None  # type: ignore[assignment]
    roustabout_mutation_duration_seconds = None  # type: ignore[assignment]
    roustabout_gate_rejections_total = None  # type: ignore[assignment]
    roustabout_audit_log_entries_total = None  # type: ignore[assignment]
    roustabout_exec_total = None  # type: ignore[assignment]
    roustabout_drift_detected = None  # type: ignore[assignment]


# --- Module state ---

_host_pool: Any = None
_config: dict[str, Any] = {}


def init_metrics(host_pool: Any, config: dict[str, Any]) -> None:
    """Called once at app startup to wire metric collection."""
    global _host_pool, _config
    _host_pool = host_pool
    _config = config


def update_container_metrics() -> None:
    """Refresh container gauges from all hosts.

    Called by a background task on a configurable interval or before scrape.
    """
    if not _available() or _host_pool is None:
        return

    max_containers = _config.get("metrics", {}).get("max_containers", 100)

    for host_cfg in _host_pool.list_hosts():
        host_name = host_cfg.name
        try:
            client = _host_pool.connect(host_name)
        except Exception:  # noqa: BLE001 — skip unreachable hosts
            continue

        try:
            # Health metrics
            healths = collect_health(client)
            for h in healths[:max_containers]:
                name = sanitize(h.name)
                roustabout_container_up.labels(container=name, host=host_name).set(
                    1 if h.status == "running" else 0
                )
                health_val = {"healthy": 1, "unhealthy": 0, None: -1}.get(h.health, -1)
                roustabout_container_health.labels(container=name, host=host_name).set(health_val)
                roustabout_container_restarts_total.labels(container=name, host=host_name).set(
                    h.restart_count
                )

            # Stats metrics
            if _config.get("metrics", {}).get("include_stats", True):
                stats = collect_stats(client)
                for s in stats[:max_containers]:
                    name = sanitize(s.name)
                    roustabout_container_cpu_percent.labels(container=name, host=host_name).set(
                        s.cpu_percent
                    )
                    roustabout_container_memory_bytes.labels(container=name, host=host_name).set(
                        s.memory_usage_bytes
                    )
                    roustabout_container_memory_limit_bytes.labels(
                        container=name, host=host_name
                    ).set(s.memory_limit_bytes)
                    roustabout_container_network_rx_bytes.labels(
                        container=name, host=host_name
                    ).set(s.network_rx_bytes)
                    roustabout_container_network_tx_bytes.labels(
                        container=name, host=host_name
                    ).set(s.network_tx_bytes)
        except Exception:  # noqa: BLE001 — skip host collection failures
            logger.warning("Failed to collect metrics for host %s", host_name)
        finally:
            _host_pool.release(host_name, client)
