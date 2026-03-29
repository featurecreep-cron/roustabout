"""Service integrations — adapters for common homelab services.

Each adapter connects to a service's API to enrich roustabout's
understanding of the environment (proxy routes, uptime, dashboards).

LLD: docs/roustabout/designs/030-service-integrations.md
"""

from roustabout.integrations.manager import IntegrationManager, ServiceHealth

__all__ = ["IntegrationManager", "ServiceHealth"]
