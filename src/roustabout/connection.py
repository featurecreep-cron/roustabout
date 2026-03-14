"""Docker connection management.

Single source of truth for connecting to the Docker daemon.
CLI and MCP server wrap errors their own way; this module
provides the shared connection logic.
"""

from __future__ import annotations

import os

import docker


def connect(docker_host: str | None = None) -> docker.DockerClient:
    """Connect to Docker and verify the daemon is responsive.

    Resolution order:
        1. Explicit ``docker_host`` argument (from config file)
        2. ``DOCKER_HOST`` environment variable (standard Docker convention)
        3. Default local socket

    Args:
        docker_host: Docker host URL (e.g. ``unix:///tmp/docker.sock``,
            ``tcp://host:2375``). Overrides the environment variable.

    Raises:
        Exception: If connection or ping fails.
    """
    host = docker_host or os.environ.get("DOCKER_HOST")
    client = docker.DockerClient(base_url=host) if host else docker.DockerClient()
    try:
        client.ping()
    except Exception:
        client.close()
        raise
    return client
