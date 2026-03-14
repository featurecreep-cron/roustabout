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

    Args:
        docker_host: Optional Docker host URL (e.g. tcp://host:2375).
            If None, reads DOCKER_HOST env var, then falls back to the
            default local socket.

    Raises:
        Exception: If connection or ping fails.
    """
    host = docker_host or os.environ.get("DOCKER_HOST")
    kwargs = {"base_url": host} if host else {}
    client = docker.DockerClient(**kwargs)
    try:
        client.ping()
    except Exception:
        client.close()
        raise
    return client
