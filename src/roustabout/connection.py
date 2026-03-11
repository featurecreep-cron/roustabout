"""Docker connection management.

Single source of truth for connecting to the Docker daemon.
CLI and MCP server wrap errors their own way; this module
provides the shared connection logic.
"""

from __future__ import annotations

import docker


def connect(docker_host: str | None = None) -> docker.DockerClient:
    """Connect to Docker and verify the daemon is responsive.

    Args:
        docker_host: Optional Docker host URL (e.g. tcp://host:2375).
            If None, uses the default from environment/socket.

    Raises:
        Exception: If connection or ping fails.
    """
    kwargs = {"base_url": docker_host} if docker_host else {}
    client = docker.DockerClient(**kwargs)
    client.ping()
    return client
