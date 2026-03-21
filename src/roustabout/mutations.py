"""Container mutation operations — start, stop, restart, recreate.

This is the only module that calls docker-py mutation methods.
Only gateway.py imports this module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import docker.errors as _docker_errors

from roustabout.redactor import sanitize
from roustabout.session import DockerSession

logger = logging.getLogger(__name__)


# Result type


@dataclass(frozen=True)
class MutationResult:
    """Outcome of a mutation operation."""

    success: bool
    action: str
    target: str
    error: str | None = None
    error_type: str | None = None  # connection_error, not_found, mutation_error


# Individual operations


def _stop(docker: DockerSession, target: str) -> MutationResult:
    container = docker.client.containers.get(target)
    container.stop()
    return MutationResult(success=True, action="stop", target=target)


def _start(docker: DockerSession, target: str) -> MutationResult:
    container = docker.client.containers.get(target)
    container.start()
    return MutationResult(success=True, action="start", target=target)


def _restart(docker: DockerSession, target: str) -> MutationResult:
    container = docker.client.containers.get(target)
    container.restart()
    return MutationResult(success=True, action="restart", target=target)


# Dispatch
_DISPATCH = {
    "start": _start,
    "stop": _stop,
    "restart": _restart,
}


def execute(
    docker: DockerSession,
    action: str,
    target: str,
    *,
    new_image: str | None = None,
) -> MutationResult:
    """Execute a container mutation.

    Routes to the appropriate handler based on action.
    All docker-py mutation calls are contained within this module.
    """
    handler = _DISPATCH.get(action)
    if handler is None:
        return MutationResult(
            success=False,
            action=action,
            target=target,
            error=f"Unknown mutation action: {action!r}",
            error_type="mutation_error",
        )

    try:
        return handler(docker, target)
    except _docker_errors.NotFound:
        return MutationResult(
            success=False,
            action=action,
            target=target,
            error=f"Container {target!r} not found",
            error_type="not_found",
        )
    except ConnectionError as e:
        return MutationResult(
            success=False,
            action=action,
            target=target,
            error=sanitize(str(e)),
            error_type="connection_error",
        )
    except _docker_errors.APIError as e:
        return MutationResult(
            success=False,
            action=action,
            target=target,
            error=sanitize(str(e)),
            error_type="mutation_error",
        )
