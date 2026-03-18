"""Container log access — safe log retrieval without docker exec.

Retrieves logs via Docker API with sanitization and filtering.
Phase 1: Docker API logs only. In-container file access in Phase 2.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime
from typing import Any

import docker.errors as _docker_errors

from roustabout.redactor import sanitize

logger = logging.getLogger(__name__)

# Log drivers that support the Docker logs API
_SUPPORTED_DRIVERS = frozenset({"json-file", "local", "journald"})

# Relative duration pattern: digits + s/m/h/d
_RELATIVE_RE = re.compile(r"^(\d+)([smhd])$")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ContainerNotFoundError(Exception):
    """Container does not exist."""


class UnsupportedLogDriver(Exception):
    """Container uses a log driver that doesn't support the logs API."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def collect_logs(
    client: Any,
    container_name: str,
    *,
    tail: int = 100,
    since: str | None = None,
    grep: str | None = None,
    line_limit: int = 2048,
    timestamps: bool = False,
) -> str:
    """Retrieve sanitized logs for a container.

    Args:
        client: Docker client.
        container_name: Container name or ID.
        tail: Number of lines from end (default 100).
        since: Time filter — ISO 8601 or relative ("5m", "1h").
        grep: Substring filter — only return matching lines.
        line_limit: Max bytes per line (truncated with marker).
        timestamps: Include Docker timestamps.

    Returns:
        Sanitized log text.

    Raises:
        ContainerNotFoundError: Container doesn't exist.
        UnsupportedLogDriver: Log driver doesn't support API access.
    """
    try:
        container = client.containers.get(container_name)
    except _docker_errors.NotFound as e:
        raise ContainerNotFoundError(
            f"Container {container_name!r} not found"
        ) from e

    # Check log driver
    log_config = container.attrs.get("HostConfig", {}).get("LogConfig", {})
    driver = log_config.get("Type", "json-file")
    if driver not in _SUPPORTED_DRIVERS:
        raise UnsupportedLogDriver(
            f"Log driver '{driver}' does not support the Docker logs API. "
            f"Supported drivers: {', '.join(sorted(_SUPPORTED_DRIVERS))}"
        )

    # Build kwargs
    kwargs: dict[str, Any] = {
        "tail": tail,
        "timestamps": timestamps,
    }
    if since is not None:
        kwargs["since"] = parse_since(since)

    raw = container.logs(**kwargs)
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)

    # Process lines
    lines = text.splitlines()
    processed = []
    for line in lines:
        # Per-line sanitization
        line = sanitize(line)
        # Per-line truncation
        if len(line.encode("utf-8")) > line_limit:
            line = line[:line_limit] + "[truncated]"
        # Grep filtering
        if grep and grep not in line:
            continue
        processed.append(line)

    return "\n".join(processed)


# ---------------------------------------------------------------------------
# Since parsing
# ---------------------------------------------------------------------------


def parse_since(value: str) -> int | str:
    """Parse a since parameter into a Docker-compatible value.

    Relative durations ("5m", "1h", "30s", "1d") return Unix timestamp.
    ISO 8601 strings are returned as-is for Docker to parse.

    Raises ValueError for invalid input.
    """
    match = _RELATIVE_RE.match(value)
    if match:
        amount = int(match.group(1))
        unit = match.group(2)
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        seconds_ago = amount * multipliers[unit]
        return int(time.time()) - seconds_ago

    # Try ISO 8601
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value
    except ValueError:
        pass

    raise ValueError(
        f"Invalid since value: {value!r}. "
        f"Use relative duration (5m, 1h, 1d) or ISO 8601 timestamp."
    )
