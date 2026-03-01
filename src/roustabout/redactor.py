"""Pattern-based secret redaction for environment variables.

Runs even when env vars will be hidden in output (defense in depth).
The redacted DockerEnvironment can be safely logged, diffed, or stored.
"""

from __future__ import annotations

import dataclasses
import re

from roustabout.models import ContainerInfo, DockerEnvironment, make_container, make_environment

REDACTED = "[REDACTED]"

DEFAULT_PATTERNS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "api_key",
    "key",
    "credential",
    "private_key",
    "access_key",
    "database_url",
    "auth",
)

# Matches URLs with embedded credentials: scheme://user:pass@host
_CREDENTIAL_URL_RE = re.compile(r"://[^@]+@")


def redact(
    env: DockerEnvironment,
    patterns: tuple[str, ...] | None = None,
) -> DockerEnvironment:
    """Return a new DockerEnvironment with secrets replaced by [REDACTED].

    Args:
        env: The environment to redact.
        patterns: Case-insensitive substrings to match against env var keys.
            Defaults to DEFAULT_PATTERNS if None.
    """
    active_patterns = patterns if patterns is not None else DEFAULT_PATTERNS

    containers = [_redact_container(c, active_patterns) for c in env.containers]

    return make_environment(
        containers=containers,
        generated_at=env.generated_at,
        docker_version=env.docker_version,
    )


def _redact_container(
    container: ContainerInfo,
    patterns: tuple[str, ...],
) -> ContainerInfo:
    """Redact env vars in a single container."""
    redacted_env = [
        (key, REDACTED if _should_redact(key, value, patterns) else value)
        for key, value in container.env
    ]

    kwargs = {f.name: getattr(container, f.name) for f in dataclasses.fields(container)}
    kwargs["env"] = redacted_env
    return make_container(**kwargs)


def _should_redact(key: str, value: str, patterns: tuple[str, ...]) -> bool:
    """Determine if a key-value pair should be redacted.

    Two mechanisms:
    1. Pattern match: if a pattern substring appears in the key, redact —
       UNLESS the key ends with _url, in which case only redact if the
       value contains embedded credentials (://...@...).
    2. Catch-all: any key ending with _url whose value has embedded
       credentials is redacted regardless of pattern match.
    """
    key_lower = key.lower()

    # Catch-all: any _url key with embedded credentials
    if key_lower.endswith("_url") and _CREDENTIAL_URL_RE.search(value):
        return True

    for pattern in patterns:
        pattern_lower = pattern.lower()
        if pattern_lower in key_lower:
            # _url suffix without embedded credentials: don't redact
            if key_lower.endswith("_url"):
                return bool(_CREDENTIAL_URL_RE.search(value))
            return True

    return False
