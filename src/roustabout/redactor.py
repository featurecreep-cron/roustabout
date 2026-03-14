"""Pattern-based secret redaction for environment variables.

Runs even when env vars will be hidden in output (defense in depth).
The redacted DockerEnvironment can be safely logged, diffed, or stored.

Detection is delegated to secretscreen (5 detection layers, 221 format patterns).
Roustabout-specific concerns (DockerEnvironment model, CLI arg redaction) stay here.
"""

from __future__ import annotations

import dataclasses
import re

from secretscreen import Mode, redact_pair
from secretscreen._keys import DEFAULT_KEY_PATTERNS

from roustabout.models import ContainerInfo, DockerEnvironment, make_environment

REDACTED = "[REDACTED]"

# Re-export default patterns for callers that need them (auditor, config).
DEFAULT_PATTERNS: tuple[str, ...] = DEFAULT_KEY_PATTERNS

# Matches secrets passed as CLI flags: --password=value, --token value, etc.
# This is roustabout-specific — secretscreen handles key-value pairs, not CLI args.
_CLI_SECRET_RE = re.compile(
    r"(--(?:password|passwd|passphrase|secret|token|api[_-]key|"
    r"private[_-]key|access[_-]key|credential)[=\s])(\S+)",
    re.IGNORECASE,
)


def resolve_patterns(
    custom: tuple[str, ...] = (),
    defaults: tuple[str, ...] = DEFAULT_PATTERNS,
) -> tuple[str, ...]:
    """Merge custom patterns with defaults. Custom extends, never replaces.

    Args:
        custom: Additional patterns from user config.
        defaults: Base patterns (normally DEFAULT_PATTERNS).

    Returns:
        Combined tuple with defaults first, then any new custom patterns.
    """
    if not custom:
        return defaults
    seen = {p.lower() for p in defaults}
    extra = tuple(p for p in custom if p.lower() not in seen)
    return defaults + extra


def redact(
    env: DockerEnvironment,
    patterns: tuple[str, ...] | None = None,
) -> DockerEnvironment:
    """Return a new DockerEnvironment with secrets replaced by [REDACTED].

    Args:
        env: The environment to redact.
        patterns: Case-insensitive substrings to match against env var keys.
            Defaults to DEFAULT_PATTERNS if None. Custom patterns are merged
            with defaults via resolve_patterns.
    """
    if patterns is None:
        active_patterns = DEFAULT_PATTERNS
    else:
        active_patterns = resolve_patterns(patterns)

    containers = [_redact_container(c, active_patterns) for c in env.containers]

    return make_environment(
        containers=containers,
        generated_at=env.generated_at,
        docker_version=env.docker_version,
        warnings=env.warnings,
    )


def _redact_container(
    container: ContainerInfo,
    patterns: tuple[str, ...],
) -> ContainerInfo:
    """Redact env vars, labels, and command strings in a single container."""
    redacted_env = tuple((key, redact_value(key, value, patterns)) for key, value in container.env)
    redacted_labels = tuple(
        (key, redact_value(key, value, patterns)) for key, value in container.labels
    )
    redacted_command = _redact_cli_args(container.command) if container.command else None
    redacted_entrypoint = _redact_cli_args(container.entrypoint) if container.entrypoint else None

    return dataclasses.replace(
        container,
        env=redacted_env,
        labels=redacted_labels,
        command=redacted_command,
        entrypoint=redacted_entrypoint,
    )


def redact_value(key: str, value: str, patterns: tuple[str, ...]) -> str:
    """Return the redacted form of a value, or the original if not secret.

    Delegates to secretscreen for detection and redaction across all layers:
    key patterns, structured parsing, 221 format patterns, URL credentials.
    """
    return redact_pair(key, value, extra_keys=patterns)


def is_secret_key(key: str, value: str, patterns: tuple[str, ...]) -> bool:
    """Check if a key-value pair needs any redaction.

    Returns True if redact_value would change the value.
    """
    return redact_value(key, value, patterns) != value


def _redact_cli_args(args: tuple[str, ...]) -> tuple[str, ...]:
    """Redact secrets in command-line argument tuples.

    Handles patterns like --password=secret and --token secret.
    This is roustabout-specific — secretscreen handles key-value pairs only.
    """
    result = list(args)
    for i, arg in enumerate(result):
        result[i] = _CLI_SECRET_RE.sub(rf"\g<1>{REDACTED}", arg)
    return tuple(result)
