"""Pattern-based secret redaction for environment variables.

Runs even when env vars will be hidden in output (defense in depth).
The redacted DockerEnvironment can be safely logged, diffed, or stored.
"""

from __future__ import annotations

import dataclasses
import re
from urllib.parse import urlsplit, urlunsplit

from roustabout.models import ContainerInfo, DockerEnvironment, make_environment

REDACTED = "[REDACTED]"

# Patterns match as substrings in env var KEY names (case-insensitive).
# Deliberately excludes overly broad terms like "auth" (matches AUTHENTIK_*)
# and bare "key" (matches REGISTRY_KEY, etc.). Specific compound patterns
# like "api_key" and "secret_key" cover the important cases.
DEFAULT_PATTERNS: tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "access_key",
    "secret_key",
)

# Matches secret-like keys inside JSON/structured values
_JSON_SECRET_RE = re.compile(
    r'["\'](?:secret|password|passwd|passphrase|token|api_key|client_secret|'
    r'private_key|access_key)["\']'
    r'\s*:\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Matches secrets passed as CLI flags: --password=value, --token value, etc.
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

    Three redaction mechanisms:
    1. Key-based: pattern substring in key name → full value replaced.
    2. URL credential: value contains ://user:pass@host → password portion replaced.
    3. Value-based: JSON/structured values with embedded secret keys → secret values replaced.
    """
    key_lower = key.lower()

    # 1. Key-based pattern match
    for pattern in patterns:
        if pattern.lower() in key_lower:
            # URL keys get partial redaction, not full
            if key_lower.endswith("_url"):
                if _has_url_credentials(value):
                    return _redact_url_password(value)
                return value
            return REDACTED

    # 2. Catch-all: any _url key with embedded credentials (partial redaction)
    if key_lower.endswith("_url") and _has_url_credentials(value):
        return _redact_url_password(value)

    # 3. Value-based: scan for embedded secrets in JSON/structured values
    if _JSON_SECRET_RE.search(value):
        return _redact_json_secrets(value)

    return value


def is_secret_key(key: str, value: str, patterns: tuple[str, ...]) -> bool:
    """Check if a key-value pair needs any redaction.

    Returns True if redact_value would change the value.
    """
    return redact_value(key, value, patterns) != value


def _has_url_credentials(value: str) -> bool:
    """Check if a value contains a URL with embedded credentials."""
    try:
        parsed = urlsplit(value)
        return bool(parsed.scheme and parsed.password)
    except (ValueError, AttributeError):
        return False


def _redact_url_password(value: str) -> str:
    """Replace only the password portion of a credential URL.

    Uses urllib.parse for correct handling of special characters,
    missing usernames, and URL-encoded values.
    """
    try:
        parsed = urlsplit(value)
        if not parsed.password:
            return value

        # Reconstruct netloc with redacted password
        user = parsed.username or ""
        host = parsed.hostname or ""
        port_str = f":{parsed.port}" if parsed.port else ""
        new_netloc = f"{user}:{REDACTED}@{host}{port_str}"

        return urlunsplit(
            (
                parsed.scheme,
                new_netloc,
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )
    except (ValueError, AttributeError):
        return REDACTED


def _redact_json_secrets(value: str) -> str:
    """Replace secret values inside JSON/structured strings."""

    def _replace_secret(match: re.Match) -> str:
        full = match.group(0)
        secret_value = match.group(1)
        return full.replace(secret_value, REDACTED)

    return _JSON_SECRET_RE.sub(_replace_secret, value)


def _redact_cli_args(args: tuple[str, ...]) -> tuple[str, ...]:
    """Redact secrets in command-line argument tuples.

    Handles patterns like --password=secret and --token secret.
    """
    result = list(args)
    for i, arg in enumerate(result):
        result[i] = _CLI_SECRET_RE.sub(rf"\g<1>{REDACTED}", arg)
    return tuple(result)
