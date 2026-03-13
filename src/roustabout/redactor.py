"""Pattern-based secret redaction for environment variables.

Runs even when env vars will be hidden in output (defense in depth).
The redacted DockerEnvironment can be safely logged, diffed, or stored.
"""

from __future__ import annotations

import dataclasses
import re

from roustabout.models import ContainerInfo, DockerEnvironment, make_container, make_environment

REDACTED = "[REDACTED]"

# Patterns match as substrings in env var KEY names (case-insensitive).
# Deliberately excludes overly broad terms like "auth" (matches AUTHENTIK_*)
# and bare "key" (matches REGISTRY_KEY, etc.). Specific compound patterns
# like "api_key" and "secret_key" cover the important cases.
DEFAULT_PATTERNS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "access_key",
    "secret_key",
)

# Matches URLs with embedded credentials: scheme://user:pass@host
_CREDENTIAL_URL_RE = re.compile(r"(://[^:]+:)([^@]+)(@)")

# Matches secret-like keys inside JSON/structured values
_JSON_SECRET_RE = re.compile(
    r'["\'](?:secret|password|token|api_key|client_secret|private_key)["\']'
    r'\s*:\s*["\']([^"\']+)["\']',
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
            Defaults to DEFAULT_PATTERNS if None.
    """
    active_patterns = patterns if patterns is not None else DEFAULT_PATTERNS

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
    """Redact env vars in a single container."""
    redacted_env = [(key, redact_value(key, value, patterns)) for key, value in container.env]

    kwargs = {f.name: getattr(container, f.name) for f in dataclasses.fields(container)}
    kwargs["env"] = redacted_env
    return make_container(**kwargs)


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
                if _CREDENTIAL_URL_RE.search(value):
                    return _redact_url_password(value)
                return value
            return REDACTED

    # 2. Catch-all: any _url key with embedded credentials (partial redaction)
    if key_lower.endswith("_url") and _CREDENTIAL_URL_RE.search(value):
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


def _redact_url_password(value: str) -> str:
    """Replace only the password portion of a credential URL.

    ://user:password@host → ://user:[REDACTED]@host
    """
    return _CREDENTIAL_URL_RE.sub(rf"\g<1>{REDACTED}\g<3>", value)


def _redact_json_secrets(value: str) -> str:
    """Replace secret values inside JSON/structured strings."""

    def _replace_secret(match: re.Match) -> str:
        full = match.group(0)
        secret_value = match.group(1)
        return full.replace(secret_value, REDACTED)

    return _JSON_SECRET_RE.sub(_replace_secret, value)
