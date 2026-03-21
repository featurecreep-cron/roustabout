"""Secret redaction and metadata sanitization for Docker-sourced content.

Two independent transforms:
- sanitize(): strips control chars, ANSI escapes, bidi overrides, injection payloads
- redact(): replaces secret values with [REDACTED]

Pipeline: sanitize first (remove dangerous content), then redact (remove secrets).

Detection is delegated to secretscreen (5 detection layers, 221 format patterns).
Roustabout-specific concerns (DockerEnvironment model, CLI arg redaction) stay here.
"""

from __future__ import annotations

import dataclasses
import re
import unicodedata

from secretscreen import redact_pair
from secretscreen._keys import DEFAULT_KEY_PATTERNS

from roustabout.models import ContainerInfo, DockerEnvironment, make_environment

REDACTED = "[REDACTED]"

# Sanitization patterns (NFR-01)

# ASCII control characters except \n (0x0A) and \t (0x09), plus C1 codes
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]")

# ANSI escape sequences: CSI, OSC, character set, simple escapes
_ANSI_ESCAPE = re.compile(
    r"\x1b"
    r"(?:"
    r"\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    r"|"
    r"\][^\x07\x1b]*(?:\x07|\x1b\\|$)"
    r"|"
    r"[()#][A-Za-z0-9]"
    r"|"
    r"[A-Za-z]"
    r")"
)

# Unicode directional overrides (Trojan Source attack vectors)
_BIDI_OVERRIDES = re.compile(r"[\u202a-\u202e\u2066-\u2069]")

# Zero-width characters
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff]")

# Prompt injection patterns
_INJECTION_PATTERNS = re.compile(
    r"(?:"
    r"(?:^|\s)(?:system|assistant|user|human)\s*:"
    r"|<\|im_start\|>"
    r"|ignore\s+(?:previous|above|all\s+prior)"
    r"|disregard\s+(?:previous|your|all)"
    r"|forget\s+your\s+instructions"
    r"|system\s+prompt"
    r"|initial\s+instructions"
    r"|</tool_result>"
    r"|</function_call>"
    r"|```system"
    r")",
    re.IGNORECASE,
)

# Container name validation: Docker allows [a-zA-Z0-9][a-zA-Z0-9_.-]+
_VALID_NAME = re.compile(r"^/?[a-zA-Z0-9][a-zA-Z0-9_.\-/]*$")

MAX_LABEL_VALUE_LENGTH = 4096


def sanitize(text: str) -> str:
    """Strip dangerous content from a Docker-sourced string.

    Removes control chars, ANSI escapes, bidi overrides, zero-width chars.
    Preserves newlines, tabs, and valid UTF-8 text.
    """
    result = _ANSI_ESCAPE.sub("", text)
    result = _CONTROL_CHARS.sub("", result)
    result = _BIDI_OVERRIDES.sub("", result)
    result = _ZERO_WIDTH.sub("", result)
    return result


def check_prompt_injection(text: str) -> bool:
    """Check if text matches known prompt injection patterns.

    Must be called AFTER sanitize().
    """
    normalized = unicodedata.normalize("NFKC", text)
    return bool(_INJECTION_PATTERNS.search(normalized))


def flag_suspicious_name(name: str) -> bool:
    """Check if a container name has characters outside [a-zA-Z0-9._/-]."""
    if not name:
        return False
    return not bool(_VALID_NAME.match(name))


# Re-export default patterns for callers that need them (auditor, config).
DEFAULT_PATTERNS: tuple[str, ...] = DEFAULT_KEY_PATTERNS

# Matches secrets passed as CLI flags: --password=value, --token value, etc.
# This is roustabout-specific — secretscreen handles key-value pairs, not CLI args.
_CLI_SECRET_RE = re.compile(
    r"(--(?:password|passwd|passphrase|secret|token|api[_-]key|"
    r"private[_-]key|access[_-]key|credential)[=\s])(\S+)",
    re.IGNORECASE,
)

# Matches a bare secret flag without =value (for split-arg redaction).
_CLI_SECRET_FLAG_RE = re.compile(
    r"^--(?:password|passwd|passphrase|secret|token|api[_-]key|"
    r"private[_-]key|access[_-]key|credential)$",
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


def sanitize_environment(env: DockerEnvironment) -> DockerEnvironment:
    """Return a new DockerEnvironment with all string fields sanitized.

    Strips control chars, ANSI escapes, bidi overrides, zero-width chars
    from container names, images, env vars, labels, commands, and entrypoints.
    Must be called BEFORE redact() — sanitize first, then redact secrets.
    """
    containers = [_sanitize_container(c) for c in env.containers]
    return make_environment(
        containers=containers,
        generated_at=env.generated_at,
        docker_version=sanitize(env.docker_version) if env.docker_version else env.docker_version,
        warnings=env.warnings,
    )


def _sanitize_container(container: ContainerInfo) -> ContainerInfo:
    """Sanitize all string fields in a single container."""
    return dataclasses.replace(
        container,
        name=sanitize(container.name),
        image=sanitize(container.image),
        env=tuple((sanitize(k), sanitize(v)) for k, v in container.env),
        labels=tuple(
            (sanitize(k), sanitize(v)[:MAX_LABEL_VALUE_LENGTH]) for k, v in container.labels
        ),
        command=tuple(sanitize(a) for a in container.command) if container.command else None,
        entrypoint=(
            tuple(sanitize(a) for a in container.entrypoint) if container.entrypoint else None
        ),
    )


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

    Handles both combined (--password=secret) and split (--token, secret) forms.
    This is roustabout-specific — secretscreen handles key-value pairs only.
    """
    result = list(args)
    redact_next = False
    for i, arg in enumerate(result):
        if redact_next:
            result[i] = REDACTED
            redact_next = False
            continue
        # Combined form: --password=secret
        result[i] = _CLI_SECRET_RE.sub(rf"\g<1>{REDACTED}", arg)
        # Split form: --token secret (flag alone, value is next element)
        if _CLI_SECRET_FLAG_RE.match(arg):
            redact_next = True
    return tuple(result)
