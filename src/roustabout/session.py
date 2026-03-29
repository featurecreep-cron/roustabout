"""Per-connection session with Docker client lifecycle and rate limiting.

Each MCP connection gets its own session with isolated Docker client,
permission tier, and rate limiter. CLI gets an ephemeral session per command.
"""

from __future__ import annotations

import dataclasses
import functools
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from time import monotonic

from roustabout import connection

# Permission tiers


@functools.total_ordering
class PermissionTier(Enum):
    OBSERVE = "observe"
    OPERATE = "operate"
    ELEVATE = "elevate"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PermissionTier):
            return NotImplemented
        return self.value == other.value

    def __lt__(self, other: PermissionTier) -> bool:
        order = {PermissionTier.OBSERVE: 0, PermissionTier.OPERATE: 1, PermissionTier.ELEVATE: 2}
        return order[self] < order[other]

    def __hash__(self) -> int:
        return hash(self.value)


# Capability sets

_OBSERVE_CAPABILITIES: frozenset[str] = frozenset(
    {
        "can_snapshot",
        "can_audit",
        "can_audit_compose",
        "can_diff",
        "can_generate",
        "can_read_logs",
        "can_read_health",
        "can_dr_plan",
        "can_file_read",
        "can_digest_age",
        "can_reverse_map_env",
    }
)

_OPERATE_CAPABILITIES: frozenset[str] = _OBSERVE_CAPABILITIES | frozenset(
    {
        "can_start",
        "can_stop",
        "can_restart",
        "can_recreate",
        "can_notify_configure",
    }
)

_ELEVATE_CAPABILITIES: frozenset[str] = _OPERATE_CAPABILITIES | frozenset(
    {
        "can_update_image",
        "can_recreate_spec_change",
        "can_compose_apply",
        "can_file_write",
        "can_prune",
        "can_exec",
        "can_modify_secrets",
        "can_modify_tier_labels",
    }
)


def capabilities_for_tier(tier: PermissionTier) -> frozenset[str]:
    return {
        PermissionTier.OBSERVE: _OBSERVE_CAPABILITIES,
        PermissionTier.OPERATE: _OPERATE_CAPABILITIES,
        PermissionTier.ELEVATE: _ELEVATE_CAPABILITIES,
    }[tier]


# Docker session


@dataclass
class DockerSession:
    """A Docker client bound to a host."""

    client: object  # docker.DockerClient — typed as object to avoid import
    host: str
    is_alive: bool = True

    def close(self) -> None:
        close_fn = getattr(self.client, "close", None)
        if close_fn is not None:
            close_fn()


# Rate limiter


@dataclass
class _TokenBucket:
    max_tokens: int
    window_seconds: float
    tokens: int
    last_refill: float = field(default_factory=monotonic)

    def _refill(self) -> None:
        now = monotonic()
        elapsed = now - self.last_refill
        if elapsed >= self.window_seconds:
            self.tokens = self.max_tokens
            self.last_refill = now

    def available(self) -> int:
        self._refill()
        return self.tokens

    def time_until_refill(self) -> float:
        elapsed = monotonic() - self.last_refill
        return max(0.0, self.window_seconds - elapsed)


class RateLimitExceeded(Exception):
    """No tokens available for this target."""

    def __init__(self, target: str, retry_after: float) -> None:
        self.target = target
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded for '{target}'. Retry after {retry_after:.0f}s.")


@dataclass(frozen=True)
class _Reservation:
    target: str
    timestamp: float


@dataclass
class RateLimiter:
    """Token bucket rate limiter. Per-container and global limits."""

    max_tokens: int = 3
    window_seconds: float = 300.0
    global_max_tokens: int = 10
    _buckets: dict[str, _TokenBucket] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _get_bucket(self, target: str) -> _TokenBucket:
        if target not in self._buckets:
            max_t = self.global_max_tokens if target == "_global" else self.max_tokens
            self._buckets[target] = _TokenBucket(
                max_tokens=max_t,
                window_seconds=self.window_seconds,
                tokens=max_t,
            )
        return self._buckets[target]

    def reserve(self, target: str) -> _Reservation:
        with self._lock:
            bucket = self._get_bucket(target)
            if bucket.available() <= 0:
                raise RateLimitExceeded(target, bucket.time_until_refill())

            global_bucket = self._get_bucket("_global")
            if global_bucket.available() <= 0:
                raise RateLimitExceeded(target, global_bucket.time_until_refill())

            bucket.tokens -= 1
            global_bucket.tokens -= 1
            return _Reservation(target=target, timestamp=monotonic())

    def commit(self, reservation: _Reservation) -> None:
        # Token already consumed in reserve — nothing to do
        pass

    def release(self, reservation: _Reservation) -> None:
        with self._lock:
            bucket = self._get_bucket(reservation.target)
            bucket.tokens = min(bucket.tokens + 1, bucket.max_tokens)
            global_bucket = self._get_bucket("_global")
            global_bucket.tokens = min(global_bucket.tokens + 1, global_bucket.max_tokens)


# Session


@dataclass(frozen=True)
class Session:
    """Per-connection session state."""

    id: str
    docker: DockerSession
    tier: PermissionTier
    capabilities: frozenset[str]
    rate_limiter: RateLimiter
    created_at: str


# Errors


class SessionError(Exception):
    """Base for session errors."""


class SessionInvalidError(SessionError):
    """Docker connection is dead. Session must be recreated."""


class NoSessionError(SessionError):
    """No session established in current context."""


# ContextVar

current_session: ContextVar[Session] = ContextVar("current_session")


@contextmanager
def session_context(sess: Session) -> Generator[Session, None, None]:
    """Set current_session for the duration of the block."""
    token = current_session.set(sess)
    try:
        yield sess
    finally:
        current_session.reset(token)


def get_current_session() -> Session:
    """Read current_session ContextVar."""
    try:
        return current_session.get()
    except LookupError:
        raise NoSessionError("No session established. Use session_context() or create_session().")


# Session lifecycle


def create_session(
    *,
    docker_host: str | None = None,
    tier: PermissionTier = PermissionTier.OBSERVE,
    session_id: str | None = None,
) -> Session:
    """Create a new session with a fresh Docker client."""
    client = connection.connect(docker_host)
    host = docker_host or "localhost"
    docker_session = DockerSession(client=client, host=host)

    sid = session_id or str(uuid.uuid4())
    caps = capabilities_for_tier(tier)
    now = datetime.now(UTC).isoformat()

    return Session(
        id=sid,
        docker=docker_session,
        tier=tier,
        capabilities=caps,
        rate_limiter=RateLimiter(),
        created_at=now,
    )


def elevate_session(sess: Session, new_tier: PermissionTier) -> Session:
    """Return a new Session with updated tier and capabilities."""
    return dataclasses.replace(
        sess,
        tier=new_tier,
        capabilities=capabilities_for_tier(new_tier),
    )


def destroy_session(sess: Session) -> None:
    """Close Docker client. Idempotent."""
    sess.docker.close()
