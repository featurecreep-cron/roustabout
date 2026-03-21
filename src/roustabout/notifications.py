"""Notification routing — fire-and-forget event delivery.

Central notification bus. All events route through send_event().
Never blocks the gateway pipeline — delivery failures are logged, not raised.

Phase 1: ntfy channel only. Apprise support in Phase 2.
"""

from __future__ import annotations

import logging
import threading
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


# Prevent HTTP redirects from bypassing SSRF validation — a redirect
# from a validated host to localhost/metadata would defeat URL checks.
class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


_no_redirect_opener = urllib.request.build_opener(_NoRedirectHandler)

logger = logging.getLogger(__name__)


# Event type


@dataclass(frozen=True)
class NotificationEvent:
    """A notification event to route to configured channels."""

    event_type: str  # mutation.executed, mutation.failed, etc.
    severity: str  # info, warning, critical
    title: str
    message: str
    target: str | None = None
    session_id: str | None = None


# Channel state
_channels: list[dict[str, Any]] = []
_lock = threading.Lock()


def configure(channels: list[dict[str, Any]]) -> None:
    """Configure notification channels. Atomic swap."""
    validated = []
    for ch in channels:
        ch_type = ch.get("type", "")
        if ch_type == "ntfy":
            url = ch.get("url", "")
            if not url:
                logger.warning("ntfy channel missing url, skipping")
                continue
            if not _validate_ntfy_url(url):
                logger.warning("ntfy channel URL rejected: %s", url)
                continue
            validated.append({"type": "ntfy", "url": url})
        else:
            logger.warning("Unknown notification channel type: %s", ch_type)
    with _lock:
        global _channels
        _channels = validated


# Delivery


def send_event(event: NotificationEvent) -> None:
    """Route an event to all configured channels. Never raises."""
    with _lock:
        channels = list(_channels)

    for channel in channels:
        try:
            if channel["type"] == "ntfy":
                _send_ntfy(channel["url"], event)
        except (
            TimeoutError,
            ConnectionError,
            OSError,
            urllib.error.URLError,
        ):
            logger.warning(
                "Notification delivery failed for %s channel",
                channel["type"],
                exc_info=True,
            )
        except Exception:
            logger.warning(
                "Unexpected notification error for %s channel",
                channel["type"],
                exc_info=True,
            )


# ntfy channel

_SAFE_SCHEMES = frozenset({"https", "http"})

# RFC 1918, loopback, link-local — reject for SSRF prevention
_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "169.254.169.254",  # cloud metadata
        "metadata.google.internal",
    }
)


def _validate_ntfy_url(url: str) -> bool:
    """Reject URLs that could be used for SSRF."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in _SAFE_SCHEMES:
        return False
    host = (parsed.hostname or "").lower()
    if host in _BLOCKED_HOSTS:
        return False
    # Reject RFC 1918 ranges by prefix
    if host.startswith(("10.", "192.168.", "172.")):
        return False
    return True


def _ntfy_priority(severity: str) -> str:
    """Map event severity to ntfy priority level."""
    return {"critical": "5", "warning": "3", "info": "2"}.get(severity, "3")


def _send_ntfy(url: str, event: NotificationEvent) -> None:
    """Send event to ntfy topic via HTTP PUT."""
    data = event.message.encode("utf-8")
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Title", event.title)
    req.add_header("Priority", _ntfy_priority(event.severity))
    if event.event_type:
        req.add_header("Tags", event.event_type)
    _no_redirect_opener.open(req, timeout=10)  # noqa: S310


# Convenience senders


def send_mutation_event(
    *,
    action: str,
    target: str,
    success: bool,
    session_id: str | None = None,
    rolled_back: bool = False,
) -> None:
    """Send a mutation lifecycle event."""
    if rolled_back:
        event_type = "mutation.rolled_back"
        severity = "warning"
        title = f"Rolled back {action} on {target}"
        message = f"Mutation {action} on {target} failed and was rolled back"
    elif success:
        event_type = "mutation.executed"
        severity = "info"
        title = f"{action.capitalize()}ed {target}"
        message = f"Container {target} {action}ed successfully"
    else:
        event_type = "mutation.failed"
        severity = "warning"
        title = f"Failed to {action} {target}"
        message = f"Mutation {action} on {target} failed"

    send_event(
        NotificationEvent(
            event_type=event_type,
            severity=severity,
            title=title,
            message=message,
            target=target,
            session_id=session_id,
        )
    )
