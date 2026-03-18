"""Tests for notifications — event routing and channel delivery.

Covers E6: notification channels, event routing, delivery isolation.
"""

from __future__ import annotations

from unittest.mock import patch

from roustabout.notifications import (
    NotificationEvent,
    configure,
    send_event,
    send_mutation_event,
)

# ---------------------------------------------------------------------------
# NotificationEvent dataclass
# ---------------------------------------------------------------------------


class TestNotificationEvent:
    def test_fields(self):
        event = NotificationEvent(
            event_type="mutation.executed",
            severity="info",
            title="Restarted nginx",
            message="Container nginx restarted successfully",
            target="nginx",
            session_id="test-session",
        )
        assert event.event_type == "mutation.executed"
        assert event.target == "nginx"

    def test_optional_fields(self):
        event = NotificationEvent(
            event_type="lockdown.activated",
            severity="critical",
            title="Lockdown",
            message="Emergency lockdown activated",
        )
        assert event.target is None
        assert event.session_id is None


# ---------------------------------------------------------------------------
# Channel configuration
# ---------------------------------------------------------------------------


class TestConfigure:
    def test_empty_config(self):
        """No channels configured — no error."""
        configure([])

    def test_ntfy_channel(self):
        configure([{"type": "ntfy", "url": "https://ntfy.sh/test"}])

    def test_invalid_ntfy_scheme(self):
        """Non-HTTPS ntfy URL should warn but not crash."""
        # Should not raise
        configure([{"type": "ntfy", "url": "http://ntfy.sh/test"}])

    def test_unknown_channel_type_ignored(self):
        configure([{"type": "carrier_pigeon", "url": "lol"}])


# ---------------------------------------------------------------------------
# Event delivery
# ---------------------------------------------------------------------------


class TestSendEvent:
    def test_no_channels_no_error(self):
        configure([])
        event = NotificationEvent(
            event_type="mutation.executed",
            severity="info",
            title="test",
            message="test",
        )
        # Should not raise
        send_event(event)

    def test_ntfy_delivery(self):
        configure([{"type": "ntfy", "url": "https://ntfy.sh/test"}])
        event = NotificationEvent(
            event_type="mutation.executed",
            severity="info",
            title="Restarted nginx",
            message="Container nginx restarted",
            target="nginx",
        )
        with patch("roustabout.notifications._send_ntfy") as mock:
            send_event(event)
            mock.assert_called_once()

    def test_delivery_failure_does_not_raise(self):
        """Channel failure is swallowed — never blocks caller."""
        configure([{"type": "ntfy", "url": "https://ntfy.sh/test"}])
        event = NotificationEvent(
            event_type="mutation.failed",
            severity="warning",
            title="Failed",
            message="Stop failed",
        )
        with patch(
            "roustabout.notifications._send_ntfy",
            side_effect=ConnectionError("refused"),
        ):
            # Should NOT raise
            send_event(event)


# ---------------------------------------------------------------------------
# Convenience senders
# ---------------------------------------------------------------------------


class TestSendMutationEvent:
    def test_success_event(self):
        configure([{"type": "ntfy", "url": "https://ntfy.sh/test"}])
        with patch("roustabout.notifications.send_event") as mock:
            send_mutation_event(
                action="restart",
                target="nginx",
                success=True,
                session_id="test",
            )
            mock.assert_called_once()
            event = mock.call_args[0][0]
            assert event.event_type == "mutation.executed"
            assert event.severity == "info"

    def test_failure_event(self):
        configure([{"type": "ntfy", "url": "https://ntfy.sh/test"}])
        with patch("roustabout.notifications.send_event") as mock:
            send_mutation_event(
                action="restart",
                target="nginx",
                success=False,
                session_id="test",
            )
            event = mock.call_args[0][0]
            assert event.event_type == "mutation.failed"
            assert event.severity == "warning"


# ---------------------------------------------------------------------------
# ntfy specifics
# ---------------------------------------------------------------------------


class TestNtfySend:
    def test_priority_mapping(self):
        from roustabout.notifications import _ntfy_priority

        assert _ntfy_priority("critical") == "5"
        assert _ntfy_priority("warning") == "3"
        assert _ntfy_priority("info") == "2"
        assert _ntfy_priority("unknown") == "3"
