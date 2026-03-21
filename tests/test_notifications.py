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

# NotificationEvent dataclass


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


# Channel configuration


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


# Event delivery


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


# Convenience senders


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

    def test_rollback_event(self):
        configure([{"type": "ntfy", "url": "https://ntfy.sh/test"}])
        with patch("roustabout.notifications.send_event") as mock:
            send_mutation_event(
                action="restart",
                target="nginx",
                success=False,
                rolled_back=True,
                session_id="test",
            )
            mock.assert_called_once()
            event = mock.call_args[0][0]
            assert event.event_type == "mutation.rolled_back"
            assert event.severity == "warning"
            assert "rolled back" in event.title.lower()
            assert "rolled back" in event.message.lower()


# ntfy specifics


class TestNtfySend:
    def test_priority_mapping(self):
        from roustabout.notifications import _ntfy_priority

        assert _ntfy_priority("critical") == "5"
        assert _ntfy_priority("warning") == "3"
        assert _ntfy_priority("info") == "2"
        assert _ntfy_priority("unknown") == "3"


class TestNtfyRedirectProtection:
    def test_no_redirect_handler_prevents_redirects(self):
        """_NoRedirectHandler returns None for redirect requests."""
        from roustabout.notifications import _NoRedirectHandler

        handler = _NoRedirectHandler()
        result = handler.redirect_request(None, None, 302, "", {}, "http://evil.com")
        assert result is None

    def test_opener_uses_no_redirect_handler(self):
        """The module-level opener blocks redirects."""
        from roustabout.notifications import _no_redirect_opener

        # Verify _NoRedirectHandler is in the handler chain
        handler_types = [type(h).__name__ for h in _no_redirect_opener.handlers]
        assert "_NoRedirectHandler" in handler_types


class TestNtfyUrlValidation:
    def test_https_allowed(self):
        from roustabout.notifications import _validate_ntfy_url

        assert _validate_ntfy_url("https://ntfy.sh/roustabout") is True

    def test_http_allowed(self):
        from roustabout.notifications import _validate_ntfy_url

        assert _validate_ntfy_url("http://ntfy.example.com/topic") is True

    def test_file_scheme_rejected(self):
        from roustabout.notifications import _validate_ntfy_url

        assert _validate_ntfy_url("file:///etc/passwd") is False

    def test_localhost_rejected(self):
        from roustabout.notifications import _validate_ntfy_url

        assert _validate_ntfy_url("http://localhost:8080/topic") is False
        assert _validate_ntfy_url("http://127.0.0.1/topic") is False

    def test_cloud_metadata_rejected(self):
        from roustabout.notifications import _validate_ntfy_url

        assert _validate_ntfy_url("http://169.254.169.254/latest") is False

    def test_rfc1918_rejected(self):
        from roustabout.notifications import _validate_ntfy_url

        assert _validate_ntfy_url("http://10.0.0.1/topic") is False
        assert _validate_ntfy_url("http://192.168.1.1/topic") is False

    def test_configure_rejects_bad_url(self):
        """configure() should skip channels with blocked URLs."""
        from roustabout.notifications import _lock

        # Reset state, then configure with a blocked URL
        configure([])
        configure([{"type": "ntfy", "url": "http://localhost/topic"}])
        from roustabout import notifications

        with _lock:
            assert len(notifications._channels) == 0

        configure([{"type": "ntfy", "url": "https://ntfy.sh/ok"}])
        with _lock:
            assert len(notifications._channels) == 1
