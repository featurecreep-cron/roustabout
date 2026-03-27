"""Tests for secret_rotation module."""

from unittest.mock import MagicMock

import pytest

from roustabout.secret_rotation import (
    RotationPolicy,
    RotationResult,
    RotationStatus,
    SecretSharingReport,
    SharedSecret,
    audit_secret_sharing,
    check_stale_secrets,
    get_rotation_status,
    policies_from_config,
    rotate_secret,
)


# --- Helpers ---


def _policy(name="db_password", strategy="regenerate", interval=90, consumers=("db", "app")):
    return RotationPolicy(
        secret_name=name,
        strategy=strategy,
        interval_days=interval,
        warn_days=14,
        consumers=consumers,
        restart_order=consumers,
    )


# --- Rotation status ---


class TestGetRotationStatus:
    def test_returns_status_per_policy(self):
        broker = MagicMock()
        broker.get_metadata.return_value = None

        policies = (_policy("a"), _policy("b"))
        statuses = get_rotation_status(broker, policies)
        assert len(statuses) == 2
        assert statuses[0].secret_name == "a"
        assert statuses[1].secret_name == "b"

    def test_stale_when_no_metadata(self):
        broker = MagicMock()
        broker.get_metadata.return_value = None

        statuses = get_rotation_status(broker, (_policy(),))
        assert statuses[0].stale is True

    def test_stale_when_old(self):
        from datetime import UTC, datetime, timedelta

        broker = MagicMock()
        metadata = MagicMock()
        metadata.last_updated = datetime.now(UTC) - timedelta(days=100)
        broker.get_metadata.return_value = metadata

        statuses = get_rotation_status(broker, (_policy(interval=90),))
        assert statuses[0].stale is True

    def test_not_stale_when_fresh(self):
        from datetime import UTC, datetime, timedelta

        broker = MagicMock()
        metadata = MagicMock()
        metadata.last_updated = datetime.now(UTC) - timedelta(days=10)
        broker.get_metadata.return_value = metadata

        statuses = get_rotation_status(broker, (_policy(interval=90),))
        assert statuses[0].stale is False


class TestCheckStaleSecrets:
    def test_filters_stale_only(self):
        broker = MagicMock()
        broker.get_metadata.return_value = None  # All stale

        policies = (_policy("stale"),)
        stale = check_stale_secrets(broker, policies)
        assert len(stale) == 1


# --- Rotation ---


class TestRotateSecret:
    def test_non_regenerate_rejected(self):
        result = rotate_secret(
            MagicMock(),
            MagicMock(),
            MagicMock(),
            _policy(strategy="manual"),
        )
        assert result.success is False
        assert "manual" in result.error

    def test_successful_rotation(self):
        broker = MagicMock()
        broker.get_value.return_value = "old"
        broker.generate.return_value = "new"

        gateway = MagicMock()
        gateway_result = MagicMock()
        gateway_result.success = True
        gateway.execute.return_value = gateway_result

        session = MagicMock()

        result = rotate_secret(broker, gateway, session, _policy())
        assert result.success is True
        assert len(result.containers_updated) == 2
        assert len(result.containers_restarted) == 2
        assert result.rolled_back is False

    def test_injection_failure_rollback(self):
        broker = MagicMock()
        broker.get_value.return_value = "old"
        broker.generate.return_value = "new"
        # First inject succeeds, second fails
        broker.inject.side_effect = [None, Exception("injection failed")]

        result = rotate_secret(broker, MagicMock(), MagicMock(), _policy())
        assert result.success is False
        assert result.rolled_back is True
        assert "injection failed" in result.error

    def test_restart_failure_rollback(self):
        broker = MagicMock()
        broker.get_value.return_value = "old"
        broker.generate.return_value = "new"

        gateway = MagicMock()
        success = MagicMock()
        success.success = True
        failure = MagicMock()
        failure.success = False
        failure.error = "restart timeout"
        gateway.execute.side_effect = [success, failure, success]  # restart ok, fail, rollback ok

        result = rotate_secret(broker, gateway, MagicMock(), _policy())
        assert result.success is False
        assert result.rolled_back is True
        assert len(result.containers_restarted) == 1
        assert len(result.containers_failed) == 1


# --- Secret sharing audit ---


class TestAuditSecretSharing:
    def test_shared_secrets_detected(self):
        broker = MagicMock()
        secret1 = MagicMock()
        secret1.name = "db_password"
        secret2 = MagicMock()
        secret2.name = "api_key"
        broker.list_secrets.return_value = [secret1, secret2]
        broker.get_consumers.side_effect = lambda name: (
            ["db", "app", "worker"] if name == "db_password" else ["api"]
        )

        report = audit_secret_sharing(broker)
        assert report.total_secrets == 2
        assert len(report.shared_secrets) == 1
        assert report.shared_secrets[0].blast_radius == 3
        assert report.unique_secrets == 1

    def test_no_shared_secrets(self):
        broker = MagicMock()
        secret = MagicMock()
        secret.name = "solo"
        broker.list_secrets.return_value = [secret]
        broker.get_consumers.return_value = ["app"]

        report = audit_secret_sharing(broker)
        assert len(report.shared_secrets) == 0
        assert report.unique_secrets == 1


# --- Config parsing ---


class TestPoliciesFromConfig:
    def test_disabled(self):
        config = {"secrets": {"rotation": {"enabled": False}}}
        assert policies_from_config(config) == ()

    def test_empty(self):
        assert policies_from_config({}) == ()

    def test_valid_config(self):
        config = {
            "secrets": {
                "rotation": {
                    "enabled": True,
                    "policies": [
                        {
                            "name": "db_password",
                            "strategy": "regenerate",
                            "interval_days": 90,
                            "warn_days": 14,
                            "consumers": ["postgres", "app"],
                            "restart_order": ["postgres", "app"],
                        }
                    ],
                }
            }
        }
        policies = policies_from_config(config)
        assert len(policies) == 1
        assert policies[0].secret_name == "db_password"
        assert policies[0].strategy == "regenerate"
