"""Tests for permissions — stateless capability checks.

Covers E2 S2.1.1-S2.1.2: tiered permissions, per-container overrides,
action-capability mapping, session filtering.
"""

from __future__ import annotations

import pytest

from roustabout.models import make_container
from roustabout.session import PermissionTier

# Fixtures

def _make_session(tier: PermissionTier):
    """Create a minimal session-like object for permission checks."""
    from unittest.mock import MagicMock

    from roustabout.session import DockerSession, RateLimiter, Session, capabilities_for_tier

    docker = DockerSession(client=MagicMock(), host="localhost")
    return Session(
        id="test-session",
        docker=docker,
        tier=tier,
        capabilities=capabilities_for_tier(tier),
        rate_limiter=RateLimiter(),
        created_at="2026-03-17T00:00:00Z",
    )


def _make_container_with_label(label_key: str, label_value: str):
    return make_container(
        name="test-container",
        id="abc123",
        status="running",
        image="test:latest",
        image_id="sha256:abc",
        labels=[(label_key, label_value)],
    )


# Action → capability mapping


class TestActionCapabilityMapping:
    def test_all_read_actions_exist(self):
        from roustabout.permissions import ACTION_CAPABILITY

        read_actions = [
            "snapshot", "audit", "diff", "generate",
            "read-logs", "read-health", "dr-plan",
        ]
        for action in read_actions:
            assert action in ACTION_CAPABILITY

    def test_all_mutation_actions_exist(self):
        from roustabout.permissions import ACTION_CAPABILITY

        mutation_actions = ["start", "stop", "restart", "recreate"]
        for action in mutation_actions:
            assert action in ACTION_CAPABILITY

    def test_elevate_actions_exist(self):
        from roustabout.permissions import ACTION_CAPABILITY

        elevate_actions = ["update-image", "prune", "exec"]
        for action in elevate_actions:
            assert action in ACTION_CAPABILITY


# Capability → tier mapping


class TestCapabilityTierMapping:
    def test_read_capabilities_are_observe(self):
        from roustabout.permissions import CAPABILITY_TIER

        observe_caps = [
            "can_snapshot", "can_audit", "can_diff", "can_generate",
            "can_read_logs", "can_read_health", "can_dr_plan",
        ]
        for cap in observe_caps:
            assert CAPABILITY_TIER[cap] == PermissionTier.OBSERVE

    def test_mutation_capabilities_are_operate(self):
        from roustabout.permissions import CAPABILITY_TIER

        operate_caps = ["can_start", "can_stop", "can_restart", "can_recreate"]
        for cap in operate_caps:
            assert CAPABILITY_TIER[cap] == PermissionTier.OPERATE

    def test_elevate_capabilities_are_elevate(self):
        from roustabout.permissions import CAPABILITY_TIER

        elevate_caps = [
            "can_update_image", "can_prune", "can_exec",
            "can_modify_compose", "can_modify_secrets", "can_modify_tier_labels",
        ]
        for cap in elevate_caps:
            assert CAPABILITY_TIER[cap] == PermissionTier.ELEVATE


# Permission check — tier-based


class TestCheckPermission:
    def test_observe_session_can_read(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.OBSERVE)
        # Should not raise
        check(session, "snapshot", target_info=None)

    def test_observe_session_cannot_mutate(self):
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OBSERVE)
        with pytest.raises(PermissionDenied) as exc_info:
            check(session, "restart", target_info=None)
        assert "requires" in str(exc_info.value)
        assert exc_info.value.session_tier == PermissionTier.OBSERVE

    def test_operate_session_can_read(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.OPERATE)
        check(session, "snapshot", target_info=None)

    def test_operate_session_can_mutate(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.OPERATE)
        check(session, "restart", target_info=None)

    def test_operate_session_cannot_elevate(self):
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OPERATE)
        with pytest.raises(PermissionDenied):
            check(session, "update-image", target_info=None)

    def test_elevate_session_can_do_everything(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.ELEVATE)
        check(session, "snapshot", target_info=None)
        check(session, "restart", target_info=None)
        check(session, "update-image", target_info=None)

    def test_unknown_action_raises_value_error(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.ELEVATE)
        with pytest.raises(ValueError, match="Unknown action"):
            check(session, "nonexistent-action", target_info=None)


# Per-container tier overrides (S2.1.2)


class TestPerContainerOverrides:
    def test_elevate_only_label_forces_elevate(self):
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OPERATE)
        container = _make_container_with_label("roustabout.tier", "elevate-only")
        with pytest.raises(PermissionDenied) as exc_info:
            check(session, "restart", target_info=container)
        assert exc_info.value.required_tier == PermissionTier.ELEVATE

    def test_elevate_session_overrides_label(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.ELEVATE)
        container = _make_container_with_label("roustabout.tier", "elevate-only")
        # Should not raise — session is Elevate
        check(session, "restart", target_info=container)

    def test_no_label_uses_default_tier(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.OPERATE)
        container = make_container(
            name="app", id="a1", status="running", image="app:latest", image_id="sha256:a1"
        )
        # Should not raise — no override label, Operate is sufficient
        check(session, "restart", target_info=container)

    def test_default_deny_list_by_image(self):
        """Database images default to elevate-only."""
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OPERATE)
        db_container = make_container(
            name="mydb", id="db1", status="running",
            image="postgres:16", image_id="sha256:db1",
        )
        with pytest.raises(PermissionDenied):
            check(session, "restart", target_info=db_container)

    def test_default_deny_list_redis(self):
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OPERATE)
        redis = make_container(
            name="cache", id="r1", status="running",
            image="redis:7-alpine", image_id="sha256:r1",
        )
        with pytest.raises(PermissionDenied):
            check(session, "stop", target_info=redis)

    def test_default_deny_list_auth(self):
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OPERATE)
        auth = make_container(
            name="auth", id="a1", status="running",
            image="ghcr.io/goauthentik/server:latest", image_id="sha256:a1",
        )
        with pytest.raises(PermissionDenied):
            check(session, "restart", target_info=auth)

    def test_read_operations_bypass_deny_list(self):
        """Read operations should still work on deny-listed containers."""
        from roustabout.permissions import check

        session = _make_session(PermissionTier.OBSERVE)
        db = make_container(
            name="mydb", id="db1", status="running",
            image="postgres:16", image_id="sha256:db1",
        )
        # Read operations should pass even for deny-listed containers
        check(session, "snapshot", target_info=db)

    def test_none_target_skips_override(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.OPERATE)
        check(session, "restart", target_info=None)


# can_session_do (MCP tool filtering)


class TestCanSessionDo:
    def test_observe_can_read(self):
        from roustabout.permissions import can_session_do

        session = _make_session(PermissionTier.OBSERVE)
        assert can_session_do(session, "snapshot") is True

    def test_observe_cannot_mutate(self):
        from roustabout.permissions import can_session_do

        session = _make_session(PermissionTier.OBSERVE)
        assert can_session_do(session, "restart") is False

    def test_unknown_action_returns_false(self):
        from roustabout.permissions import can_session_do

        session = _make_session(PermissionTier.ELEVATE)
        assert can_session_do(session, "nonexistent") is False


# list_capabilities (meta-tool)


class TestListCapabilities:
    def test_returns_all_capabilities(self):
        from roustabout.permissions import CAPABILITY_TIER, list_capabilities

        session = _make_session(PermissionTier.OBSERVE)
        caps = list_capabilities(session)
        assert len(caps) == len(CAPABILITY_TIER)

    def test_observe_availability(self):
        from roustabout.permissions import list_capabilities

        session = _make_session(PermissionTier.OBSERVE)
        caps = list_capabilities(session)
        by_cap = {c["capability"]: c for c in caps}
        assert by_cap["can_snapshot"]["available"] is True
        assert by_cap["can_restart"]["available"] is False
        assert by_cap["can_exec"]["available"] is False

    def test_elevate_all_available(self):
        from roustabout.permissions import list_capabilities

        session = _make_session(PermissionTier.ELEVATE)
        caps = list_capabilities(session)
        assert all(c["available"] is True for c in caps)


# PermissionDenied exception


class TestPermissionDenied:
    def test_is_exception(self):
        from roustabout.permissions import PermissionDenied

        exc = PermissionDenied(
            required_capability="can_restart",
            required_tier=PermissionTier.OPERATE,
            session_tier=PermissionTier.OBSERVE,
            target="nginx",
            reason="test denial",
        )
        assert isinstance(exc, Exception)
        assert str(exc) == "test denial"
        assert exc.target == "nginx"

    def test_no_target(self):
        from roustabout.permissions import PermissionDenied

        exc = PermissionDenied(
            required_capability="can_prune",
            required_tier=PermissionTier.ELEVATE,
            session_tier=PermissionTier.OPERATE,
            target=None,
            reason="no target",
        )
        assert exc.target is None
