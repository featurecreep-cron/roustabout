"""Tests for permissions — friction-based capability checks.

Covers: FrictionMechanism enum, PermissionResult, CAPABILITY_FRICTION mapping,
check() with friction routing, resolve_friction(), can_session_do(), list_capabilities(),
per-container overrides, hard deny cases.
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


# FrictionMechanism enum


class TestFrictionMechanism:
    def test_all_values_exist(self):
        from roustabout.permissions import FrictionMechanism

        assert FrictionMechanism.DIRECT.value == "direct"
        assert FrictionMechanism.CONFIRM.value == "confirm"
        assert FrictionMechanism.STAGE.value == "stage"
        assert FrictionMechanism.DIRECTED.value == "directed"
        assert FrictionMechanism.ALLOWLIST.value == "allowlist"
        assert FrictionMechanism.DENYLIST.value == "denylist"

    def test_six_members(self):
        from roustabout.permissions import FrictionMechanism

        assert len(FrictionMechanism) == 6


# PermissionResult dataclass


class TestPermissionResult:
    def test_frozen(self):
        from roustabout.permissions import FrictionMechanism, PermissionResult

        result = PermissionResult(
            action="start",
            capability="can_start",
            friction=FrictionMechanism.DIRECT,
            session_tier=PermissionTier.OPERATE,
            effective_tier=PermissionTier.OPERATE,
            target="nginx",
        )
        with pytest.raises(AttributeError):
            result.action = "stop"

    def test_target_can_be_none(self):
        from roustabout.permissions import FrictionMechanism, PermissionResult

        result = PermissionResult(
            action="prune",
            capability="can_prune",
            friction=FrictionMechanism.DIRECTED,
            session_tier=PermissionTier.OBSERVE,
            effective_tier=PermissionTier.OBSERVE,
            target=None,
        )
        assert result.target is None


# Action → capability mapping


class TestActionCapabilityMapping:
    def test_all_read_actions_exist(self):
        from roustabout.permissions import ACTION_CAPABILITY

        read_actions = [
            "snapshot",
            "audit",
            "audit-compose",
            "diff",
            "generate",
            "read-logs",
            "read-health",
            "dr-plan",
            "digest-age",
            "reverse-map-env",
        ]
        for action in read_actions:
            assert action in ACTION_CAPABILITY, f"Missing read action: {action}"

    def test_all_mutation_actions_exist(self):
        from roustabout.permissions import ACTION_CAPABILITY

        mutation_actions = [
            "start",
            "stop",
            "restart",
            "recreate",
            "recreate-spec-change",
            "update-image",
        ]
        for action in mutation_actions:
            assert action in ACTION_CAPABILITY, f"Missing mutation action: {action}"

    def test_new_actions_exist(self):
        from roustabout.permissions import ACTION_CAPABILITY

        new_actions = [
            "exec",
            "file-read",
            "file-write",
            "compose-apply",
            "prune",
            "modify-secrets",
            "modify-tier-labels",
        ]
        for action in new_actions:
            assert action in ACTION_CAPABILITY, f"Missing action: {action}"


# CAPABILITY_FRICTION mapping


class TestCapabilityFriction:
    def test_read_ops_direct_at_all_tiers(self):
        from roustabout.permissions import CAPABILITY_FRICTION, FrictionMechanism

        read_caps = [
            "can_snapshot",
            "can_audit",
            "can_audit_compose",
            "can_diff",
            "can_generate",
            "can_read_logs",
            "can_read_health",
            "can_dr_plan",
            "can_digest_age",
            "can_reverse_map_env",
            "can_file_read",
        ]
        for cap in read_caps:
            for tier in PermissionTier:
                assert CAPABILITY_FRICTION[cap][tier] == FrictionMechanism.DIRECT, (
                    f"{cap} at {tier} should be DIRECT"
                )

    def test_lifecycle_directed_at_observe_direct_at_operate(self):
        from roustabout.permissions import CAPABILITY_FRICTION, FrictionMechanism

        lifecycle_caps = ["can_start", "can_stop", "can_restart", "can_recreate"]
        for cap in lifecycle_caps:
            assert CAPABILITY_FRICTION[cap][PermissionTier.OBSERVE] == FrictionMechanism.DIRECTED
            assert CAPABILITY_FRICTION[cap][PermissionTier.OPERATE] == FrictionMechanism.DIRECT
            assert CAPABILITY_FRICTION[cap][PermissionTier.ELEVATE] == FrictionMechanism.DIRECT

    def test_spec_change_confirm_at_operate(self):
        from roustabout.permissions import CAPABILITY_FRICTION, FrictionMechanism

        for cap in ("can_recreate_spec_change", "can_update_image"):
            assert CAPABILITY_FRICTION[cap][PermissionTier.OBSERVE] == FrictionMechanism.DIRECTED
            assert CAPABILITY_FRICTION[cap][PermissionTier.OPERATE] == FrictionMechanism.CONFIRM
            assert CAPABILITY_FRICTION[cap][PermissionTier.ELEVATE] == FrictionMechanism.DIRECT

    def test_exec_friction_ladder(self):
        from roustabout.permissions import CAPABILITY_FRICTION, FrictionMechanism

        ce = CAPABILITY_FRICTION["can_exec"]
        assert ce[PermissionTier.OBSERVE] == FrictionMechanism.DIRECTED
        assert ce[PermissionTier.OPERATE] == FrictionMechanism.ALLOWLIST
        assert ce[PermissionTier.ELEVATE] == FrictionMechanism.DENYLIST

    def test_file_write_friction_ladder(self):
        from roustabout.permissions import CAPABILITY_FRICTION, FrictionMechanism

        fw = CAPABILITY_FRICTION["can_file_write"]
        assert fw[PermissionTier.OBSERVE] == FrictionMechanism.DIRECTED
        assert fw[PermissionTier.OPERATE] == FrictionMechanism.STAGE
        assert fw[PermissionTier.ELEVATE] == FrictionMechanism.DIRECT

    def test_compose_apply_friction_ladder(self):
        from roustabout.permissions import CAPABILITY_FRICTION, FrictionMechanism

        ca = CAPABILITY_FRICTION["can_compose_apply"]
        assert ca[PermissionTier.OBSERVE] == FrictionMechanism.DIRECTED
        assert ca[PermissionTier.OPERATE] == FrictionMechanism.CONFIRM
        assert ca[PermissionTier.ELEVATE] == FrictionMechanism.DIRECT


# resolve_friction


class TestResolveFriction:
    def test_known_capability(self):
        from roustabout.permissions import FrictionMechanism, resolve_friction

        assert resolve_friction("can_start", PermissionTier.OBSERVE) == FrictionMechanism.DIRECTED
        assert resolve_friction("can_start", PermissionTier.OPERATE) == FrictionMechanism.DIRECT

    def test_unknown_capability_returns_directed(self):
        from roustabout.permissions import FrictionMechanism, resolve_friction

        result = resolve_friction("can_nonexistent", PermissionTier.ELEVATE)
        assert result == FrictionMechanism.DIRECTED


# check() — friction-based


class TestCheckFriction:
    def test_observe_read_returns_direct(self):
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.OBSERVE)
        result = check(session, "snapshot", target_info=None)
        assert result.friction == FrictionMechanism.DIRECT
        assert result.action == "snapshot"
        assert result.capability == "can_snapshot"

    def test_observe_mutation_returns_directed(self):
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.OBSERVE)
        result = check(session, "restart", target_info=None)
        assert result.friction == FrictionMechanism.DIRECTED

    def test_operate_mutation_returns_direct(self):
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.OPERATE)
        result = check(session, "restart", target_info=None)
        assert result.friction == FrictionMechanism.DIRECT

    def test_operate_spec_change_returns_confirm(self):
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.OPERATE)
        result = check(session, "recreate-spec-change", target_info=None)
        assert result.friction == FrictionMechanism.CONFIRM

    def test_operate_exec_returns_allowlist(self):
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.OPERATE)
        result = check(session, "exec", target_info=None)
        assert result.friction == FrictionMechanism.ALLOWLIST

    def test_operate_file_write_returns_stage(self):
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.OPERATE)
        result = check(session, "file-write", target_info=None)
        assert result.friction == FrictionMechanism.STAGE

    def test_elevate_exec_returns_denylist(self):
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.ELEVATE)
        result = check(session, "exec", target_info=None)
        assert result.friction == FrictionMechanism.DENYLIST

    def test_elevate_modify_tier_labels_returns_confirm(self):
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.ELEVATE)
        result = check(session, "modify-tier-labels", target_info=None)
        assert result.friction == FrictionMechanism.CONFIRM

    def test_unknown_action_raises_value_error(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.ELEVATE)
        with pytest.raises(ValueError, match="Unknown action"):
            check(session, "nonexistent-action", target_info=None)

    def test_result_includes_session_and_effective_tier(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.OPERATE)
        result = check(session, "restart", target_info=None)
        assert result.session_tier == PermissionTier.OPERATE
        assert result.effective_tier == PermissionTier.OPERATE

    def test_result_includes_target(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.OPERATE)
        container = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
        )
        result = check(session, "restart", target_info=container)
        assert result.target == "app"


# Hard deny cases


class TestHardDeny:
    def test_elevate_only_label_denies_at_observe(self):
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OBSERVE)
        container = _make_container_with_label("roustabout.tier", "elevate-only")
        with pytest.raises(PermissionDenied) as exc_info:
            check(session, "restart", target_info=container)
        assert exc_info.value.required_tier == PermissionTier.ELEVATE

    def test_elevate_only_label_denies_at_operate(self):
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OPERATE)
        container = _make_container_with_label("roustabout.tier", "elevate-only")
        with pytest.raises(PermissionDenied):
            check(session, "restart", target_info=container)

    def test_elevate_only_label_allows_at_elevate(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.ELEVATE)
        container = _make_container_with_label("roustabout.tier", "elevate-only")
        result = check(session, "restart", target_info=container)
        assert result.friction is not None

    def test_modify_tier_labels_denied_at_observe(self):
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OBSERVE)
        with pytest.raises(PermissionDenied) as exc_info:
            check(session, "modify-tier-labels", target_info=None)
        assert "ELEVATE" in str(exc_info.value) or "elevate" in str(exc_info.value).lower()

    def test_modify_tier_labels_denied_at_operate(self):
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OPERATE)
        with pytest.raises(PermissionDenied):
            check(session, "modify-tier-labels", target_info=None)

    def test_modify_tier_labels_allowed_at_elevate(self):
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.ELEVATE)
        result = check(session, "modify-tier-labels", target_info=None)
        assert result.friction == FrictionMechanism.CONFIRM

    def test_default_deny_list_by_image(self):
        """Database images denied at sub-ELEVATE tiers."""
        from roustabout.permissions import PermissionDenied, check

        session = _make_session(PermissionTier.OPERATE)
        db = make_container(
            name="mydb",
            id="db1",
            status="running",
            image="postgres:16",
            image_id="sha256:db1",
        )
        with pytest.raises(PermissionDenied):
            check(session, "restart", target_info=db)

    def test_deny_list_allows_read_ops(self):
        """Read operations bypass deny list."""
        from roustabout.permissions import FrictionMechanism, check

        session = _make_session(PermissionTier.OBSERVE)
        db = make_container(
            name="mydb",
            id="db1",
            status="running",
            image="postgres:16",
            image_id="sha256:db1",
        )
        result = check(session, "snapshot", target_info=db)
        assert result.friction == FrictionMechanism.DIRECT

    def test_deny_list_allows_at_elevate(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.ELEVATE)
        db = make_container(
            name="mydb",
            id="db1",
            status="running",
            image="postgres:16",
            image_id="sha256:db1",
        )
        result = check(session, "restart", target_info=db)
        assert result.friction is not None

    def test_none_target_skips_override(self):
        from roustabout.permissions import check

        session = _make_session(PermissionTier.OPERATE)
        result = check(session, "restart", target_info=None)
        assert result is not None


# can_session_do (MCP tool filtering)


class TestCanSessionDo:
    def test_all_known_actions_return_true(self):
        from roustabout.permissions import ACTION_CAPABILITY, can_session_do

        session = _make_session(PermissionTier.OBSERVE)
        for action in ACTION_CAPABILITY:
            assert can_session_do(session, action) is True

    def test_unknown_action_returns_false(self):
        from roustabout.permissions import can_session_do

        session = _make_session(PermissionTier.ELEVATE)
        assert can_session_do(session, "nonexistent") is False


# list_capabilities (meta-tool)


class TestListCapabilities:
    def test_returns_all_capabilities(self):
        from roustabout.permissions import ACTION_CAPABILITY, list_capabilities

        session = _make_session(PermissionTier.OBSERVE)
        caps = list_capabilities(session)
        assert len(caps) == len(ACTION_CAPABILITY)

    def test_includes_friction_field(self):
        from roustabout.permissions import list_capabilities

        session = _make_session(PermissionTier.OBSERVE)
        caps = list_capabilities(session)
        for cap in caps:
            assert "friction" in cap

    def test_all_available_at_every_tier(self):
        from roustabout.permissions import list_capabilities

        for tier in PermissionTier:
            session = _make_session(tier)
            caps = list_capabilities(session)
            assert all(c["available"] is True for c in caps)

    def test_friction_varies_by_tier(self):
        from roustabout.permissions import list_capabilities

        observe = _make_session(PermissionTier.OBSERVE)
        operate = _make_session(PermissionTier.OPERATE)
        obs_caps = {c["action"]: c for c in list_capabilities(observe)}
        op_caps = {c["action"]: c for c in list_capabilities(operate)}
        # restart: DIRECTED at observe, DIRECT at operate
        assert obs_caps["restart"]["friction"] == "directed"
        assert op_caps["restart"]["friction"] == "direct"


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
