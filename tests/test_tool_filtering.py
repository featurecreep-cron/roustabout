"""Tests for tool filtering — capabilities and operational context.

Covers E9 F9.2: capabilities tool, tier metadata.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from roustabout.session import PermissionTier, capabilities_for_tier

# Capabilities


class TestCapabilities:
    def test_observe_capabilities(self):
        caps = capabilities_for_tier(PermissionTier.OBSERVE)
        assert "can_snapshot" in caps
        assert "can_restart" not in caps
        assert "can_exec" not in caps

    def test_operate_capabilities(self):
        caps = capabilities_for_tier(PermissionTier.OPERATE)
        assert "can_snapshot" in caps
        assert "can_restart" in caps
        assert "can_exec" not in caps

    def test_elevate_capabilities(self):
        caps = capabilities_for_tier(PermissionTier.ELEVATE)
        assert "can_snapshot" in caps
        assert "can_restart" in caps
        assert "can_exec" in caps

    def test_tier_ordering(self):
        assert PermissionTier.OBSERVE < PermissionTier.OPERATE
        assert PermissionTier.OPERATE < PermissionTier.ELEVATE


class TestListCapabilities:
    def test_returns_all_capabilities(self):
        from roustabout.permissions import ACTION_CAPABILITY, list_capabilities
        from roustabout.session import (
            DockerSession,
            RateLimiter,
            Session,
        )

        docker = DockerSession(client=MagicMock(), host="localhost")
        session = Session(
            id="test",
            docker=docker,
            tier=PermissionTier.OBSERVE,
            capabilities=capabilities_for_tier(PermissionTier.OBSERVE),
            rate_limiter=RateLimiter(),
            created_at="",
        )

        caps = list_capabilities(session)
        assert len(caps) == len(ACTION_CAPABILITY)
        # Each has capability, action, friction, available keys
        for c in caps:
            assert "capability" in c
            assert "action" in c
            assert "friction" in c
            assert "available" in c
