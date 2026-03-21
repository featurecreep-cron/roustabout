"""Tests for session — per-connection isolation, rate limiting, and Docker lifecycle.

Covers S1.2.1 (session management) and S1.2.2 (rate limiting).
"""

from __future__ import annotations

import ast
import threading
from contextvars import copy_context
from pathlib import Path
from time import monotonic
from unittest.mock import MagicMock, patch

import pytest

from roustabout import session

# S1.2.1: Session lifecycle


class TestPermissionTier:
    """PermissionTier ordering and comparison."""

    def test_observe_lt_operate(self) -> None:
        assert session.PermissionTier.OBSERVE < session.PermissionTier.OPERATE

    def test_operate_lt_elevate(self) -> None:
        assert session.PermissionTier.OPERATE < session.PermissionTier.ELEVATE

    def test_observe_lt_elevate(self) -> None:
        assert session.PermissionTier.OBSERVE < session.PermissionTier.ELEVATE

    def test_equality(self) -> None:
        assert session.PermissionTier.OBSERVE == session.PermissionTier.OBSERVE

    def test_hash(self) -> None:
        s = {session.PermissionTier.OBSERVE, session.PermissionTier.OBSERVE}
        assert len(s) == 1


class TestCapabilities:
    """Each tier has correct capabilities."""

    def test_observe_capabilities(self) -> None:
        caps = session.capabilities_for_tier(session.PermissionTier.OBSERVE)
        assert "can_snapshot" in caps
        assert "can_audit" in caps
        assert "can_dr_plan" in caps
        assert "can_start" not in caps

    def test_operate_superset_of_observe(self) -> None:
        obs = session.capabilities_for_tier(session.PermissionTier.OBSERVE)
        ops = session.capabilities_for_tier(session.PermissionTier.OPERATE)
        assert obs < ops

    def test_elevate_superset_of_operate(self) -> None:
        ops = session.capabilities_for_tier(session.PermissionTier.OPERATE)
        elv = session.capabilities_for_tier(session.PermissionTier.ELEVATE)
        assert ops < elv

    def test_operate_has_mutation_caps(self) -> None:
        caps = session.capabilities_for_tier(session.PermissionTier.OPERATE)
        assert "can_start" in caps
        assert "can_stop" in caps
        assert "can_restart" in caps
        assert "can_recreate" in caps


class TestCreateSession:
    """Session creation and Docker client lifecycle."""

    @patch("roustabout.session.connection.connect")
    def test_creates_session_with_uuid(self, mock_connect: MagicMock) -> None:
        mock_client = MagicMock()
        mock_connect.return_value = mock_client

        s = session.create_session()
        assert s.id
        assert s.tier == session.PermissionTier.OBSERVE
        assert s.docker.client is mock_client
        session.destroy_session(s)

    @patch("roustabout.session.connection.connect")
    def test_custom_tier(self, mock_connect: MagicMock) -> None:
        mock_connect.return_value = MagicMock()
        s = session.create_session(tier=session.PermissionTier.OPERATE)
        assert s.tier == session.PermissionTier.OPERATE
        assert "can_start" in s.capabilities
        session.destroy_session(s)

    @patch("roustabout.session.connection.connect")
    def test_custom_session_id(self, mock_connect: MagicMock) -> None:
        mock_connect.return_value = MagicMock()
        s = session.create_session(session_id="my-session")
        assert s.id == "my-session"
        session.destroy_session(s)

    @patch("roustabout.session.connection.connect")
    def test_docker_host_forwarded(self, mock_connect: MagicMock) -> None:
        mock_connect.return_value = MagicMock()
        s = session.create_session(docker_host="tcp://host:2375")
        mock_connect.assert_called_with("tcp://host:2375")
        assert s.docker.host == "tcp://host:2375"
        session.destroy_session(s)


class TestDestroySession:
    """Session teardown."""

    @patch("roustabout.session.connection.connect")
    def test_closes_client(self, mock_connect: MagicMock) -> None:
        mock_client = MagicMock()
        mock_connect.return_value = mock_client
        s = session.create_session()
        session.destroy_session(s)
        mock_client.close.assert_called_once()

    @patch("roustabout.session.connection.connect")
    def test_idempotent(self, mock_connect: MagicMock) -> None:
        mock_client = MagicMock()
        mock_connect.return_value = mock_client
        s = session.create_session()
        session.destroy_session(s)
        session.destroy_session(s)  # Should not raise


class TestElevateSession:
    """Tier elevation returns new session sharing Docker/rate state."""

    @patch("roustabout.session.connection.connect")
    def test_new_tier_and_capabilities(self, mock_connect: MagicMock) -> None:
        mock_connect.return_value = MagicMock()
        s = session.create_session(tier=session.PermissionTier.OBSERVE)
        elevated = session.elevate_session(s, session.PermissionTier.OPERATE)
        assert elevated.tier == session.PermissionTier.OPERATE
        assert "can_start" in elevated.capabilities
        session.destroy_session(s)

    @patch("roustabout.session.connection.connect")
    def test_shares_docker_session(self, mock_connect: MagicMock) -> None:
        mock_connect.return_value = MagicMock()
        s = session.create_session(tier=session.PermissionTier.OBSERVE)
        elevated = session.elevate_session(s, session.PermissionTier.OPERATE)
        assert elevated.docker is s.docker
        session.destroy_session(s)

    @patch("roustabout.session.connection.connect")
    def test_shares_rate_limiter(self, mock_connect: MagicMock) -> None:
        mock_connect.return_value = MagicMock()
        s = session.create_session(tier=session.PermissionTier.OBSERVE)
        elevated = session.elevate_session(s, session.PermissionTier.OPERATE)
        assert elevated.rate_limiter is s.rate_limiter
        session.destroy_session(s)


class TestContextVar:
    """ContextVar isolation between sessions."""

    @patch("roustabout.session.connection.connect")
    def test_get_current_session(self, mock_connect: MagicMock) -> None:
        mock_connect.return_value = MagicMock()
        s = session.create_session()
        with session.session_context(s):
            assert session.get_current_session() is s
        session.destroy_session(s)

    def test_no_session_raises(self) -> None:
        with pytest.raises(session.NoSessionError):
            session.get_current_session()

    @patch("roustabout.session.connection.connect")
    def test_context_cleanup_on_exit(self, mock_connect: MagicMock) -> None:
        mock_connect.return_value = MagicMock()
        s = session.create_session()
        with session.session_context(s):
            pass
        with pytest.raises(session.NoSessionError):
            session.get_current_session()
        session.destroy_session(s)

    @patch("roustabout.session.connection.connect")
    def test_isolation_between_sessions(self, mock_connect: MagicMock) -> None:
        mock_connect.return_value = MagicMock()
        s1 = session.create_session(session_id="s1", tier=session.PermissionTier.OBSERVE)
        s2 = session.create_session(session_id="s2", tier=session.PermissionTier.OPERATE)

        results: dict[str, str] = {}

        def run_in_context(s: session.Session, key: str) -> None:
            with session.session_context(s):
                results[key] = session.get_current_session().id

        ctx1 = copy_context()
        ctx2 = copy_context()
        t1 = threading.Thread(target=ctx1.run, args=(run_in_context, s1, "t1"))
        t2 = threading.Thread(target=ctx2.run, args=(run_in_context, s2, "t2"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert results["t1"] == "s1"
        assert results["t2"] == "s2"
        session.destroy_session(s1)
        session.destroy_session(s2)


# S1.2.2: Rate limiting


class TestRateLimiter:
    """Per-container, per-session rate limiting."""

    def test_reserve_and_commit(self) -> None:
        rl = session.RateLimiter(max_tokens=3, window_seconds=300)
        reservation = rl.reserve("nginx")
        rl.commit(reservation)

    def test_reserve_and_release(self) -> None:
        rl = session.RateLimiter(max_tokens=1, window_seconds=300)
        reservation = rl.reserve("nginx")
        rl.release(reservation)
        # Should be able to reserve again after release
        reservation2 = rl.reserve("nginx")
        rl.commit(reservation2)

    def test_exhaustion_raises(self) -> None:
        rl = session.RateLimiter(max_tokens=2, window_seconds=300)
        r1 = rl.reserve("nginx")
        rl.commit(r1)
        r2 = rl.reserve("nginx")
        rl.commit(r2)
        with pytest.raises(session.RateLimitExceeded) as exc_info:
            rl.reserve("nginx")
        assert exc_info.value.target == "nginx"
        assert exc_info.value.retry_after > 0

    def test_per_container_isolation(self) -> None:
        rl = session.RateLimiter(max_tokens=1, window_seconds=300)
        r1 = rl.reserve("nginx")
        rl.commit(r1)
        # Different container should still have tokens
        r2 = rl.reserve("redis")
        rl.commit(r2)

    def test_global_limit(self) -> None:
        rl = session.RateLimiter(max_tokens=3, window_seconds=300, global_max_tokens=2)
        r1 = rl.reserve("c1")
        rl.commit(r1)
        r2 = rl.reserve("c2")
        rl.commit(r2)
        # Global limit hit even though c3 has per-container tokens
        with pytest.raises(session.RateLimitExceeded):
            rl.reserve("c3")

    def test_refill_after_window(self) -> None:
        rl = session.RateLimiter(max_tokens=1, window_seconds=1)
        r1 = rl.reserve("nginx")
        rl.commit(r1)

        # Simulate time passing by adjusting the bucket's last_refill
        bucket = rl._buckets["nginx"]
        bucket.last_refill = monotonic() - 2  # 2 seconds ago
        if "_global" in rl._buckets:
            rl._buckets["_global"].last_refill = monotonic() - 2

        # Should be able to reserve again
        r2 = rl.reserve("nginx")
        rl.commit(r2)

    def test_retry_after_in_error(self) -> None:
        rl = session.RateLimiter(max_tokens=1, window_seconds=300)
        r1 = rl.reserve("nginx")
        rl.commit(r1)
        with pytest.raises(session.RateLimitExceeded) as exc_info:
            rl.reserve("nginx")
        # retry_after should be positive and <= window_seconds
        assert 0 < exc_info.value.retry_after <= 300


# Lint test: only connection.py calls docker.DockerClient


class TestArchitecturalLint:
    """S1.2.1 T6: Only connection.py creates Docker clients."""

    def test_only_connection_creates_docker_client(self) -> None:
        src_dir = Path(__file__).parent.parent / "src" / "roustabout"
        violations = []
        for py_file in src_dir.glob("*.py"):
            if py_file.name == "connection.py":
                continue
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    # Check for docker.DockerClient() or docker.from_env()
                    if isinstance(func, ast.Attribute):
                        if isinstance(func.value, ast.Name) and func.value.id == "docker":
                            if func.attr in ("DockerClient", "from_env"):
                                violations.append(f"{py_file.name}: docker.{func.attr}()")
        assert violations == [], f"Docker client created outside connection.py: {violations}"
