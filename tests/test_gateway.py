"""Tests for the operator gateway — gate sequence and structured results.

Covers E2 S2.2.1: gateway skeleton, gate ordering, structured errors.
All Docker operations are mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from roustabout.gateway import (
    BlastRadiusExceeded,
    CircuitOpen,
    ConcurrentMutation,
    GatewayResult,
    MutationCommand,
    TargetNotFound,
    execute,
)
from roustabout.session import (
    DockerSession,
    PermissionTier,
    RateLimiter,
    Session,
    capabilities_for_tier,
)

# Helpers


def _make_session(tier: PermissionTier = PermissionTier.OPERATE) -> Session:
    docker = DockerSession(client=MagicMock(), host="localhost")
    return Session(
        id="test-session",
        docker=docker,
        tier=tier,
        capabilities=capabilities_for_tier(tier),
        rate_limiter=RateLimiter(),
        created_at="2026-03-17T00:00:00Z",
    )


def _make_command(**kwargs) -> MutationCommand:
    defaults = {"action": "restart", "target": "nginx", "host": "localhost"}
    defaults.update(kwargs)
    return MutationCommand(**defaults)


def _mock_gates(**overrides):
    """Context manager stack for common gate mocks.

    Defaults: _inspect_target returns None, lockdown passes,
    _compute_target_hash returns None.
    """
    from contextlib import ExitStack

    stack = ExitStack()
    defaults = {
        "_inspect_target": None,
        "lockdown.check": None,
        "_compute_target_hash": None,
    }
    defaults.update(overrides)

    patches = {}
    for key, value in defaults.items():
        target = f"roustabout.gateway.{key}"
        if value is None and key != "_inspect_target" and key != "_compute_target_hash":
            patches[key] = stack.enter_context(patch(target))
        else:
            patches[key] = stack.enter_context(patch(target, return_value=value))
    return stack


# MutationCommand dataclass


class TestMutationCommand:
    def test_frozen(self):
        cmd = _make_command()
        with pytest.raises(AttributeError):
            cmd.action = "stop"

    def test_defaults(self):
        cmd = MutationCommand(action="start", target="app")
        assert cmd.host == "localhost"
        assert cmd.dry_run is False
        assert cmd.new_image is None


# GatewayResult dataclass


class TestGatewayResult:
    def test_success_result(self):
        result = GatewayResult(
            success=True,
            action="restart",
            target="nginx",
            pre_state_hash="abc",
            post_state_hash="def",
            result="success",
        )
        assert result.success is True
        assert result.gate_failed is None

    def test_denial_result(self):
        result = GatewayResult(
            success=False,
            action="restart",
            target="nginx",
            pre_state_hash="",
            post_state_hash=None,
            result="denied",
            error="locked",
            gate_failed="LockdownError",
        )
        assert result.success is False
        assert result.gate_failed == "LockdownError"


# Gate exception types


class TestGateExceptions:
    def test_circuit_open(self):
        exc = CircuitOpen(target="nginx", consecutive_failures=3)
        assert "nginx" in str(exc)
        assert "3" in str(exc)

    def test_blast_radius_exceeded(self):
        exc = BlastRadiusExceeded(affected_count=10, threshold=5)
        assert "10" in str(exc)
        assert "5" in str(exc)

    def test_target_not_found(self):
        exc = TargetNotFound(target="ghost")
        assert "ghost" in str(exc)

    def test_concurrent_mutation(self):
        exc = ConcurrentMutation(target="nginx", expected_hash="aaa", actual_hash="bbb")
        assert "TOCTOU" in str(exc)


# Action validation


class TestActionValidation:
    def test_read_action_rejected(self):
        session = _make_session()
        cmd = _make_command(action="snapshot")
        with pytest.raises(ValueError, match="read action"):
            execute(cmd, session=session, db=None)

    def test_mutation_action_accepted(self):
        """Mutation actions pass validation (may fail at later gate)."""
        session = _make_session()
        cmd = _make_command(action="restart")
        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)
        # Fails at TargetNotFound, NOT at action validation
        assert result.gate_failed == "TargetNotFound"


# Gate sequence — lockdown


class TestLockdownGate:
    def test_lockdown_blocks_mutation(self):
        from roustabout.lockdown import LockdownError, LockdownStatus

        session = _make_session()
        cmd = _make_command()

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch(
                    "roustabout.gateway.lockdown.check",
                    side_effect=LockdownError(
                        LockdownStatus(
                            locked=True,
                            reason="emergency",
                            path="/etc/roustabout/lockdown",
                        )
                    ),
                ):
                    result = execute(cmd, session=session, db=None)

        assert result.success is False
        assert result.gate_failed == "LockdownError"
        assert result.result == "denied"


# Gate sequence — permission


class TestPermissionGate:
    def test_observe_session_passes_permission_with_directed_friction(self):
        """Observe session passes permission gate with DIRECTED friction.

        In the friction model, OBSERVE tier gets DIRECTED friction for
        mutations instead of PermissionDenied. The gateway proceeds past
        step 2 — friction routing will be handled in a later step.
        """
        session = _make_session(PermissionTier.OBSERVE)
        cmd = _make_command(action="restart")

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        # Fails at TargetNotFound (step 0a), NOT at permission gate
        assert result.success is False
        assert result.gate_failed == "TargetNotFound"

    def test_operate_session_allowed_mutation(self):
        """Operate session passes permission gate (may fail later)."""
        session = _make_session(PermissionTier.OPERATE)
        cmd = _make_command(action="restart")

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        # Fails at TargetNotFound, NOT at permission gate
        assert result.gate_failed == "TargetNotFound"


# Gate sequence — target not found


class TestTargetNotFoundGate:
    def test_nonexistent_container(self):
        session = _make_session()
        cmd = _make_command(target="ghost")

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        assert result.success is False
        assert result.gate_failed == "TargetNotFound"
        assert "ghost" in (result.error or "")


# Gate sequence — TOCTOU


class TestTargetHashCompleteness:
    """TOCTOU hash must cover all security-relevant container fields."""

    def test_hash_includes_required_fields(self):
        """Verify _compute_target_hash reads all fields from security.md."""
        import inspect

        from roustabout.gateway import _compute_target_hash

        source = inspect.getsource(_compute_target_hash)
        required_fields = [
            "Status",
            "Image",
            "Env",
            "Cmd",
            "Entrypoint",
            "User",
            "Labels",
            "NetworkMode",
            "Privileged",
            "CapAdd",
            "CapDrop",
            "PidMode",
            "IpcMode",
            "SecurityOpt",
            "ReadonlyRootfs",
            "Devices",
            "Binds",
            "PortBindings",
        ]
        for field in required_fields:
            assert field in source, (
                f"_compute_target_hash missing field {field!r} — "
                f"required by security.md TOCTOU convention"
            )


class TestTOCTOU:
    def test_concurrent_mutation_detected(self):
        """If container state changes between step 0b and step 7, deny."""
        session = _make_session()
        cmd = _make_command()

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        hash_calls = iter(["hash_before", "hash_after_changed"])

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway.lockdown.check"):
                with patch(
                    "roustabout.gateway._compute_target_hash",
                    side_effect=lambda *a, **kw: next(hash_calls),
                ):
                    result = execute(cmd, session=session, db=None)

        assert result.success is False
        assert result.gate_failed == "ConcurrentMutation"
        assert "TOCTOU" in (result.error or "")

    def test_matching_hashes_pass(self):
        """If hashes match, TOCTOU passes (fails at next gate)."""
        session = _make_session()
        cmd = _make_command(dry_run=True)

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway.lockdown.check"):
                with patch(
                    "roustabout.gateway._compute_target_hash",
                    return_value="same_hash",
                ):
                    result = execute(cmd, session=session, db=None)

        assert result.success is True
        assert result.result == "dry-run"


# Gate sequence — dry run


class TestDryRun:
    def test_dry_run_returns_preview(self):
        session = _make_session()
        cmd = _make_command(dry_run=True)

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway.lockdown.check"):
                with patch(
                    "roustabout.gateway._compute_target_hash",
                    return_value="fakehash",
                ):
                    result = execute(cmd, session=session, db=None)

        assert result.success is True
        assert result.result == "dry-run"
        assert result.pre_state_hash == "fakehash"


# Gate sequence — circuit breaker


class TestCircuitBreakerGate:
    def test_circuit_open_denies(self):
        """Circuit breaker open → denied result."""
        from unittest.mock import MagicMock as MM

        session = _make_session()
        cmd = _make_command()

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        mock_db = MM()
        mock_circuit = MM()
        mock_circuit.open = True
        mock_circuit.consecutive_failures = 5

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch(
                "roustabout.gateway._compute_target_hash",
                return_value="hash",
            ):
                with patch("roustabout.gateway.lockdown.check"):
                    with patch(
                        "roustabout.state_db.check_circuit",
                        return_value=mock_circuit,
                    ):
                        result = execute(
                            cmd,
                            session=session,
                            db=mock_db,
                        )

        assert result.success is False
        assert result.gate_failed == "CircuitOpen"
        assert "5" in (result.error or "")


# Gate sequence — rate limit cleanup


class TestRateLimitExhausted:
    def test_exhausted_rate_limit_returns_denied(self):
        """When rate limit is exhausted, gateway returns denied result."""
        session = _make_session()
        # Exhaust all tokens
        session.rate_limiter._max_tokens = 1
        session.rate_limiter._global_max_tokens = 100
        bucket = session.rate_limiter._get_bucket("nginx")
        bucket.tokens = 0

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        cmd = _make_command(target="nginx")
        with patch("roustabout.gateway.lockdown.check"):
            with patch("roustabout.gateway._inspect_target", return_value=mock_info):
                with patch("roustabout.gateway._compute_target_hash", return_value="hash"):
                    result = execute(cmd, session=session, db=None)

        assert not result.success
        assert result.gate_failed == "RateLimitExceeded"
        assert result.result == "denied"


class TestRateLimitCleanup:
    def test_reservation_released_on_gate_failure(self):
        """If a gate fails after rate limit reservation, token is released."""
        session = _make_session()
        initial_tokens = session.rate_limiter._get_bucket("nginx").tokens
        cmd = _make_command(target="nginx")

        # Fail at target-not-found (after rate limit reserve)
        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        assert result.gate_failed == "TargetNotFound"
        # Token should be released back
        final_tokens = session.rate_limiter._get_bucket("nginx").tokens
        assert final_tokens == initial_tokens


# Full success path (mutation executes)


class TestSuccessPath:
    def test_successful_mutation(self):
        """Full path through all gates to successful mutation."""
        from roustabout.mutations import MutationResult

        session = _make_session()
        cmd = _make_command(action="restart")

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        mock_mutation = MutationResult(
            success=True,
            action="restart",
            target="nginx",
        )

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway.lockdown.check"):
                with patch(
                    "roustabout.gateway._compute_target_hash",
                    return_value="stablehash",
                ):
                    with patch(
                        "roustabout.mutations.execute",
                        return_value=mock_mutation,
                    ):
                        result = execute(cmd, session=session, db=None)

        assert result.success is True
        assert result.result == "success"
        assert result.action == "restart"
        assert result.pre_state_hash == "stablehash"
        assert result.gate_failed is None

    def test_failed_mutation(self):
        """Mutation that executes but fails (e.g. API error)."""
        from roustabout.mutations import MutationResult

        session = _make_session()
        cmd = _make_command(action="stop")

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        mock_mutation = MutationResult(
            success=False,
            action="stop",
            target="nginx",
            error="container already stopped",
        )

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway.lockdown.check"):
                with patch(
                    "roustabout.gateway._compute_target_hash",
                    return_value="stablehash",
                ):
                    with patch(
                        "roustabout.mutations.execute",
                        return_value=mock_mutation,
                    ):
                        result = execute(cmd, session=session, db=None)

        assert result.success is False
        assert result.result == "failed"
        assert result.error == "container already stopped"
