"""Tests for the operator gateway — gate sequence and structured results.

Covers E2 S2.2.1: gateway skeleton, gate ordering, structured errors.
Covers friction model: DIRECTED, STAGE, CONFIRM routing.
All Docker operations are mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from roustabout.gateway import (
    BlastRadiusExceeded,
    CircuitOpen,
    ConcurrentMutation,
    ConfirmationRequest,
    GatewayResult,
    MutationCommand,
    TargetNotFound,
    _build_suggested_command,
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
    def test_observe_session_gets_directed_friction(self):
        """Observe session gets DIRECTED friction — returns suggested command."""
        session = _make_session(PermissionTier.OBSERVE)
        cmd = _make_command(action="restart")

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        assert result.success is True
        assert result.result == "directed"
        assert result.friction == "directed"
        assert result.suggested_command == "docker restart nginx"

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


# MutationCommand new fields


class TestMutationCommandNewFields:
    def test_exec_command_field(self):
        cmd = MutationCommand(
            action="exec", target="app", exec_command=("ls", "-la")
        )
        assert cmd.exec_command == ("ls", "-la")

    def test_compose_path_field(self):
        cmd = MutationCommand(
            action="compose-apply", target="mystack", compose_path="/opt/stack/compose.yml"
        )
        assert cmd.compose_path == "/opt/stack/compose.yml"

    def test_new_fields_default_none(self):
        cmd = MutationCommand(action="restart", target="nginx")
        assert cmd.exec_command is None
        assert cmd.compose_path is None


# GatewayResult new fields


class TestGatewayResultNewFields:
    def test_friction_field(self):
        result = GatewayResult(
            success=True, action="restart", target="nginx",
            pre_state_hash="abc", post_state_hash="def",
            result="success", friction="direct",
        )
        assert result.friction == "direct"

    def test_suggested_command_field(self):
        result = GatewayResult(
            success=True, action="restart", target="nginx",
            pre_state_hash="", post_state_hash=None,
            result="directed", friction="directed",
            suggested_command="docker restart nginx",
        )
        assert result.suggested_command == "docker restart nginx"

    def test_confirmation_id_field(self):
        result = GatewayResult(
            success=False, action="update-image", target="nginx",
            pre_state_hash="abc", post_state_hash=None,
            result="pending-confirmation", friction="confirm",
            confirmation_id="some-uuid",
        )
        assert result.confirmation_id == "some-uuid"

    def test_new_fields_default_none(self):
        result = GatewayResult(
            success=True, action="restart", target="nginx",
            pre_state_hash="abc", post_state_hash="def",
            result="success",
        )
        assert result.friction is None
        assert result.suggested_command is None
        assert result.confirmation_id is None


# ConfirmationRequest dataclass


class TestConfirmationRequest:
    def test_fields(self):
        cmd = MutationCommand(action="update-image", target="nginx", new_image="nginx:1.26")
        req = ConfirmationRequest(
            id="test-uuid",
            command=cmd,
            session_id="sess-1",
            semantic_diff="image: nginx:1.25 → nginx:1.26",
            audit_findings=None,
            created_at=1000.0,
            expires_at=1300.0,
            pre_state_hash="abc123",
        )
        assert req.id == "test-uuid"
        assert req.command.action == "update-image"
        assert req.expires_at == 1300.0
        assert req.pre_state_hash == "abc123"

    def test_frozen(self):
        cmd = MutationCommand(action="restart", target="nginx")
        req = ConfirmationRequest(
            id="x", command=cmd, session_id="s",
            semantic_diff=None, audit_findings=None,
            created_at=0.0, expires_at=0.0, pre_state_hash="",
        )
        with pytest.raises(AttributeError):
            req.id = "y"


# Friction routing — DIRECTED


class TestDirectedFriction:
    def test_directed_returns_suggested_command(self):
        """DIRECTED friction returns immediately with suggested_command."""
        session = _make_session(PermissionTier.OBSERVE)
        cmd = _make_command(action="stop")

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        assert result.success is True
        assert result.result == "directed"
        assert result.friction == "directed"
        assert "docker stop nginx" in result.suggested_command

    def test_directed_skips_rate_limit(self):
        """DIRECTED returns before rate limiter — no token consumed."""
        session = _make_session(PermissionTier.OBSERVE)
        initial_tokens = session.rate_limiter._get_bucket("nginx").tokens
        cmd = _make_command(action="restart")

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        assert result.result == "directed"
        final_tokens = session.rate_limiter._get_bucket("nginx").tokens
        assert final_tokens == initial_tokens

    def test_directed_exec_command(self):
        """DIRECTED for exec includes the exec command."""
        session = _make_session(PermissionTier.OBSERVE)
        cmd = _make_command(
            action="exec", target="app",
            exec_command=("ls", "-la"),
        )

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        assert result.result == "directed"
        assert "docker exec app ls -la" in result.suggested_command


# Friction routing — STAGE


class TestStageFriction:
    def test_stage_returns_staged_result(self):
        """STAGE friction delegates to staging handler."""
        # OBSERVE + file-write = DIRECTED, OPERATE + file-write = STAGE
        session = _make_session(PermissionTier.OPERATE)
        cmd = _make_command(action="file-write", target="app")

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        assert result.result == "staged"
        assert result.friction == "stage"

    def test_stage_skips_rate_limit(self):
        """STAGE returns before rate limiter."""
        session = _make_session(PermissionTier.OPERATE)
        initial_tokens = session.rate_limiter._get_bucket("app").tokens
        cmd = _make_command(action="file-write", target="app")

        with patch("roustabout.gateway._inspect_target", return_value=None):
            with patch("roustabout.gateway._compute_target_hash", return_value=None):
                with patch("roustabout.gateway.lockdown.check"):
                    execute(cmd, session=session, db=None)

        final_tokens = session.rate_limiter._get_bucket("app").tokens
        assert final_tokens == initial_tokens


# Friction routing — CONFIRM


class TestConfirmFriction:
    def test_confirm_returns_pending(self):
        """CONFIRM friction creates confirmation, returns pending."""
        # OPERATE + update-image = CONFIRM
        session = _make_session(PermissionTier.OPERATE)
        cmd = _make_command(action="update-image", target="nginx", new_image="nginx:1.26")

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway._compute_target_hash", return_value="hash123"):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        assert result.success is False
        assert result.result == "pending-confirmation"
        assert result.friction == "confirm"
        assert result.confirmation_id is not None

    def test_confirm_skipped_at_elevate(self):
        """ELEVATE + update-image = DIRECT — no confirmation needed."""
        from roustabout.mutations import MutationResult

        session = _make_session(PermissionTier.ELEVATE)
        cmd = _make_command(action="update-image", target="nginx", new_image="nginx:1.26")

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        mock_mutation = MutationResult(
            success=True, action="update-image", target="nginx",
        )

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway._compute_target_hash", return_value="hash"):
                with patch("roustabout.gateway.lockdown.check"):
                    with patch("roustabout.mutations.execute", return_value=mock_mutation):
                        result = execute(cmd, session=session, db=None)

        assert result.success is True
        assert result.result == "success"
        assert result.friction == "direct"


# _build_suggested_command


class TestBuildSuggestedCommand:
    def test_start(self):
        cmd = MutationCommand(action="start", target="nginx")
        assert _build_suggested_command(cmd) == "docker start nginx"

    def test_stop(self):
        cmd = MutationCommand(action="stop", target="nginx")
        assert _build_suggested_command(cmd) == "docker stop nginx"

    def test_restart(self):
        cmd = MutationCommand(action="restart", target="app")
        assert _build_suggested_command(cmd) == "docker restart app"

    def test_recreate(self):
        cmd = MutationCommand(action="recreate", target="app")
        assert _build_suggested_command(cmd) == "docker compose up -d app"

    def test_exec(self):
        cmd = MutationCommand(action="exec", target="app", exec_command=("bash",))
        assert _build_suggested_command(cmd) == "docker exec app bash"

    def test_exec_multi_args(self):
        cmd = MutationCommand(
            action="exec", target="db",
            exec_command=("pg_dump", "-U", "postgres"),
        )
        assert _build_suggested_command(cmd) == "docker exec db pg_dump -U postgres"

    def test_compose_apply(self):
        cmd = MutationCommand(
            action="compose-apply", target="mystack",
            compose_path="/opt/stacks/compose.yml",
        )
        assert _build_suggested_command(cmd) == "docker compose -f /opt/stacks/compose.yml up -d"

    def test_unknown_action(self):
        cmd = MutationCommand(action="custom-thing", target="app")
        result = _build_suggested_command(cmd)
        assert "Manual action required" in result
        assert "custom-thing" in result


# Friction field populated in results


class TestFrictionInResult:
    def test_success_includes_friction(self):
        """Successful mutation has friction field populated."""
        from roustabout.mutations import MutationResult

        session = _make_session(PermissionTier.OPERATE)
        cmd = _make_command(action="restart")

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        mock_mutation = MutationResult(
            success=True, action="restart", target="nginx",
        )

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway.lockdown.check"):
                with patch("roustabout.gateway._compute_target_hash", return_value="hash"):
                    with patch("roustabout.mutations.execute", return_value=mock_mutation):
                        result = execute(cmd, session=session, db=None)

        assert result.friction == "direct"

    def test_dry_run_includes_friction(self):
        """Dry-run result has friction field populated."""
        session = _make_session(PermissionTier.OPERATE)
        cmd = _make_command(action="restart", dry_run=True)

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway.lockdown.check"):
                with patch("roustabout.gateway._compute_target_hash", return_value="hash"):
                    result = execute(cmd, session=session, db=None)

        assert result.result == "dry-run"
        assert result.friction == "direct"


# Pre-mutation backup (stub)


class TestPreMutationBackup:
    def test_no_backup_configured_proceeds(self):
        """When no pre-mutation backup is configured, mutation proceeds."""
        from roustabout.mutations import MutationResult

        session = _make_session()
        cmd = _make_command(action="restart")

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "nginx"

        mock_mutation = MutationResult(
            success=True, action="restart", target="nginx",
        )

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway.lockdown.check"):
                with patch("roustabout.gateway._compute_target_hash", return_value="hash"):
                    with patch("roustabout.mutations.execute", return_value=mock_mutation):
                        result = execute(cmd, session=session, db=None)

        assert result.success is True
        assert result.result == "success"


# Compose apply gateway routing


class TestComposeApplyRouting:
    def test_compose_apply_routes_to_compose_gitops(self):
        """compose-apply action routes to apply_compose, not mutations."""
        from roustabout.compose_gitops import ComposeApplyResult

        session = _make_session(PermissionTier.ELEVATE)
        cmd = _make_command(
            action="compose-apply", target="mystack",
            compose_path="/opt/stacks/compose.yml",
        )

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "mystack"

        mock_apply = ComposeApplyResult(
            success=True,
            compose_path="/opt/stacks/compose.yml",
            services_affected=("web", "db"),
            output="done\n",
        )

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway._compute_target_hash", return_value="h"):
                with patch("roustabout.gateway.lockdown.check"):
                    with patch(
                        "roustabout.compose_gitops.apply_compose",
                        return_value=mock_apply,
                    ):
                        result = execute(cmd, session=session, db=None)

        assert result.success is True
        assert result.result == "success"
        assert result.friction == "direct"

    def test_compose_apply_dry_run(self):
        """compose-apply dry-run returns without executing."""
        session = _make_session(PermissionTier.ELEVATE)
        cmd = _make_command(
            action="compose-apply", target="mystack",
            compose_path="/opt/stacks/compose.yml",
            dry_run=True,
        )

        mock_info = MagicMock()
        mock_info.image = "nginx:latest"
        mock_info.name = "mystack"

        with patch("roustabout.gateway._inspect_target", return_value=mock_info):
            with patch("roustabout.gateway._compute_target_hash", return_value="h"):
                with patch("roustabout.gateway.lockdown.check"):
                    result = execute(cmd, session=session, db=None)

        assert result.success is True
        assert result.result == "dry-run"
