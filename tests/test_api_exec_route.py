"""Tests for POST /v1/containers/{name}/exec — who may exec, and how.

Covers LLD-025 friction model at the API boundary: OBSERVE is refused unless
the key carries an exec grant for the container, and so is OPERATE. A granted
key is limited to the container's allowlist. ELEVATE uses the denylist unless
the container has an allowlist.

The Docker client is mocked; the allowlist and denylist checks are real.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from roustabout.api.app import create_app
from roustabout.api.auth import AuthConfig
from roustabout.exec import ExecConfig, ExecConfigError

AIRFLOW = ExecConfig(allowed=("airflow dags trigger *",), user="airflow")
TRIGGER = ["airflow", "dags", "trigger", "my_dag"]


@pytest.fixture
def docker_client():
    container = MagicMock()
    container.status = "running"
    container.exec_run.return_value = (0, (b"triggered", b""))
    client = MagicMock()
    client.containers.get.return_value = container
    return client


@pytest.fixture
def client(docker_client):
    from fastapi.testclient import TestClient

    auth = AuthConfig(
        keys={
            "sk-observe": {"tier": "observe", "label": "observe"},
            "sk-granted": {"tier": "observe", "label": "dag-trigger", "exec": ["airflow"]},
            "sk-operate": {"tier": "operate", "label": "operate"},
            "sk-elevate": {"tier": "elevate", "label": "elevate"},
        }
    )
    with (
        patch("roustabout.connection.connect", return_value=docker_client),
        patch("roustabout.api.routes._load_cfg_simple", return_value=None),
    ):
        yield TestClient(create_app(auth_config=auth))


def _exec(client, key, container="airflow", command=TRIGGER, config=AIRFLOW, **body):
    """POST an exec request with the container's exec config set to `config`.

    `config` may be an exception instance, raised when the config is loaded.
    """
    side_effect = config if isinstance(config, Exception) else None
    return_value = None if side_effect else config
    with patch(
        "roustabout.exec.load_exec_config", return_value=return_value, side_effect=side_effect
    ):
        return client.post(
            f"/v1/containers/{container}/exec",
            json={"command": command, **body},
            headers={"Authorization": f"Bearer {key}"},
        )


def _ran(docker_client):
    return docker_client.containers.get.return_value.exec_run


class TestObserve:
    def test_without_grant_is_forbidden(self, client, docker_client):
        response = _exec(client, "sk-observe")
        assert response.status_code == 403
        _ran(docker_client).assert_not_called()

    def test_grant_runs_an_allowlisted_command(self, client, docker_client):
        response = _exec(client, "sk-granted")
        assert response.status_code == 200
        assert response.json()["success"] is True
        assert response.json()["stdout"] == "triggered"
        assert _ran(docker_client).call_args.kwargs["cmd"] == TRIGGER

    def test_grant_runs_as_the_configured_user(self, client, docker_client):
        _exec(client, "sk-granted")
        assert _ran(docker_client).call_args.kwargs["user"] == "airflow"

    def test_grant_does_not_run_other_commands(self, client, docker_client):
        response = _exec(client, "sk-granted", command=["airflow", "db", "reset", "-y"])
        assert response.json()["denied"] is True
        _ran(docker_client).assert_not_called()

    def test_grant_does_not_reach_other_containers(self, client, docker_client):
        response = _exec(client, "sk-granted", container="postgres")
        assert response.status_code == 403
        _ran(docker_client).assert_not_called()

    def test_grant_on_container_without_allowlist_runs_nothing(self, client, docker_client):
        """The grant must not fall through to denylist mode."""
        response = _exec(client, "sk-granted", command=["ls"], config=None)
        assert response.json()["denied"] is True
        _ran(docker_client).assert_not_called()

    @pytest.mark.parametrize("override", [{"user": "root"}, {"workdir": "/"}])
    def test_grant_cannot_choose_user_or_workdir(self, client, docker_client, override):
        response = _exec(client, "sk-granted", **override)
        assert response.json()["denied"] is True
        _ran(docker_client).assert_not_called()


class TestOperate:
    def test_allowlist_alone_grants_nothing(self, client, docker_client):
        response = _exec(client, "sk-operate")
        assert response.status_code == 403
        _ran(docker_client).assert_not_called()


class TestExactMatching:
    EXACT = ExecConfig(allowed=("airflow dags trigger my_dag",))

    def test_exact_entry_runs(self, client, docker_client):
        response = _exec(client, "sk-granted", config=self.EXACT)
        assert response.json()["success"] is True

    def test_exact_entry_refuses_extra_arguments(self, client, docker_client):
        response = _exec(
            client, "sk-granted", command=[*TRIGGER, "--conf", "{}"], config=self.EXACT
        )
        assert response.json()["denied"] is True
        _ran(docker_client).assert_not_called()


class TestElevate:
    def test_denylist_mode_without_allowlist(self, client, docker_client):
        response = _exec(client, "sk-elevate", command=["ls", "/"], config=None)
        assert response.json()["success"] is True

    def test_denylist_still_blocks_shells(self, client, docker_client):
        response = _exec(client, "sk-elevate", command=["bash", "-c", "id"], config=None)
        assert response.json()["denied"] is True
        _ran(docker_client).assert_not_called()

    def test_bound_by_a_configured_allowlist(self, client, docker_client):
        response = _exec(client, "sk-elevate", command=["ls", "/"])
        assert response.json()["denied"] is True
        _ran(docker_client).assert_not_called()

    def test_may_choose_user(self, client, docker_client):
        _exec(client, "sk-elevate", user="root")
        assert _ran(docker_client).call_args.kwargs["user"] == "root"


class TestDeniedBeforeDocker:
    @pytest.mark.parametrize("key", ["sk-granted", "sk-elevate"])
    def test_denied_command_never_opens_a_docker_connection(self, client, key):
        with patch("roustabout.connection.connect") as connect:
            response = _exec(client, key, command=["ls", "/"])
        assert response.json()["denied"] is True
        connect.assert_not_called()


class TestConfigFailure:
    @pytest.mark.parametrize("key", ["sk-granted", "sk-elevate"])
    def test_unreadable_config_refuses_exec(self, client, docker_client, key):
        """An unreadable config must never widen to denylist mode."""
        response = _exec(client, key, command=["ls", "/"], config=ExecConfigError("bad toml"))
        assert response.status_code == 500
        _ran(docker_client).assert_not_called()


class TestLockdown:
    @pytest.mark.parametrize("key", ["sk-granted", "sk-elevate"])
    def test_lockdown_blocks_exec(self, client, docker_client, key):
        from roustabout.lockdown import LockdownError, LockdownStatus

        locked = LockdownError(LockdownStatus(locked=True, reason="incident", path="/x"))
        with patch("roustabout.lockdown.check", side_effect=locked):
            response = _exec(client, key)
        assert response.status_code == 503
        _ran(docker_client).assert_not_called()


class TestAuditLog:
    def test_executed_command_is_logged(self, client, caplog):
        with caplog.at_level(logging.INFO, logger="roustabout.audit"):
            _exec(client, "sk-granted")
        line = next(r.getMessage() for r in caplog.records if "exec " in r.getMessage())
        assert "key=dag-trigger" in line
        assert "target=airflow" in line
        assert "airflow dags trigger my_dag" in line
        assert "outcome=ran" in line

    def test_denied_command_is_logged_as_denied(self, client, caplog):
        with caplog.at_level(logging.INFO, logger="roustabout.audit"):
            _exec(client, "sk-granted", command=["airflow", "db", "reset"])
        line = next(r.getMessage() for r in caplog.records if "exec " in r.getMessage())
        assert "airflow db reset" in line
        assert "outcome=denied" in line

    def test_forbidden_request_is_logged(self, client, caplog):
        with caplog.at_level(logging.INFO, logger="roustabout.audit"):
            _exec(client, "sk-observe")
        line = next(r.getMessage() for r in caplog.records if "exec " in r.getMessage())
        assert "outcome=forbidden" in line


class TestRateLimit:
    """Exec is rate limited per container, from a budget separate to mutations."""

    @pytest.fixture
    def limiter(self, monkeypatch):
        from roustabout.api import routes
        from roustabout.session import RateLimiter

        limiter = RateLimiter(max_tokens=2, window_seconds=300.0, global_max_tokens=3)
        monkeypatch.setattr(routes, "_exec_rate_limiter", limiter)
        return limiter

    def test_exec_beyond_the_limit_is_refused(self, client, docker_client, limiter):
        assert _exec(client, "sk-granted").status_code == 200
        assert _exec(client, "sk-granted").status_code == 200
        response = _exec(client, "sk-granted")
        assert response.status_code == 429
        assert int(response.headers["Retry-After"]) > 0
        assert _ran(docker_client).call_count == 2

    def test_limit_applies_to_elevate_keys_too(self, client, docker_client, limiter):
        for _ in range(2):
            _exec(client, "sk-elevate", command=["ls"], config=None)
        assert _exec(client, "sk-elevate", command=["ls"], config=None).status_code == 429

    def test_limit_is_per_container(self, client, docker_client, limiter):
        for _ in range(2):
            _exec(client, "sk-elevate", command=["ls"], config=None)
        other = _exec(client, "sk-elevate", container="nginx", command=["ls"], config=None)
        assert other.status_code == 200

    def test_global_limit_spans_containers(self, client, docker_client, limiter):
        for name in ("a", "b", "c"):
            assert (
                _exec(
                    client, "sk-elevate", container=name, command=["ls"], config=None
                ).status_code
                == 200
            )
        assert (
            _exec(client, "sk-elevate", container="d", command=["ls"], config=None).status_code
            == 429
        )

    def test_denied_commands_do_not_spend_the_budget(self, client, docker_client, limiter):
        for _ in range(5):
            assert _exec(client, "sk-granted", command=["ls", "/"]).json()["denied"] is True
        assert _exec(client, "sk-granted").status_code == 200

    def test_forbidden_requests_do_not_spend_the_budget(self, client, docker_client, limiter):
        for _ in range(5):
            assert _exec(client, "sk-observe").status_code == 403
        assert _exec(client, "sk-granted").status_code == 200

    def test_docker_failure_returns_the_token(self, client, docker_client, limiter):
        """A command that never ran should not count against the limit."""
        with patch("roustabout.connection.connect", side_effect=ConnectionError("no daemon")):
            for _ in range(5):
                with pytest.raises(ConnectionError):
                    _exec(client, "sk-granted")
        assert _exec(client, "sk-granted").status_code == 200

    def test_exec_does_not_spend_the_mutation_budget(
        self, client, docker_client, limiter, monkeypatch
    ):
        """Otherwise a granted key could block an operator's restart."""
        from roustabout.api import routes
        from roustabout.session import RateLimiter

        mutations = RateLimiter(max_tokens=1, window_seconds=300.0, global_max_tokens=1)
        monkeypatch.setattr(routes, "_rate_limiter", mutations)
        _exec(client, "sk-granted")
        mutations.reserve("airflow")  # raises RateLimitExceeded if exec spent it

    def test_rate_limited_request_is_logged(self, client, limiter, caplog):
        for _ in range(2):
            _exec(client, "sk-granted")
        with caplog.at_level(logging.INFO, logger="roustabout.audit"):
            _exec(client, "sk-granted")
        assert any("outcome=rate-limited" in r.getMessage() for r in caplog.records)

    def test_no_limiter_means_no_limit(self, client, docker_client):
        for _ in range(5):
            assert _exec(client, "sk-granted").status_code == 200


class TestServerWiring:
    def test_server_installs_separate_exec_and_mutation_limiters(self, monkeypatch):
        from roustabout.api import routes, server

        monkeypatch.setattr(routes, "_rate_limiter", None)
        monkeypatch.setattr(routes, "_exec_rate_limiter", None)
        with patch("uvicorn.run"), patch("roustabout.config.load_config") as load:
            from roustabout.config import Config

            load.return_value = Config(rate_limit_per_container=7, rate_limit_global=9)
            server.main()
        assert routes._exec_rate_limiter is not None
        assert routes._exec_rate_limiter is not routes._rate_limiter
        assert routes._exec_rate_limiter.max_tokens == 7
        assert routes._exec_rate_limiter.global_max_tokens == 9
