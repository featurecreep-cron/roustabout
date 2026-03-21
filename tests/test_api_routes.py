"""Tests for API route handlers.

Uses FastAPI TestClient to verify HTTP behavior end-to-end,
with core logic mocked at the boundary.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from roustabout.api.app import create_app
from roustabout.api.auth import AuthConfig


@pytest.fixture
def auth_config():
    return AuthConfig(
        keys={
            "sk-observe": {"tier": "observe", "label": "test-observe"},
            "sk-operate": {"tier": "operate", "label": "test-operate"},
            "sk-elevate": {"tier": "elevate", "label": "test-elevate"},
        }
    )


@pytest.fixture
def app(auth_config):
    return create_app(auth_config=auth_config)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    return TestClient(app)


def _auth(key="sk-observe"):
    return {"Authorization": f"Bearer {key}"}


class TestAuthMiddleware:
    """Authentication enforcement on all routes."""

    def test_no_auth_header_returns_401(self, client):
        response = client.get("/v1/snapshot")
        assert response.status_code == 401

    def test_invalid_key_returns_401(self, client):
        response = client.get("/v1/snapshot", headers=_auth("sk-wrong"))
        assert response.status_code == 401

    def test_valid_key_passes_auth(self, client):
        with patch("roustabout.api.routes._snapshot") as mock:
            mock.return_value = {"containers": []}
            response = client.get("/v1/snapshot", headers=_auth())
        assert response.status_code == 200

    def test_bearer_prefix_required(self, client):
        response = client.get(
            "/v1/snapshot",
            headers={"Authorization": "sk-observe"},
        )
        assert response.status_code == 401


class TestHealthEndpoint:
    """Health check — no auth required."""

    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestSnapshotRoute:
    """GET /v1/snapshot — read-only, Observe tier."""

    def test_observe_key_can_snapshot(self, client):
        with patch("roustabout.api.routes._snapshot") as mock:
            mock.return_value = {"containers": [], "daemon": None}
            response = client.get("/v1/snapshot", headers=_auth())
        assert response.status_code == 200

    def test_snapshot_returns_container_list(self, client):
        with patch("roustabout.api.routes._snapshot") as mock:
            mock.return_value = {
                "containers": [{"name": "nginx", "image": "nginx:latest", "status": "running"}]
            }
            response = client.get("/v1/snapshot", headers=_auth())
        data = response.json()
        assert len(data["containers"]) == 1
        assert data["containers"][0]["name"] == "nginx"


class TestAuditRoute:
    """GET /v1/audit — read-only, Observe tier."""

    def test_observe_key_can_audit(self, client):
        with patch("roustabout.api.routes._audit") as mock:
            mock.return_value = {"findings": []}
            response = client.get("/v1/audit", headers=_auth())
        assert response.status_code == 200

    def test_audit_returns_findings(self, client):
        with patch("roustabout.api.routes._audit") as mock:
            mock.return_value = {
                "findings": [
                    {
                        "check": "privileged",
                        "severity": "critical",
                        "container": "nginx",
                        "message": "running privileged",
                    },
                ]
            }
            response = client.get("/v1/audit", headers=_auth())
        data = response.json()
        assert len(data["findings"]) == 1
        assert data["findings"][0]["check"] == "privileged"


class TestContainerDetailRoute:
    """GET /v1/containers/{name} — read-only, Observe tier."""

    def test_returns_detail_for_known_container(self, client):
        with patch("roustabout.api.routes._container_detail") as mock:
            mock.return_value = {
                "name": "nginx",
                "image": "nginx:latest",
                "status": "running",
                "health": "healthy",
                "restart_count": 0,
                "ports": [],
                "networks": ["bridge"],
            }
            response = client.get("/v1/containers/nginx", headers=_auth())
        assert response.status_code == 200
        assert response.json()["name"] == "nginx"

    def test_returns_404_for_unknown_container(self, client):
        with patch("roustabout.api.routes._container_detail") as mock:
            mock.return_value = None
            response = client.get("/v1/containers/ghost", headers=_auth())
        assert response.status_code == 404


class TestHealthRoute:
    """GET /v1/health/{name} — read-only, Observe tier."""

    def test_returns_health_for_known_container(self, client):
        with patch("roustabout.api.routes._health") as mock:
            mock.return_value = {
                "name": "nginx",
                "status": "running",
                "health": "healthy",
                "restart_count": 0,
                "oom_killed": False,
            }
            response = client.get("/v1/health/nginx", headers=_auth())
        assert response.status_code == 200
        assert response.json()["health"] == "healthy"

    def test_returns_404_for_unknown_container(self, client):
        with patch("roustabout.api.routes._health") as mock:
            mock.return_value = None
            response = client.get("/v1/health/ghost", headers=_auth())
        assert response.status_code == 404


class TestLogsRoute:
    """GET /v1/logs/{name} — read-only, Observe tier."""

    def test_returns_logs_for_container(self, client):
        with patch("roustabout.api.routes._logs") as mock:
            mock.return_value = {"container": "nginx", "lines": "GET / 200\nGET /health 200\n"}
            response = client.get("/v1/logs/nginx", headers=_auth())
        assert response.status_code == 200
        assert "GET /" in response.json()["lines"]

    def test_tail_parameter(self, client):
        with patch("roustabout.api.routes._logs") as mock:
            mock.return_value = {"container": "nginx", "lines": "line1\n"}
            response = client.get("/v1/logs/nginx?tail=10", headers=_auth())
        assert response.status_code == 200
        mock.assert_called_once_with("nginx", 10)

    def test_container_not_found(self, client):
        class ContainerNotFoundError(Exception):
            pass

        with patch("roustabout.api.routes._logs") as mock:
            exc = ContainerNotFoundError("ghost")
            exc.__class__.__name__ = "ContainerNotFoundError"
            mock.side_effect = exc
            response = client.get("/v1/logs/ghost", headers=_auth())
        assert response.status_code == 404


class TestDrPlanRoute:
    """GET /v1/dr-plan — read-only, Observe tier."""

    def test_returns_plan(self, client):
        with patch("roustabout.api.routes._dr_plan") as mock:
            mock.return_value = {"plan": "# Disaster Recovery Plan\n\n..."}
            response = client.get("/v1/dr-plan", headers=_auth())
        assert response.status_code == 200
        assert "plan" in response.json()


class TestMutationRoutes:
    """POST /v1/containers/{name}/{action} — Operate tier required."""

    def test_observe_key_cannot_restart(self, client):
        response = client.post("/v1/containers/nginx/restart", headers=_auth("sk-observe"))
        assert response.status_code == 403

    def test_operate_key_can_restart(self, client):
        with patch("roustabout.api.routes._mutate") as mock:
            mock.return_value = (
                200,
                {"result": "success", "container": "nginx", "action": "restart"},
            )
            response = client.post("/v1/containers/nginx/restart", headers=_auth("sk-operate"))
        assert response.status_code == 200
        assert response.json()["result"] == "success"

    def test_unknown_action_returns_400(self, client):
        response = client.post("/v1/containers/nginx/explode", headers=_auth("sk-operate"))
        assert response.status_code == 400

    def test_elevate_key_can_mutate(self, client):
        with patch("roustabout.api.routes._mutate") as mock:
            mock.return_value = (
                200,
                {"result": "success", "container": "nginx", "action": "stop"},
            )
            response = client.post("/v1/containers/nginx/stop", headers=_auth("sk-elevate"))
        assert response.status_code == 200

    def test_gateway_lockdown_returns_503(self, client):
        with patch("roustabout.api.routes._mutate") as mock:
            mock.return_value = (
                503,
                {
                    "result": "denied",
                    "error": "system locked",
                    "container": "nginx",
                    "action": "restart",
                },
            )
            response = client.post("/v1/containers/nginx/restart", headers=_auth("sk-operate"))
        assert response.status_code == 503

    def test_gateway_permission_denied_returns_403(self, client):
        with patch("roustabout.api.routes._mutate") as mock:
            mock.return_value = (
                403,
                {
                    "result": "denied",
                    "error": "insufficient tier",
                    "container": "nginx",
                    "action": "restart",
                },
            )
            response = client.post("/v1/containers/nginx/restart", headers=_auth("sk-operate"))
        assert response.status_code == 403

    def test_gateway_rate_limit_returns_429(self, client):
        with patch("roustabout.api.routes._mutate") as mock:
            mock.return_value = (
                429,
                {
                    "result": "denied",
                    "error": "rate limit exceeded",
                    "container": "nginx",
                    "action": "restart",
                },
            )
            response = client.post("/v1/containers/nginx/restart", headers=_auth("sk-operate"))
        assert response.status_code == 429

    def test_gateway_target_not_found_returns_404(self, client):
        with patch("roustabout.api.routes._mutate") as mock:
            mock.return_value = (
                404,
                {
                    "result": "denied",
                    "error": "container not found",
                    "container": "ghost",
                    "action": "restart",
                },
            )
            response = client.post("/v1/containers/ghost/restart", headers=_auth("sk-operate"))
        assert response.status_code == 404

    def test_gateway_concurrent_mutation_returns_409(self, client):
        with patch("roustabout.api.routes._mutate") as mock:
            mock.return_value = (
                409,
                {
                    "result": "denied",
                    "error": "state changed",
                    "container": "nginx",
                    "action": "restart",
                },
            )
            response = client.post("/v1/containers/nginx/restart", headers=_auth("sk-operate"))
        assert response.status_code == 409


class TestCapabilitiesRoute:
    """GET /v1/capabilities — returns capabilities for authenticated key."""

    def test_observe_key_sees_observe_capabilities(self, client):
        response = client.get("/v1/capabilities", headers=_auth("sk-observe"))
        assert response.status_code == 200
        data = response.json()
        assert "can_snapshot" in data["capabilities"]
        assert "can_restart" not in data["capabilities"]

    def test_operate_key_sees_operate_capabilities(self, client):
        response = client.get("/v1/capabilities", headers=_auth("sk-operate"))
        data = response.json()
        assert "can_restart" in data["capabilities"]
        assert data["tier"] == "operate"
        assert data["label"] == "test-operate"

    def test_elevate_key_sees_all_capabilities(self, client):
        response = client.get("/v1/capabilities", headers=_auth("sk-elevate"))
        data = response.json()
        assert "can_update_image" in data["capabilities"]
        assert "can_snapshot" in data["capabilities"]


class TestGatewayErrorMapping:
    """Verify _GATEWAY_ERROR_MAP covers all documented gateway errors."""

    def test_all_gateway_errors_mapped(self):
        from roustabout.api.routes import _GATEWAY_ERROR_MAP

        expected = {
            "LockdownError": 503,
            "PermissionDenied": 403,
            "RateLimitExceeded": 429,
            "CircuitOpen": 503,
            "BlastRadiusExceeded": 403,
            "TargetNotFound": 404,
            "ConcurrentMutation": 409,
        }
        assert _GATEWAY_ERROR_MAP == expected


class TestSchemas:
    """Verify Pydantic schemas can be constructed."""

    def test_mutation_response_serialization(self):
        from roustabout.api.schemas import MutationResponse

        resp = MutationResponse(
            result="success",
            container="nginx",
            action="restart",
            pre_hash="abc123",
            post_hash="def456",
        )
        data = resp.model_dump()
        assert data["result"] == "success"
        assert data["error"] is None

    def test_error_response_serialization(self):
        from roustabout.api.schemas import ErrorResponse

        resp = ErrorResponse(error="not found", detail="container 'ghost' does not exist")
        data = resp.model_dump()
        assert data["error"] == "not found"

    def test_health_entry_serialization(self):
        from roustabout.api.schemas import HealthEntry

        resp = HealthEntry(
            name="nginx", status="running", health="healthy", restart_count=0, oom_killed=False
        )
        data = resp.model_dump()
        assert data["health"] == "healthy"

    def test_snapshot_response_serialization(self):
        from roustabout.api.schemas import ContainerSummary, SnapshotResponse

        resp = SnapshotResponse(
            containers=[
                ContainerSummary(name="nginx", image="nginx:latest", status="running"),
            ]
        )
        data = resp.model_dump()
        assert len(data["containers"]) == 1
