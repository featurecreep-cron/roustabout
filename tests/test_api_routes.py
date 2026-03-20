"""Tests for API route handlers.

Uses FastAPI TestClient to verify HTTP behavior end-to-end,
with core logic mocked at the boundary.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from roustabout.api.app import create_app
from roustabout.api.auth import AuthConfig


@pytest.fixture
def auth_config():
    return AuthConfig(keys={
        "sk-observe": {"tier": "observe", "label": "test-observe"},
        "sk-operate": {"tier": "operate", "label": "test-operate"},
        "sk-elevate": {"tier": "elevate", "label": "test-elevate"},
    })


@pytest.fixture
def app(auth_config):
    return create_app(auth_config=auth_config)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    return TestClient(app)


class TestAuthMiddleware:
    """Authentication enforcement on all routes."""

    def test_no_auth_header_returns_401(self, client):
        response = client.get("/v1/snapshot")
        assert response.status_code == 401

    def test_invalid_key_returns_401(self, client):
        response = client.get(
            "/v1/snapshot",
            headers={"Authorization": "Bearer sk-wrong"},
        )
        assert response.status_code == 401

    def test_valid_key_passes_auth(self, client):
        with patch("roustabout.api.routes._snapshot") as mock:
            mock.return_value = {"containers": []}
            response = client.get(
                "/v1/snapshot",
                headers={"Authorization": "Bearer sk-observe"},
            )
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
            response = client.get(
                "/v1/snapshot",
                headers={"Authorization": "Bearer sk-observe"},
            )
        assert response.status_code == 200

    def test_snapshot_returns_json(self, client):
        with patch("roustabout.api.routes._snapshot") as mock:
            mock.return_value = {"containers": [{"name": "nginx"}]}
            response = client.get(
                "/v1/snapshot",
                headers={"Authorization": "Bearer sk-observe"},
            )
        data = response.json()
        assert "containers" in data


class TestAuditRoute:
    """GET /v1/audit — read-only, Observe tier."""

    def test_observe_key_can_audit(self, client):
        with patch("roustabout.api.routes._audit") as mock:
            mock.return_value = {"findings": []}
            response = client.get(
                "/v1/audit",
                headers={"Authorization": "Bearer sk-observe"},
            )
        assert response.status_code == 200


class TestMutationRoutes:
    """POST /v1/containers/{name}/{action} — Operate tier required."""

    def test_observe_key_cannot_restart(self, client):
        response = client.post(
            "/v1/containers/nginx/restart",
            headers={"Authorization": "Bearer sk-observe"},
        )
        assert response.status_code == 403

    def test_operate_key_can_restart(self, client):
        with patch("roustabout.api.routes._mutate") as mock:
            mock.return_value = {"result": "success", "container": "nginx"}
            response = client.post(
                "/v1/containers/nginx/restart",
                headers={"Authorization": "Bearer sk-operate"},
            )
        assert response.status_code == 200

    def test_unknown_action_returns_400(self, client):
        response = client.post(
            "/v1/containers/nginx/explode",
            headers={"Authorization": "Bearer sk-operate"},
        )
        assert response.status_code == 400


class TestCapabilitiesRoute:
    """GET /v1/capabilities — returns capabilities for authenticated key."""

    def test_observe_key_sees_observe_capabilities(self, client):
        response = client.get(
            "/v1/capabilities",
            headers={"Authorization": "Bearer sk-observe"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "can_snapshot" in data["capabilities"]
        assert "can_restart" not in data["capabilities"]

    def test_operate_key_sees_operate_capabilities(self, client):
        response = client.get(
            "/v1/capabilities",
            headers={"Authorization": "Bearer sk-operate"},
        )
        data = response.json()
        assert "can_restart" in data["capabilities"]
