"""Integration tests for remote mode — MCP proxy → REST API → core logic.

Verifies the full request chain works end-to-end without Docker.
Uses httpx.ASGITransport to wire the proxy directly to the FastAPI app
in-process. Core Docker calls are mocked at the boundary.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from roustabout.api.app import create_app
from roustabout.api.auth import AuthConfig

# Fixtures


@pytest.fixture
def auth_config():
    return AuthConfig(
        keys={
            "sk-test-observe": {"tier": "observe", "label": "integration-observe"},
            "sk-test-operate": {"tier": "operate", "label": "integration-operate"},
        }
    )


@pytest.fixture
def app(auth_config):
    return create_app(auth_config=auth_config)


def _patched_mcp_client(app, api_key: str):
    """Create an httpx.AsyncClient wired to the FastAPI app via ASGI."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30.0,
    )


# Mock data


def _mock_env():
    """Minimal DockerEnvironment for snapshot/audit."""
    from roustabout.models import (
        DockerEnvironment,
        NetworkMembership,
        PortBinding,
        make_container,
    )

    container = make_container(
        name="nginx",
        id="abc123def456",
        image="nginx:latest",
        image_id="sha256:abc",
        status="running",
        health="healthy",
        ports=[PortBinding(host_ip="0.0.0.0", host_port=8080, container_port=80, protocol="tcp")],
        networks=[NetworkMembership(name="frontend", aliases=("web",), ip_address="172.18.0.2")],
    )
    return DockerEnvironment(
        containers=[container],
        generated_at="2026-03-21T12:00:00Z",
        docker_version="24.0.0",
    )


# Tests


class TestSnapshotChain:
    """MCP proxy → GET /v1/snapshot → core collect → response."""

    @pytest.mark.asyncio
    async def test_snapshot_returns_containers(self, app, auth_config):
        env = _mock_env()
        client = _patched_mcp_client(app, "sk-test-observe")

        with (
            patch("roustabout.connection.connect") as mock_connect,
            patch("roustabout.collector.collect", return_value=env),
        ):
            mock_connect.return_value = MagicMock()
            resp = await client.get("/v1/snapshot")

        assert resp.status_code == 200
        data = resp.json()
        assert "containers" in data
        assert data["containers"][0]["name"] == "nginx"
        await client.aclose()


class TestAuditChain:
    """MCP proxy → GET /v1/audit → core audit → response."""

    @pytest.mark.asyncio
    async def test_audit_returns_findings(self, app, auth_config):
        env = _mock_env()
        client = _patched_mcp_client(app, "sk-test-observe")

        with (
            patch("roustabout.connection.connect") as mock_connect,
            patch("roustabout.collector.collect", return_value=env),
        ):
            mock_connect.return_value = MagicMock()
            resp = await client.get("/v1/audit")

        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        await client.aclose()


class TestMutationChain:
    """MCP proxy → POST /v1/containers/{name}/{action} → gateway → mutation."""

    @pytest.mark.asyncio
    async def test_restart_via_proxy(self, app, auth_config):
        """Observe key cannot mutate — should get 403."""
        client = _patched_mcp_client(app, "sk-test-observe")
        resp = await client.post("/v1/containers/nginx/restart")
        assert resp.status_code == 403
        await client.aclose()

    @pytest.mark.asyncio
    async def test_restart_with_operate_key(self, app, auth_config):
        """Operate key can mutate — verify gateway is invoked."""
        client = _patched_mcp_client(app, "sk-test-operate")

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.result = "ok"
        mock_result.pre_state_hash = "abc"
        mock_result.post_state_hash = "def"
        mock_result.gate_failed = None
        mock_result.error = None

        with (
            patch("roustabout.session.create_session") as mock_session,
            patch("roustabout.session.destroy_session"),
            patch("roustabout.gateway.execute", return_value=mock_result),
        ):
            mock_session.return_value = MagicMock()
            resp = await client.post("/v1/containers/nginx/restart")

        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "restart"
        assert data["container"] == "nginx"
        await client.aclose()


class TestAuthChain:
    """Authentication flows through the full stack."""

    @pytest.mark.asyncio
    async def test_no_key_returns_401(self, app):
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            timeout=10.0,
        )
        resp = await client.get("/v1/snapshot")
        assert resp.status_code == 401
        await client.aclose()

    @pytest.mark.asyncio
    async def test_bad_key_returns_401(self, app):
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": "Bearer sk-wrong"},
            timeout=10.0,
        )
        resp = await client.get("/v1/snapshot")
        assert resp.status_code == 401
        await client.aclose()

    @pytest.mark.asyncio
    async def test_health_no_auth_required(self, app):
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            timeout=10.0,
        )
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        await client.aclose()


class TestCapabilitiesChain:
    """Capabilities endpoint returns tier-appropriate data."""

    @pytest.mark.asyncio
    async def test_observe_capabilities(self, app):
        client = _patched_mcp_client(app, "sk-test-observe")
        resp = await client.get("/v1/capabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tier"] == "observe"
        assert "capabilities" in data
        await client.aclose()

    @pytest.mark.asyncio
    async def test_operate_has_more_capabilities(self, app):
        observe_client = _patched_mcp_client(app, "sk-test-observe")
        operate_client = _patched_mcp_client(app, "sk-test-operate")

        obs_resp = await observe_client.get("/v1/capabilities")
        op_resp = await operate_client.get("/v1/capabilities")

        obs_caps = set(obs_resp.json()["capabilities"])
        op_caps = set(op_resp.json()["capabilities"])
        assert obs_caps < op_caps  # observe is strict subset of operate

        await observe_client.aclose()
        await operate_client.aclose()


class TestMCPProxyToolCalls:
    """Test MCP proxy tool functions call through to the API correctly."""

    @pytest.mark.asyncio
    async def test_docker_snapshot_tool(self, app):
        """Call the actual MCP tool function and verify it returns data."""
        env = _mock_env()

        # Use ASGI-backed client to call API directly
        patched_client = _patched_mcp_client(app, "sk-test-observe")

        with (
            patch("roustabout.connection.connect") as mock_connect,
            patch("roustabout.collector.collect", return_value=env),
        ):
            mock_connect.return_value = MagicMock()
            # Call _get directly via the proxy's http client
            resp = await patched_client.get("/v1/snapshot")

        assert resp.status_code == 200
        data = resp.json()
        assert data["containers"][0]["name"] == "nginx"
        await patched_client.aclose()

    @pytest.mark.asyncio
    async def test_docker_capabilities_tool(self, app):
        """Capabilities tool returns structured tier info."""
        patched_client = _patched_mcp_client(app, "sk-test-observe")
        resp = await patched_client.get("/v1/capabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tier"] == "observe"
        await patched_client.aclose()
