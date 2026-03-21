"""Tests for MCP proxy — verifies HTTP translation layer.

All tests mock httpx.AsyncClient responses. No Docker or server required.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from roustabout.mcp_proxy.server import _format_error, _format_result, create_mcp_server


class TestFormatResult:
    """Response formatting."""

    def test_wraps_in_envelope(self):
        result = _format_result({"containers": []})
        assert result.startswith("[roustabout]")
        assert '"containers"' in result

    def test_json_is_indented(self):
        result = _format_result({"key": "value"})
        assert "  " in result


class TestFormatError:
    """Error message translation."""

    def test_401_gives_auth_message(self):
        resp = MagicMock()
        resp.json.return_value = {"error": "invalid key"}
        msg = _format_error(401, resp)
        assert "Authentication failed" in msg

    def test_403_includes_detail(self):
        resp = MagicMock()
        resp.json.return_value = {"error": "insufficient tier"}
        msg = _format_error(403, resp)
        assert "Permission denied" in msg
        assert "insufficient tier" in msg

    def test_404_includes_detail(self):
        resp = MagicMock()
        resp.json.return_value = {"error": "container not found"}
        msg = _format_error(404, resp)
        assert "Not found" in msg

    def test_429_gives_rate_limit_message(self):
        resp = MagicMock()
        resp.json.return_value = {}
        msg = _format_error(429, resp)
        assert "Rate limit" in msg

    def test_503_includes_detail(self):
        resp = MagicMock()
        resp.json.return_value = {"error": "locked down"}
        msg = _format_error(503, resp)
        assert "Service unavailable" in msg

    def test_unknown_status_includes_code(self):
        resp = MagicMock()
        resp.json.return_value = {"error": "oops"}
        resp.text = "oops"
        msg = _format_error(999, resp)
        assert "999" in msg

    def test_json_parse_failure_uses_text(self):
        resp = MagicMock()
        resp.json.side_effect = Exception("not json")
        resp.text = "raw error text"
        msg = _format_error(500, resp)
        assert "raw error text" in msg


class TestMCPProxyTools:
    """Verify each tool calls the correct HTTP endpoint."""

    @pytest.fixture
    def mock_client(self):
        return AsyncMock()

    @pytest.fixture
    def mcp(self, mock_client):
        with patch("roustabout.mcp_proxy.server.httpx.AsyncClient", return_value=mock_client):
            return create_mcp_server("http://localhost:8077", "sk-test")

    def _success_response(self, data: dict):
        resp = MagicMock()
        resp.is_success = True
        resp.json.return_value = data
        return resp

    def _error_response(self, status: int, error: str):
        resp = MagicMock()
        resp.is_success = False
        resp.status_code = status
        resp.json.return_value = {"error": error}
        resp.text = error
        return resp

    @pytest.mark.anyio
    async def test_docker_snapshot_calls_get(self, mcp, mock_client):
        mock_client.get.return_value = self._success_response({"containers": []})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_snapshot"].fn()
        mock_client.get.assert_called_with("/v1/snapshot")
        assert "[roustabout]" in result

    @pytest.mark.anyio
    async def test_docker_audit_calls_get(self, mcp, mock_client):
        mock_client.get.return_value = self._success_response({"findings": []})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_audit"].fn()
        mock_client.get.assert_called_with("/v1/audit")

    @pytest.mark.anyio
    async def test_docker_restart_calls_post(self, mcp, mock_client):
        mock_client.post.return_value = self._success_response({"result": "success"})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_restart"].fn(name="nginx")
        mock_client.post.assert_called_with("/v1/containers/nginx/restart")

    @pytest.mark.anyio
    async def test_docker_stop_calls_post(self, mcp, mock_client):
        mock_client.post.return_value = self._success_response({"result": "success"})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_stop"].fn(name="nginx")
        mock_client.post.assert_called_with("/v1/containers/nginx/stop")

    @pytest.mark.anyio
    async def test_docker_health_calls_get(self, mcp, mock_client):
        mock_client.get.return_value = self._success_response({"name": "nginx", "health": "healthy"})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_health"].fn(name="nginx")
        mock_client.get.assert_called_with("/v1/health/nginx")

    @pytest.mark.anyio
    async def test_docker_logs_passes_tail(self, mcp, mock_client):
        mock_client.get.return_value = self._success_response({"container": "nginx", "lines": "log"})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_logs"].fn(name="nginx", tail=50)
        mock_client.get.assert_called_with("/v1/logs/nginx", params={"tail": 50})

    @pytest.mark.anyio
    async def test_error_response_returns_message(self, mcp, mock_client):
        mock_client.post.return_value = self._error_response(403, "insufficient tier")
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_restart"].fn(name="nginx")
        assert "Permission denied" in result

    @pytest.mark.anyio
    async def test_capabilities_calls_get(self, mcp, mock_client):
        mock_client.get.return_value = self._success_response({"tier": "observe", "capabilities": []})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_capabilities"].fn()
        mock_client.get.assert_called_with("/v1/capabilities")

    @pytest.mark.anyio
    async def test_docker_container_calls_get(self, mcp, mock_client):
        mock_client.get.return_value = self._success_response({"name": "nginx", "status": "running"})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_container"].fn(name="nginx")
        mock_client.get.assert_called_with("/v1/containers/nginx")

    @pytest.mark.anyio
    async def test_docker_dr_plan_calls_get(self, mcp, mock_client):
        mock_client.get.return_value = self._success_response({"plan": "# DR Plan"})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_dr_plan"].fn()
        mock_client.get.assert_called_with("/v1/dr-plan")

    @pytest.mark.anyio
    async def test_docker_start_calls_post(self, mcp, mock_client):
        mock_client.post.return_value = self._success_response({"result": "success"})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_start"].fn(name="nginx")
        mock_client.post.assert_called_with("/v1/containers/nginx/start")

    @pytest.mark.anyio
    async def test_docker_recreate_calls_post(self, mcp, mock_client):
        mock_client.post.return_value = self._success_response({"result": "success"})
        tools = {t.name: t for t in mcp._tool_manager.list_tools()}
        result = await tools["docker_recreate"].fn(name="nginx")
        mock_client.post.assert_called_with("/v1/containers/nginx/recreate")


class TestMainEntryPoint:
    """Verify main() validates API key."""

    def test_exits_without_api_key(self):
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("ROUSTABOUT_API_KEY", None)
            with pytest.raises(SystemExit):
                from roustabout.mcp_proxy.server import main
                main()
