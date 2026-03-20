"""Tests for CLI dual-mode backend selection and implementations."""

from __future__ import annotations

import os

import pytest
from unittest.mock import patch, MagicMock

from roustabout.cli.backend import Backend, get_backend
from roustabout.cli.direct import DirectBackend


class TestBackendProtocol:
    """Verify Backend protocol compliance."""

    def test_direct_backend_is_backend(self):
        assert isinstance(DirectBackend(), Backend)

    def test_direct_backend_rejects_mutate(self):
        backend = DirectBackend()
        with pytest.raises(RuntimeError, match="cannot execute mutations"):
            backend.mutate("nginx", "restart")

    def test_direct_backend_rejects_capabilities(self):
        backend = DirectBackend()
        with pytest.raises(RuntimeError, match="no auth context"):
            backend.capabilities()


class TestGetBackend:
    """Backend selection based on environment and command type."""

    def test_read_without_url_returns_direct(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ROUSTABOUT_URL", None)
            backend = get_backend(command_is_mutation=False)
        assert isinstance(backend, DirectBackend)

    def test_mutation_without_url_or_socket_raises(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ROUSTABOUT_URL", None)
            with patch("roustabout.cli.backend.os.path.exists", return_value=False):
                with pytest.raises(RuntimeError, match="No roustabout server found"):
                    get_backend(command_is_mutation=True)

    def test_url_set_returns_http_for_reads(self):
        with patch.dict(os.environ, {"ROUSTABOUT_URL": "http://localhost:8077"}):
            backend = get_backend(command_is_mutation=False)
        from roustabout.cli.http import HTTPBackend
        assert isinstance(backend, HTTPBackend)

    def test_url_set_returns_http_for_mutations(self):
        with patch.dict(os.environ, {"ROUSTABOUT_URL": "http://localhost:8077"}):
            backend = get_backend(command_is_mutation=True)
        from roustabout.cli.http import HTTPBackend
        assert isinstance(backend, HTTPBackend)

    def test_mutation_with_socket_returns_http(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ROUSTABOUT_URL", None)
            with patch("roustabout.cli.backend.os.path.exists", return_value=True):
                backend = get_backend(command_is_mutation=True)
        from roustabout.cli.http import HTTPBackend
        assert isinstance(backend, HTTPBackend)

    def test_api_key_passed_to_http_backend(self):
        with patch.dict(os.environ, {
            "ROUSTABOUT_URL": "http://localhost:8077",
            "ROUSTABOUT_API_KEY": "sk-test-123",
        }):
            backend = get_backend(command_is_mutation=False)
        from roustabout.cli.http import HTTPBackend
        assert isinstance(backend, HTTPBackend)
        assert "Authorization" in backend._client.headers


class TestHTTPBackend:
    """HTTPBackend HTTP call behavior."""

    def test_snapshot_calls_correct_endpoint(self):
        from roustabout.cli.http import HTTPBackend
        import httpx

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = {"containers": []}
        mock_client.get.return_value = mock_resp
        backend._client = mock_client

        result = backend.snapshot()
        mock_client.get.assert_called_once_with("/v1/snapshot", params=None)
        assert result == {"containers": []}

    def test_mutate_calls_post(self):
        from roustabout.cli.http import HTTPBackend

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = {"result": "success", "container": "nginx"}
        mock_client.post.return_value = mock_resp
        backend._client = mock_client

        result = backend.mutate("nginx", "restart")
        mock_client.post.assert_called_once_with("/v1/containers/nginx/restart")

    def test_401_raises_auth_error(self):
        from roustabout.cli.http import HTTPBackend

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = False
        mock_resp.status_code = 401
        mock_resp.json.return_value = {"error": "invalid key"}
        mock_client.get.return_value = mock_resp
        backend._client = mock_client

        with pytest.raises(RuntimeError, match="Authentication failed"):
            backend.snapshot()

    def test_403_raises_permission_error(self):
        from roustabout.cli.http import HTTPBackend

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = False
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"error": "insufficient tier"}
        mock_client.post.return_value = mock_resp
        backend._client = mock_client

        with pytest.raises(RuntimeError, match="Permission denied"):
            backend.mutate("nginx", "restart")

    def test_429_raises_rate_limit_error(self):
        from roustabout.cli.http import HTTPBackend

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = False
        mock_resp.status_code = 429
        mock_resp.json.return_value = {"error": "rate limit"}
        mock_client.post.return_value = mock_resp
        backend._client = mock_client

        with pytest.raises(RuntimeError, match="Rate limit exceeded"):
            backend.mutate("nginx", "restart")

    def test_logs_with_tail_parameter(self):
        from roustabout.cli.http import HTTPBackend

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = {"container": "nginx", "lines": "log output"}
        mock_client.get.return_value = mock_resp
        backend._client = mock_client

        backend.logs("nginx", tail=50)
        mock_client.get.assert_called_once_with("/v1/logs/nginx", params={"tail": 50})
