"""Tests for CLI backend selection and HTTP backend."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from roustabout.cli.backend import Backend, get_backend


class TestGetBackend:
    """Backend selection — always returns HTTPBackend."""

    def test_without_url_or_socket_raises(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ROUSTABOUT_URL", None)
            with patch("roustabout.cli.backend.os.path.exists", return_value=False):
                with pytest.raises(RuntimeError, match="No roustabout server found"):
                    get_backend()

    def test_url_set_returns_http(self):
        with patch.dict(os.environ, {"ROUSTABOUT_URL": "http://localhost:8077"}):
            backend = get_backend()
        from roustabout.cli.http import HTTPBackend

        assert isinstance(backend, HTTPBackend)

    def test_url_set_for_mutations_returns_http(self):
        with patch.dict(os.environ, {"ROUSTABOUT_URL": "http://localhost:8077"}):
            backend = get_backend(command_is_mutation=True)
        from roustabout.cli.http import HTTPBackend

        assert isinstance(backend, HTTPBackend)

    def test_socket_found_returns_http(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ROUSTABOUT_URL", None)
            with patch("roustabout.cli.backend.os.path.exists", return_value=True):
                backend = get_backend()
        from roustabout.cli.http import HTTPBackend

        assert isinstance(backend, HTTPBackend)

    def test_api_key_passed_to_http_backend(self):
        with patch.dict(
            os.environ,
            {
                "ROUSTABOUT_URL": "http://localhost:8077",
                "ROUSTABOUT_API_KEY": "sk-test-123",
            },
        ):
            backend = get_backend()
        from roustabout.cli.http import HTTPBackend

        assert isinstance(backend, HTTPBackend)
        assert "Authorization" in backend._client.headers

    def test_read_without_url_or_socket_raises(self):
        """Reads also require server — no direct Docker access."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ROUSTABOUT_URL", None)
            with patch("roustabout.cli.backend.os.path.exists", return_value=False):
                with pytest.raises(RuntimeError, match="does not access Docker directly"):
                    get_backend(command_is_mutation=False)


class TestHTTPBackend:
    """HTTPBackend HTTP call behavior."""

    def test_snapshot_calls_correct_endpoint(self):

        from roustabout.cli.http import HTTPBackend

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = {"containers": []}
        mock_client.get.return_value = mock_resp
        backend._client = mock_client

        result = backend.snapshot()
        mock_client.get.assert_called_once_with("/v1/snapshot", params={"format": "json"})
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

        backend.mutate("nginx", "restart")
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

    def test_snapshot_markdown_uses_get_text(self):
        from roustabout.cli.http import HTTPBackend

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.text = "# Snapshot\n..."
        mock_client.get.return_value = mock_resp
        backend._client = mock_client

        result = backend.snapshot(fmt="markdown")
        mock_client.get.assert_called_once_with("/v1/snapshot", params={"format": "markdown"})
        assert result == "# Snapshot\n..."

    def test_audit_passes_format_param(self):
        from roustabout.cli.http import HTTPBackend

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = {"findings": []}
        mock_client.get.return_value = mock_resp
        backend._client = mock_client

        result = backend.audit()
        mock_client.get.assert_called_once_with("/v1/audit", params={"format": "json"})
        assert result == {"findings": []}

    def test_audit_markdown_uses_get_text(self):
        from roustabout.cli.http import HTTPBackend

        backend = HTTPBackend.__new__(HTTPBackend)
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.text = "# Audit\n..."
        mock_client.get.return_value = mock_resp
        backend._client = mock_client

        result = backend.audit(fmt="markdown")
        mock_client.get.assert_called_once_with("/v1/audit", params={"format": "markdown"})
        assert result == "# Audit\n..."

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
