"""Tests for Docker connection management."""

from unittest.mock import MagicMock, patch

import pytest

from roustabout.connection import connect


class TestConnect:
    def test_connects_with_default(self):
        mock_client = MagicMock()
        with patch("roustabout.connection.docker.DockerClient", return_value=mock_client):
            result = connect()
        assert result is mock_client
        mock_client.ping.assert_called_once()

    def test_connects_with_docker_host(self):
        mock_client = MagicMock()
        with patch(
            "roustabout.connection.docker.DockerClient", return_value=mock_client
        ) as mock_cls:
            connect("tcp://myhost:2375")
        mock_cls.assert_called_once_with(base_url="tcp://myhost:2375")

    def test_none_docker_host_uses_default(self):
        mock_client = MagicMock()
        with patch(
            "roustabout.connection.docker.DockerClient", return_value=mock_client
        ) as mock_cls:
            connect(None)
        mock_cls.assert_called_once_with()

    def test_raises_on_ping_failure(self):
        mock_client = MagicMock()
        mock_client.ping.side_effect = Exception("Connection refused")
        with patch("roustabout.connection.docker.DockerClient", return_value=mock_client):
            with pytest.raises(Exception, match="Connection refused"):
                connect()
