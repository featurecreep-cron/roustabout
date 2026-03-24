"""Tests for multi_host module."""

from unittest.mock import MagicMock, patch

import pytest

from roustabout.multi_host import (
    HostConfig,
    HostHealth,
    HostNotFound,
    HostPool,
    HostUnreachable,
    _create_client,
    hosts_from_config,
)


# --- HostConfig ---


class TestHostConfig:
    def test_frozen(self):
        cfg = HostConfig(name="test", url="unix:///var/run/docker.sock")
        with pytest.raises(AttributeError):
            cfg.name = "other"

    def test_defaults(self):
        cfg = HostConfig(name="test", url="unix:///var/run/docker.sock")
        assert cfg.default is False
        assert cfg.ssh_key is None
        assert cfg.tls_cert is None


# --- Connection creation ---


class TestCreateClient:
    @patch("roustabout.multi_host.docker.DockerClient")
    def test_unix_socket(self, mock_client):
        cfg = HostConfig(name="local", url="unix:///var/run/docker.sock")
        _create_client(cfg)
        mock_client.assert_called_once_with(base_url="unix:///var/run/docker.sock")

    @patch("roustabout.multi_host.docker.DockerClient")
    def test_ssh_transport(self, mock_client):
        cfg = HostConfig(name="remote", url="ssh://user@host:22")
        _create_client(cfg)
        mock_client.assert_called_once()
        call_kwargs = mock_client.call_args.kwargs
        assert call_kwargs["base_url"] == "ssh://user@host:22"
        assert call_kwargs["use_ssh_client"] is True

    @patch("roustabout.multi_host.docker.DockerClient")
    @patch("roustabout.multi_host.docker.tls.TLSConfig")
    def test_tcp_transport(self, mock_tls, mock_client):
        cfg = HostConfig(
            name="tcp",
            url="tcp://host:2376",
            tls_cert="/cert.pem",
            tls_key="/key.pem",
            tls_ca="/ca.pem",
        )
        _create_client(cfg)
        mock_tls.assert_called_once()
        mock_client.assert_called_once()

    def test_tcp_without_tls_raises(self):
        cfg = HostConfig(name="tcp", url="tcp://host:2376")
        with pytest.raises(ValueError, match="requires tls_cert"):
            _create_client(cfg)

    def test_unsupported_transport_raises(self):
        cfg = HostConfig(name="bad", url="ftp://host")
        with pytest.raises(ValueError, match="Unsupported transport"):
            _create_client(cfg)


# --- HostPool ---


class TestHostPool:
    def _make_pool(self, **hosts):
        configs = {}
        for name, url in hosts.items():
            configs[name] = HostConfig(name=name, url=url)
        return HostPool(configs)

    def test_host_not_found(self):
        pool = self._make_pool(local="unix:///var/run/docker.sock")
        with pytest.raises(HostNotFound, match="missing"):
            pool.connect("missing")

    @patch("roustabout.multi_host._create_client")
    def test_connect_creates_client(self, mock_create):
        client = MagicMock()
        mock_create.return_value = client
        pool = self._make_pool(local="unix:///var/run/docker.sock")
        result = pool.connect("local")
        assert result is client
        client.ping.assert_called_once()

    @patch("roustabout.multi_host._create_client")
    def test_connect_reuses_idle(self, mock_create):
        client = MagicMock()
        mock_create.return_value = client
        pool = self._make_pool(local="unix:///var/run/docker.sock")

        c1 = pool.connect("local")
        pool.release("local", c1)
        c2 = pool.connect("local")
        assert c1 is c2
        assert mock_create.call_count == 1

    @patch("roustabout.multi_host._create_client")
    def test_connect_reconnects_stale(self, mock_create):
        stale_client = MagicMock()
        fresh_client = MagicMock()
        mock_create.side_effect = [stale_client, fresh_client]

        pool = self._make_pool(local="unix:///var/run/docker.sock")
        c1 = pool.connect("local")  # ping succeeds (default mock)
        pool.release("local", c1)

        # Make ping fail so reuse triggers reconnect
        stale_client.ping.side_effect = Exception("dead")
        c2 = pool.connect("local")
        assert c2 is fresh_client

    @patch("roustabout.multi_host._create_client")
    def test_connect_failure_raises(self, mock_create):
        mock_create.side_effect = Exception("connection refused")
        pool = self._make_pool(remote="ssh://user@host")
        with pytest.raises(HostUnreachable, match="connection refused"):
            pool.connect("remote")

    @patch("roustabout.multi_host._create_client")
    def test_release_returns_to_pool(self, mock_create):
        client = MagicMock()
        mock_create.return_value = client
        pool = self._make_pool(local="unix:///var/run/docker.sock")

        c = pool.connect("local")
        pool.release("local", c)
        # Should not raise — connection is available
        pool.connect("local")

    @patch("roustabout.multi_host._create_client")
    def test_disconnect_closes_all(self, mock_create):
        client = MagicMock()
        mock_create.return_value = client
        pool = self._make_pool(local="unix:///var/run/docker.sock")

        pool.connect("local")
        pool.disconnect("local")
        client.close.assert_called()

    @patch("roustabout.multi_host._create_client")
    def test_disconnect_all(self, mock_create):
        c1 = MagicMock()
        c2 = MagicMock()
        mock_create.side_effect = [c1, c2]

        pool = HostPool(
            {
                "a": HostConfig(name="a", url="unix:///a"),
                "b": HostConfig(name="b", url="unix:///b"),
            }
        )
        pool.connect("a")
        pool.connect("b")
        pool.disconnect_all()
        c1.close.assert_called()
        c2.close.assert_called()

    def test_list_hosts(self):
        pool = self._make_pool(a="unix:///a", b="unix:///b")
        hosts = pool.list_hosts()
        names = {h.name for h in hosts}
        assert names == {"a", "b"}

    def test_default_host(self):
        pool = HostPool(
            {
                "a": HostConfig(name="a", url="unix:///a"),
                "b": HostConfig(name="b", url="unix:///b", default=True),
            }
        )
        assert pool.default_host() == "b"

    def test_no_default_host(self):
        pool = self._make_pool(a="unix:///a")
        assert pool.default_host() is None

    @patch("roustabout.multi_host._create_client")
    def test_health_reachable(self, mock_create):
        client = MagicMock()
        client.version.return_value = {"Version": "25.0"}
        client.containers.list.return_value = [MagicMock(), MagicMock()]
        mock_create.return_value = client

        pool = self._make_pool(local="unix:///var/run/docker.sock")
        health = pool.health("local")
        assert health.reachable is True
        assert health.docker_version == "25.0"
        assert health.containers_count == 2

    @patch("roustabout.multi_host._create_client")
    def test_health_unreachable(self, mock_create):
        mock_create.side_effect = Exception("refused")
        pool = self._make_pool(remote="ssh://user@host")
        health = pool.health("remote")
        assert health.reachable is False
        assert health.error is not None


# --- Config parsing ---


class TestHostsFromConfig:
    def test_empty_config(self):
        assert hosts_from_config({}) == {}

    def test_valid_config(self):
        config = {
            "hosts": {
                "cronbox": {
                    "url": "ssh://cron@192.168.1.120",
                    "label": "Primary",
                    "default": True,
                },
                "local": {
                    "url": "unix:///var/run/docker.sock",
                    "label": "Local",
                },
            }
        }
        hosts = hosts_from_config(config)
        assert len(hosts) == 2
        assert hosts["cronbox"].default is True
        assert hosts["local"].url == "unix:///var/run/docker.sock"

    def test_missing_url_skipped(self):
        config = {"hosts": {"bad": {"label": "no url"}}}
        hosts = hosts_from_config(config)
        assert len(hosts) == 0
