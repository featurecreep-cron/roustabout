"""Tests for metrics module."""

from unittest.mock import MagicMock, patch

import pytest

from roustabout.metrics import _available, init_metrics, update_container_metrics

# --- Availability ---


class TestAvailability:
    def test_available_with_prometheus(self):
        # prometheus_client may or may not be installed in test env
        # Just verify the function doesn't crash
        result = _available()
        assert isinstance(result, bool)


# --- Init ---


class TestInitMetrics:
    def test_init_sets_state(self):
        import roustabout.metrics as m

        pool = MagicMock()
        config = {"metrics": {"max_containers": 50}}
        init_metrics(pool, config)
        assert m._host_pool is pool
        assert m._config is config
        # Reset
        m._host_pool = None
        m._config = {}


# --- Update ---


class TestUpdateContainerMetrics:
    def test_noop_without_pool(self):
        import roustabout.metrics as m

        m._host_pool = None
        # Should not raise
        update_container_metrics()

    @pytest.mark.skipif(not _available(), reason="prometheus_client not installed")
    def test_updates_from_pool(self):
        import roustabout.metrics as m
        from roustabout.health_stats import ContainerHealth, ContainerStats
        from roustabout.multi_host import HostConfig

        host = HostConfig(name="test", url="unix:///var/run/docker.sock")
        pool = MagicMock()
        pool.list_hosts.return_value = (host,)

        client = MagicMock()
        pool.connect.return_value = client

        health = ContainerHealth(
            name="nginx",
            status="running",
            health="healthy",
            restart_count=2,
            oom_killed=False,
            started_at="2026-01-01T00:00:00Z",
        )
        stats = ContainerStats(
            name="nginx",
            cpu_percent=5.0,
            memory_usage_bytes=1024 * 1024,
            memory_limit_bytes=512 * 1024 * 1024,
            memory_percent=0.2,
            network_rx_bytes=1000,
            network_tx_bytes=500,
            block_read_bytes=None,
            block_write_bytes=None,
        )

        with (
            patch("roustabout.metrics.collect_health", return_value=[health]),
            patch("roustabout.metrics.collect_stats", return_value=[stats]),
        ):
            init_metrics(pool, {"metrics": {"include_stats": True}})
            update_container_metrics()

        pool.connect.assert_called_once_with("test")
        pool.release.assert_called_once_with("test", client)

        # Reset
        m._host_pool = None
        m._config = {}

    @pytest.mark.skipif(not _available(), reason="prometheus_client not installed")
    def test_host_failure_skipped(self):
        import roustabout.metrics as m
        from roustabout.multi_host import HostConfig

        host = HostConfig(name="bad", url="ssh://unreachable")
        pool = MagicMock()
        pool.list_hosts.return_value = (host,)
        pool.connect.side_effect = Exception("unreachable")

        init_metrics(pool, {})
        # Should not raise
        update_container_metrics()

        # Reset
        m._host_pool = None
        m._config = {}
