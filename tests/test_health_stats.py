"""Tests for health_stats — container health and resource monitoring.

Covers E7: health status, container stats, disk usage.
All Docker operations are mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from roustabout.health_stats import (
    ContainerHealth,
    ContainerStats,
    DiskUsage,
    collect_disk_usage,
    collect_health,
    collect_stats,
    render_health,
    render_stats,
)

# Helpers


def _mock_container(**overrides):
    c = MagicMock()
    c.name = overrides.get("name", "nginx")
    c.status = overrides.get("status", "running")
    c.attrs = overrides.get(
        "attrs",
        {
            "State": {
                "Status": "running",
                "StartedAt": "2026-03-17T00:00:00Z",
                "OOMKilled": False,
                "Health": {
                    "Status": "healthy",
                    "Log": [
                        {"ExitCode": 0, "Output": "OK", "Start": "2026-03-17T00:01:00Z"},
                    ],
                },
            },
            "RestartCount": 0,
            "Config": {
                "Healthcheck": {
                    "Test": ["CMD-SHELL", "curl -f http://localhost/"],
                    "Interval": 30000000000,
                    "Timeout": 10000000000,
                    "Retries": 3,
                    "StartPeriod": 5000000000,
                },
            },
            "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}},
        },
    )
    return c


def _mock_stats_cgroup_v2():
    """Stats response for cgroup v2."""
    return {
        "cpu_stats": {
            "cpu_usage": {"total_usage": 200000000},
            "online_cpus": 4,
            "system_cpu_usage": 1000000000,
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 100000000},
            "system_cpu_usage": 900000000,
        },
        "memory_stats": {
            "usage": 104857600,
            "limit": 536870912,
            "stats": {"inactive_file": 10485760},
        },
        "networks": {
            "eth0": {
                "rx_bytes": 1048576,
                "tx_bytes": 524288,
            },
        },
        "blkio_stats": {
            "io_service_bytes_recursive": [
                {"op": "read", "value": 2097152},
                {"op": "write", "value": 1048576},
            ],
        },
    }


def _mock_stats_cgroup_v1():
    """Stats response for cgroup v1."""
    return {
        "cpu_stats": {
            "cpu_usage": {
                "total_usage": 200000000,
                "percpu_usage": [50000000, 50000000, 50000000, 50000000],
            },
            "system_cpu_usage": 1000000000,
        },
        "precpu_stats": {
            "cpu_usage": {
                "total_usage": 100000000,
                "percpu_usage": [25000000, 25000000, 25000000, 25000000],
            },
            "system_cpu_usage": 900000000,
        },
        "memory_stats": {
            "usage": 104857600,
            "limit": 536870912,
            "stats": {"cache": 10485760},
        },
        "networks": {
            "eth0": {"rx_bytes": 1048576, "tx_bytes": 524288},
        },
        "blkio_stats": {
            "io_service_bytes_recursive": [
                {"op": "Read", "value": 2097152},
                {"op": "Write", "value": 1048576},
            ],
        },
    }


# Health collection


class TestCollectHealth:
    def test_healthy_container(self):
        client = MagicMock()
        client.containers.list.return_value = [_mock_container()]

        results = collect_health(client)
        assert len(results) == 1
        h = results[0]
        assert isinstance(h, ContainerHealth)
        assert h.name == "nginx"
        assert h.status == "running"
        assert h.health == "healthy"
        assert h.restart_count == 0
        assert h.oom_killed is False

    def test_no_healthcheck(self):
        c = _mock_container()
        c.attrs["State"]["Health"] = None
        client = MagicMock()
        client.containers.list.return_value = [c]

        results = collect_health(client)
        assert results[0].health is None

    def test_health_log_entries(self):
        results = collect_health(
            MagicMock(containers=MagicMock(list=MagicMock(return_value=[_mock_container()])))
        )
        assert len(results[0].health_log) == 1
        assert results[0].health_log[0]["ExitCode"] == 0


# Stats collection


class TestCollectStats:
    def test_cgroup_v2_stats(self):
        container = _mock_container()
        container.stats.return_value = _mock_stats_cgroup_v2()
        client = MagicMock()
        client.containers.list.return_value = [container]

        results = collect_stats(client)
        assert len(results) == 1
        s = results[0]
        assert isinstance(s, ContainerStats)
        assert s.cpu_percent > 0
        assert s.memory_usage_bytes > 0
        assert s.network_rx_bytes == 1048576
        assert s.block_read_bytes == 2097152

    def test_cgroup_v1_stats(self):
        container = _mock_container()
        container.stats.return_value = _mock_stats_cgroup_v1()
        client = MagicMock()
        client.containers.list.return_value = [container]

        results = collect_stats(client)
        s = results[0]
        assert s.cpu_percent > 0
        assert s.memory_usage_bytes > 0

    def test_single_container(self):
        container = _mock_container()
        container.stats.return_value = _mock_stats_cgroup_v2()
        client = MagicMock()
        client.containers.get.return_value = container

        results = collect_stats(client, target="nginx")
        assert len(results) == 1

    def test_block_io_none(self):
        """cgroup v2 sometimes returns null for block I/O."""
        stats = _mock_stats_cgroup_v2()
        stats["blkio_stats"]["io_service_bytes_recursive"] = None
        container = _mock_container()
        container.stats.return_value = stats
        client = MagicMock()
        client.containers.list.return_value = [container]

        results = collect_stats(client)
        assert results[0].block_read_bytes is None
        assert results[0].block_write_bytes is None


# Disk usage


class TestCollectDiskUsage:
    def test_disk_usage(self):
        client = MagicMock()
        client.df.return_value = {
            "Images": [
                {"Size": 100000000, "SharedSize": 50000000},
                {"Size": 200000000, "SharedSize": 100000000},
            ],
            "Containers": [
                {"SizeRw": 5000000, "SizeRootFs": 300000000},
            ],
            "Volumes": [
                {"UsageData": {"Size": 10000000}},
                {"UsageData": {"Size": 20000000}},
            ],
            "BuildCache": [
                {"Size": 50000000},
            ],
        }

        du = collect_disk_usage(client)
        assert isinstance(du, DiskUsage)
        assert du.images_count == 2
        assert du.volumes_count == 2
        assert du.containers_count == 1


# Rendering


class TestRendering:
    def test_render_health(self):
        healths = [
            ContainerHealth(
                name="nginx",
                status="running",
                health="healthy",
                restart_count=0,
                oom_killed=False,
                started_at="2026-03-17T00:00:00Z",
                health_log=[],
                healthcheck_config=None,
            ),
        ]
        result = render_health(healths)
        assert "nginx" in result
        assert "healthy" in result

    def test_render_stats(self):
        stats = [
            ContainerStats(
                name="nginx",
                cpu_percent=2.5,
                memory_usage_bytes=104857600,
                memory_limit_bytes=536870912,
                memory_percent=19.5,
                network_rx_bytes=1048576,
                network_tx_bytes=524288,
                block_read_bytes=2097152,
                block_write_bytes=1048576,
            ),
        ]
        result = render_stats(stats)
        assert "nginx" in result
        assert "2.5" in result
