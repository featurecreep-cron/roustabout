"""Tests for log_access — container log retrieval.

Covers E8: log retrieval, filtering, sanitization.
All Docker operations are mocked.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import docker.errors as _docker_errors
import pytest

from roustabout.log_access import (
    ContainerNotFoundError,
    UnsupportedLogDriver,
    collect_logs,
    parse_since,
)

# Helpers

def _mock_container(
    name: str = "nginx",
    log_driver: str = "json-file",
    logs_output: bytes = b"line1\nline2\nline3\n",
):
    c = MagicMock()
    c.name = name
    c.attrs = {
        "HostConfig": {
            "LogConfig": {"Type": log_driver},
        },
    }
    c.logs.return_value = logs_output
    return c


# Log retrieval

class TestCollectLogs:
    def test_basic_retrieval(self):
        client = MagicMock()
        client.containers.get.return_value = _mock_container()

        result = collect_logs(client, "nginx")
        assert "line1" in result
        assert "line2" in result

    def test_tail_parameter(self):
        client = MagicMock()
        container = _mock_container()
        client.containers.get.return_value = container

        collect_logs(client, "nginx", tail=50)
        container.logs.assert_called_once()
        _, kwargs = container.logs.call_args
        assert kwargs["tail"] == 50

    def test_container_not_found(self):
        client = MagicMock()
        client.containers.get.side_effect = _docker_errors.NotFound("nope")

        with pytest.raises(ContainerNotFoundError):
            collect_logs(client, "ghost")

    def test_unsupported_log_driver(self):
        client = MagicMock()
        client.containers.get.return_value = _mock_container(
            log_driver="gelf"
        )

        with pytest.raises(UnsupportedLogDriver, match="gelf"):
            collect_logs(client, "nginx")

    def test_supported_drivers(self):
        for driver in ("json-file", "local", "journald"):
            client = MagicMock()
            client.containers.get.return_value = _mock_container(
                log_driver=driver
            )
            result = collect_logs(client, "nginx")
            assert isinstance(result, str)

    def test_sanitizes_control_chars(self):
        client = MagicMock()
        client.containers.get.return_value = _mock_container(
            logs_output=b"normal\x1b[31mred\x1b[0m text\x00null\n"
        )

        result = collect_logs(client, "nginx")
        assert "\x1b" not in result
        assert "\x00" not in result

    def test_per_line_truncation(self):
        long_line = b"x" * 3000 + b"\n"
        client = MagicMock()
        client.containers.get.return_value = _mock_container(
            logs_output=long_line
        )

        result = collect_logs(client, "nginx", line_limit=1024)
        lines = result.strip().split("\n")
        assert len(lines[0]) <= 1024 + len("[truncated]")

    def test_grep_filtering(self):
        client = MagicMock()
        client.containers.get.return_value = _mock_container(
            logs_output=b"error: disk full\ninfo: all good\nerror: timeout\n"
        )

        result = collect_logs(client, "nginx", grep="error")
        assert "error: disk full" in result
        assert "error: timeout" in result
        assert "info: all good" not in result


# Since parsing

class TestParseSince:
    def test_relative_minutes(self):
        result = parse_since("30m")
        assert isinstance(result, int)

    def test_relative_hours(self):
        result = parse_since("2h")
        assert isinstance(result, int)

    def test_relative_days(self):
        result = parse_since("1d")
        assert isinstance(result, int)

    def test_iso_8601(self):
        result = parse_since("2026-03-17T00:00:00Z")
        assert isinstance(result, str)

    def test_invalid(self):
        with pytest.raises(ValueError, match="Invalid"):
            parse_since("yesterday")
