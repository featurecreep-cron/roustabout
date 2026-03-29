"""Tests for network_inspect module."""

from unittest.mock import MagicMock

import pytest

from roustabout.network_inspect import (
    _collect_port_info,
    _parse_dns_output,
    _validate_host,
    inspect_container_network,
    inspect_network,
    probe_connectivity,
    probe_dns,
)
from roustabout.session import DockerSession

# --- Input validation ---


class TestValidateHost:
    @pytest.mark.parametrize(
        "value",
        ["example.com", "192.168.1.1", "::1", "my-host", "host_name", "host.local"],
    )
    def test_valid_hosts(self, value):
        _validate_host(value, "test")

    @pytest.mark.parametrize(
        "value",
        ["", "host;rm -rf /", "$(whoami)", "host`id`", "host\ninjection"],
    )
    def test_invalid_hosts(self, value):
        with pytest.raises(ValueError, match="invalid characters"):
            _validate_host(value, "test")


# --- Port info collection ---


class TestCollectPortInfo:
    def test_published_port(self):
        attrs = {
            "Config": {"ExposedPorts": {"80/tcp": {}}},
            "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}},
        }
        ports = _collect_port_info(attrs)
        assert len(ports) == 1
        assert ports[0].container_port == 80
        assert ports[0].published is True
        assert ports[0].exposed is True
        assert ports[0].host_port == "8080"

    def test_exposed_only(self):
        attrs = {
            "Config": {"ExposedPorts": {"3000/tcp": {}}},
            "NetworkSettings": {"Ports": {}},
        }
        ports = _collect_port_info(attrs)
        assert len(ports) == 1
        assert ports[0].published is False
        assert ports[0].exposed is True

    def test_published_not_exposed(self):
        attrs = {
            "Config": {},
            "NetworkSettings": {
                "Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]}
            },
        }
        ports = _collect_port_info(attrs)
        assert len(ports) == 1
        assert ports[0].published is True
        assert ports[0].exposed is False

    def test_no_ports(self):
        attrs = {"Config": {}, "NetworkSettings": {"Ports": {}}}
        ports = _collect_port_info(attrs)
        assert len(ports) == 0

    def test_port_not_bound(self):
        attrs = {
            "Config": {},
            "NetworkSettings": {"Ports": {"80/tcp": None}},
        }
        ports = _collect_port_info(attrs)
        assert len(ports) == 1
        assert ports[0].published is False

    def test_multiple_bindings(self):
        attrs = {
            "Config": {},
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": [
                        {"HostIp": "0.0.0.0", "HostPort": "8080"},
                        {"HostIp": "::", "HostPort": "8080"},
                    ]
                }
            },
        }
        ports = _collect_port_info(attrs)
        assert len(ports) == 2

    def test_malformed_port_key_skipped(self):
        attrs = {
            "Config": {},
            "NetworkSettings": {"Ports": {"bad/tcp": None}},
        }
        ports = _collect_port_info(attrs)
        assert len(ports) == 0

    def test_sorted_output(self):
        attrs = {
            "Config": {},
            "NetworkSettings": {
                "Ports": {
                    "443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}],
                    "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}],
                }
            },
        }
        ports = _collect_port_info(attrs)
        assert ports[0].container_port == 80
        assert ports[1].container_port == 443


# --- Network inspection ---


class TestInspectNetwork:
    def test_basic_network(self):
        network = MagicMock()
        network.attrs = {
            "Name": "frontend",
            "Id": "abc123def456" + "0" * 52,
            "Driver": "bridge",
            "Scope": "local",
            "Internal": False,
            "IPAM": {"Config": [{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"}]},
            "Containers": {
                "abc123": {
                    "Name": "nginx",
                    "IPv4Address": "172.18.0.2/16",
                    "IPv6Address": "",
                    "MacAddress": "02:42:ac:12:00:02",
                }
            },
        }
        client = MagicMock()
        client.networks.get.return_value = network

        detail = inspect_network(client, "frontend")
        assert detail.name == "frontend"
        assert detail.driver == "bridge"
        assert detail.subnet == "172.18.0.0/16"
        assert len(detail.containers) == 1
        assert detail.containers[0].ipv4_address == "172.18.0.2"

    def test_empty_ipam(self):
        network = MagicMock()
        network.attrs = {
            "Name": "isolated",
            "Id": "x" * 64,
            "Driver": "bridge",
            "Scope": "local",
            "Internal": True,
            "IPAM": {"Config": []},
            "Containers": {},
        }
        client = MagicMock()
        client.networks.get.return_value = network

        detail = inspect_network(client, "isolated")
        assert detail.subnet is None
        assert detail.gateway is None
        assert detail.internal is True


class TestInspectContainerNetwork:
    def test_basic_container(self):
        container = MagicMock()
        container.name = "morsl-app"
        container.attrs = {
            "NetworkSettings": {
                "Ports": {"5000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5000"}]},
                "Networks": {
                    "morsl_default": {
                        "IPAddress": "172.18.0.3",
                        "Aliases": ["morsl-app", "morsl"],
                    }
                },
            },
            "HostConfig": {
                "NetworkMode": "morsl_default",
                "Dns": [],
                "DnsSearch": [],
                "ExtraHosts": [],
            },
            "Config": {},
        }
        client = MagicMock()
        client.containers.get.return_value = container

        # Mock the network inspect call
        network = MagicMock()
        network.attrs = {
            "Name": "morsl_default",
            "Id": "x" * 64,
            "Driver": "bridge",
            "Scope": "local",
            "Internal": False,
            "IPAM": {"Config": [{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"}]},
            "Containers": {},
        }
        client.networks.get.return_value = network

        view = inspect_container_network(client, "morsl-app")
        assert view.container_name == "morsl-app"
        assert len(view.networks) == 1
        assert view.networks[0].name == "morsl_default"
        assert len(view.published_ports) == 1


# --- DNS parsing ---


class TestParseDNSOutput:
    def test_getent_format(self):
        output = "172.18.0.2\ttandoor tandoor.morsl_default"
        addrs = _parse_dns_output(output, "tandoor")
        assert "172.18.0.2" in addrs

    def test_nslookup_format(self):
        output = (
            "Server:\t\t127.0.0.11\nAddress:\t127.0.0.11\n\nName:\ttandoor\nAddress: 172.18.0.2\n"
        )
        addrs = _parse_dns_output(output, "tandoor")
        assert "172.18.0.2" in addrs

    def test_localhost_filtered(self):
        output = "127.0.0.1\tlocalhost\n172.18.0.2\ttandoor"
        addrs = _parse_dns_output(output, "tandoor")
        assert "127.0.0.1" not in addrs
        assert "172.18.0.2" in addrs

    def test_localhost_kept_when_queried(self):
        output = "127.0.0.1\tlocalhost"
        addrs = _parse_dns_output(output, "localhost")
        assert "127.0.0.1" in addrs

    def test_empty_output(self):
        addrs = _parse_dns_output("", "anything")
        assert len(addrs) == 0

    def test_deduplication(self):
        output = "172.18.0.2\thost\n172.18.0.2\thost.default"
        addrs = _parse_dns_output(output, "host")
        assert addrs.count("172.18.0.2") == 1


# --- Active probes ---


class TestProbeDNS:
    def test_getent_success(self):
        from unittest.mock import patch

        from roustabout.exec import ExecResult

        session = DockerSession(client=MagicMock(), host="localhost")
        success_result = ExecResult(
            success=True,
            target="app",
            command=("getent", "hosts", "tandoor"),
            exit_code=0,
            stdout="172.18.0.2\ttandoor",
            stderr="",
            truncated=False,
        )

        with patch("roustabout.exec.execute", return_value=success_result):
            result = probe_dns(session, "app", "tandoor")
            assert result.resolved is True
            assert "172.18.0.2" in result.addresses

    def test_invalid_hostname_rejected(self):
        session = DockerSession(client=MagicMock(), host="localhost")
        with pytest.raises(ValueError, match="invalid characters"):
            probe_dns(session, "app", "host;rm -rf /")


class TestProbeConnectivity:
    def test_invalid_target_rejected(self):
        session = DockerSession(client=MagicMock(), host="localhost")
        with pytest.raises(ValueError, match="invalid characters"):
            probe_connectivity(session, "app", "host$(id)", 80)
