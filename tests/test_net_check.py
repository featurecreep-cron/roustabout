"""Tests for network connectivity analysis."""

from roustabout.models import DockerEnvironment, NetworkMembership, make_container
from roustabout.net_check import (
    ConnectivityResult,
    check_all_connectivity,
    check_connectivity,
)


def _c(
    name: str,
    *,
    networks: tuple[NetworkMembership, ...] = (),
    network_mode: str | None = None,
    container_id: str = "",
) -> "ContainerInfo":  # noqa: F821
    return make_container(
        name=name,
        id=container_id or f"sha256{name}abc123",
        status="running",
        image=f"{name}:latest",
        image_id=f"sha256:{name}img",
        networks=networks,
        network_mode=network_mode,
    )


def _net(name: str) -> NetworkMembership:
    return NetworkMembership(name=name, ip_address="172.17.0.2", aliases=())


def _env(*containers):
    return DockerEnvironment(
        containers=tuple(containers),
        generated_at="2024-01-01T00:00:00Z",
        docker_version="24.0.0",
    )


class TestCheckConnectivity:
    def test_shared_network(self):
        a = _c("app", networks=(_net("frontend"),))
        b = _c("db", networks=(_net("frontend"),))
        result = check_connectivity(_env(a, b), "app", "db")
        assert result.reachable is True
        assert result.shared_networks == ("frontend",)
        assert "frontend" in result.reason

    def test_multiple_shared_networks(self):
        a = _c("app", networks=(_net("frontend"), _net("backend")))
        b = _c("db", networks=(_net("backend"), _net("frontend")))
        result = check_connectivity(_env(a, b), "app", "db")
        assert result.reachable is True
        assert result.shared_networks == ("backend", "frontend")
        assert "networks" in result.reason

    def test_no_shared_networks(self):
        a = _c("app", networks=(_net("frontend"),))
        b = _c("db", networks=(_net("backend"),))
        result = check_connectivity(_env(a, b), "app", "db")
        assert result.reachable is False
        assert result.shared_networks == ()
        assert "no shared networks" in result.reason

    def test_source_not_found(self):
        b = _c("db")
        result = check_connectivity(_env(b), "ghost", "db")
        assert result.reachable is False
        assert "not found" in result.reason
        assert result.source == "ghost"

    def test_target_not_found(self):
        a = _c("app")
        result = check_connectivity(_env(a), "app", "ghost")
        assert result.reachable is False
        assert "not found" in result.reason
        assert result.target == "ghost"

    def test_host_network_source(self):
        a = _c("app", network_mode="host")
        b = _c("db", networks=(_net("backend"),))
        result = check_connectivity(_env(a, b), "app", "db")
        assert result.reachable is True
        assert "host network" in result.reason

    def test_host_network_target(self):
        a = _c("app", networks=(_net("frontend"),))
        b = _c("db", network_mode="host")
        result = check_connectivity(_env(a, b), "app", "db")
        assert result.reachable is True
        assert "host network" in result.reason

    def test_container_network_mode_by_id(self):
        db = _c("db", container_id="deadbeef1234567890", networks=(_net("backend"),))
        sidecar = _c("sidecar", network_mode="container:deadbeef1234567890")
        result = check_connectivity(_env(db, sidecar), "sidecar", "db")
        assert result.reachable is True
        assert "shares network stack" in result.reason

    def test_container_network_mode_short_id(self):
        db = _c("db", container_id="deadbeef1234567890")
        sidecar = _c("sidecar", network_mode="container:deadbeef1234")
        result = check_connectivity(_env(db, sidecar), "sidecar", "db")
        assert result.reachable is True

    def test_container_network_mode_reverse(self):
        app = _c("app", container_id="abc123def456")
        sidecar = _c("sidecar", network_mode="container:abc123def456")
        result = check_connectivity(_env(app, sidecar), "app", "sidecar")
        assert result.reachable is True
        assert "shares network stack" in result.reason

    def test_no_networks_no_special_mode(self):
        a = _c("app")
        b = _c("db")
        result = check_connectivity(_env(a, b), "app", "db")
        assert result.reachable is False

    def test_result_is_frozen_dataclass(self):
        a = _c("app", networks=(_net("net1"),))
        b = _c("db", networks=(_net("net1"),))
        result = check_connectivity(_env(a, b), "app", "db")
        assert result.source == "app"
        assert result.target == "db"
        assert isinstance(result, ConnectivityResult)

    def test_host_network_takes_precedence_over_shared(self):
        """Host mode is checked before shared networks."""
        a = _c("app", network_mode="host", networks=(_net("net1"),))
        b = _c("db", networks=(_net("net1"),))
        result = check_connectivity(_env(a, b), "app", "db")
        assert result.reachable is True
        assert "host" in result.reason
        # shared_networks not populated because host mode short-circuits
        assert result.shared_networks == ()


class TestCheckAllConnectivity:
    def test_all_pairs(self):
        a = _c("app", networks=(_net("net1"),))
        b = _c("db", networks=(_net("net1"),))
        c = _c("cache", networks=(_net("net2"),))
        results = check_all_connectivity(_env(a, b, c))
        assert len(results) == 3
        pairs = {(r.source, r.target) for r in results}
        assert ("app", "cache") in pairs
        assert ("app", "db") in pairs
        assert ("cache", "db") in pairs

    def test_single_container(self):
        results = check_all_connectivity(_env(_c("app")))
        assert results == []

    def test_empty_environment(self):
        results = check_all_connectivity(_env())
        assert results == []

    def test_reachability_mixed(self):
        a = _c("app", networks=(_net("frontend"),))
        b = _c("api", networks=(_net("frontend"), _net("backend")))
        c = _c("db", networks=(_net("backend"),))
        results = check_all_connectivity(_env(a, b, c))

        by_pair = {(r.source, r.target): r for r in results}
        assert by_pair[("api", "app")].reachable is True
        assert by_pair[("api", "db")].reachable is True
        assert by_pair[("app", "db")].reachable is False
