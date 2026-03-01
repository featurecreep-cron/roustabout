"""Tests for roustabout data models."""

import pytest

from roustabout.models import (
    ContainerInfo,
    MountInfo,
    NetworkMembership,
    PortBinding,
    make_container,
    make_environment,
)


class TestFrozenDataclasses:
    """All model types are frozen — verify once per type."""

    def test_container_info_is_frozen(self):
        c = make_container(
            name="test", id="abc", status="running", image="img", image_id="sha256:123"
        )
        with pytest.raises(AttributeError):
            c.name = "other"

    def test_docker_environment_is_frozen(self):
        env = make_environment(
            containers=[], generated_at="2026-01-01T00:00:00Z", docker_version="25.0"
        )
        with pytest.raises(AttributeError):
            env.docker_version = "26.0"


class TestMakeContainerSorting:
    def test_sorts_ports_by_container_port_then_protocol(self):
        c = make_container(
            name="test",
            id="abc",
            status="running",
            image="img",
            image_id="sha256:123",
            ports=[
                PortBinding(container_port=443, protocol="tcp", host_ip="0.0.0.0", host_port="443"),
                PortBinding(container_port=53, protocol="udp", host_ip="0.0.0.0", host_port="53"),
                PortBinding(container_port=53, protocol="tcp", host_ip="0.0.0.0", host_port="53"),
                PortBinding(container_port=80, protocol="tcp", host_ip="0.0.0.0", host_port="80"),
            ],
        )
        assert [p.container_port for p in c.ports] == [53, 53, 80, 443]
        assert c.ports[0].protocol == "tcp"
        assert c.ports[1].protocol == "udp"

    def test_sorts_mounts_by_destination(self):
        c = make_container(
            name="test",
            id="abc",
            status="running",
            image="img",
            image_id="sha256:123",
            mounts=[
                MountInfo(source="b", destination="/z/data", mode="rw", type="volume"),
                MountInfo(source="a", destination="/a/conf", mode="ro", type="bind"),
            ],
        )
        assert [m.destination for m in c.mounts] == ["/a/conf", "/z/data"]

    def test_sorts_networks_by_name(self):
        c = make_container(
            name="test",
            id="abc",
            status="running",
            image="img",
            image_id="sha256:123",
            networks=[
                NetworkMembership(name="zebra", ip_address="10.0.0.1", aliases=()),
                NetworkMembership(name="alpha", ip_address="10.0.0.2", aliases=()),
            ],
        )
        assert [n.name for n in c.networks] == ["alpha", "zebra"]

    def test_sorts_env_and_labels_by_key(self):
        c = make_container(
            name="test",
            id="abc",
            status="running",
            image="img",
            image_id="sha256:123",
            env=[("ZEBRA", "1"), ("ALPHA", "2")],
            labels=[("z.label", "1"), ("a.label", "2")],
        )
        assert [k for k, _ in c.env] == ["ALPHA", "ZEBRA"]
        assert [k for k, _ in c.labels] == ["a.label", "z.label"]


class TestMakeContainerDefaults:
    def test_optional_fields_default_to_empty_or_none(self):
        c = make_container(
            name="test", id="abc", status="running", image="img", image_id="sha256:123"
        )
        assert c.ports == ()
        assert c.mounts == ()
        assert c.networks == ()
        assert c.env == ()
        assert c.labels == ()
        assert c.health is None
        assert c.compose_project is None
        assert c.restart_count == 0
        assert c.oom_killed is False


class TestMakeEnvironment:
    def test_sorts_containers_by_name(self):
        c1 = make_container(
            name="zebra", id="z", status="running", image="img", image_id="sha256:z"
        )
        c2 = make_container(
            name="alpha", id="a", status="running", image="img", image_id="sha256:a"
        )
        env = make_environment(
            containers=[c1, c2], generated_at="2026-01-01T00:00:00Z", docker_version="25.0"
        )
        assert [c.name for c in env.containers] == ["alpha", "zebra"]

    def test_warnings_defaults_to_empty_tuple(self):
        env = make_environment(
            containers=[], generated_at="2026-01-01T00:00:00Z", docker_version="25.0"
        )
        assert env.warnings == ()

    def test_warnings_passed_through(self):
        env = make_environment(
            containers=[],
            generated_at="2026-01-01T00:00:00Z",
            docker_version="25.0",
            warnings=["container 'foo' skipped: inspection failed"],
        )
        assert len(env.warnings) == 1
        assert "foo" in env.warnings[0]
