"""Tests for roustabout collector."""

from unittest.mock import MagicMock

from roustabout.collector import collect


def _make_minimal_container(*, name="/test", env=(), ports=None):
    """Build a bare-minimum mock container for edge case tests."""
    container = MagicMock()
    container.name = name.lstrip("/")
    container.short_id = "abc123"
    container.status = "running"
    container.image.tags = ["img:latest"]
    container.image.id = "sha256:123"
    container.image.attrs = {"RepoDigests": []}
    container.attrs = {
        "Id": "abc123" + "0" * 58,
        "Name": name,
        "State": {"Status": "running", "StartedAt": "", "OOMKilled": False},
        "Created": "",
        "Config": {
            "Image": "img:latest",
            "Env": list(env),
            "Labels": {},
            "Cmd": None,
            "Entrypoint": None,
        },
        "NetworkSettings": {"Ports": ports or {}, "Networks": {}},
        "Mounts": [],
        "RestartCount": 0,
    }
    return container


def _make_client(*containers):
    """Wrap mock containers in a mock DockerClient."""
    client = MagicMock()
    client.containers.list.return_value = list(containers)
    client.version.return_value = {"Version": "25.0"}
    return client


class TestCollectTopLevel:
    def test_environment_metadata(self, mock_docker_client):
        env = collect(mock_docker_client)
        assert env.docker_version == "25.0.3"
        assert len(env.containers) == 4
        assert "T" in env.generated_at

    def test_containers_sorted_by_name(self, mock_docker_client):
        env = collect(mock_docker_client)
        names = [c.name for c in env.containers]
        assert names == sorted(names)


class TestContainerFields:
    def test_nginx_all_fields(self, mock_docker_client):
        """Comprehensive check of a fully-populated container."""
        env = collect(mock_docker_client)
        nginx = next(c for c in env.containers if c.name == "nginx-proxy")
        assert nginx.id == "abc123def4"
        assert nginx.status == "running"
        assert nginx.image == "nginx:1.25-alpine"
        assert nginx.image_digest == "nginx@sha256:deadbeef1234567890abcdef"
        assert nginx.health == "healthy"
        assert nginx.compose_project == "webstack"
        assert nginx.compose_service == "nginx"
        assert nginx.compose_config_files == "/opt/webstack/docker-compose.yml"
        assert nginx.oom_killed is False

    def test_name_strips_leading_slash(self, mock_docker_client):
        env = collect(mock_docker_client)
        for c in env.containers:
            assert not c.name.startswith("/")

    def test_name_with_leading_slash_in_name_attr(self):
        """Coverage: container.name retains leading slash (defensive strip)."""
        container = _make_minimal_container(name="/slash-test")
        container.name = "/slash-test"  # override the lstrip in helper
        client = _make_client(container)
        env = collect(client)
        assert env.containers[0].name == "slash-test"


class TestPorts:
    def test_ports_sorted_by_container_port(self, mock_docker_client):
        env = collect(mock_docker_client)
        nginx = next(c for c in env.containers if c.name == "nginx-proxy")
        assert len(nginx.ports) == 2
        assert nginx.ports[0].container_port == 80
        assert nginx.ports[0].host_port == "8080"
        assert nginx.ports[1].container_port == 443

    def test_empty_ports(self, mock_docker_client):
        env = collect(mock_docker_client)
        watchtower = next(c for c in env.containers if c.name == "watchtower")
        assert watchtower.ports == ()

    def test_null_bindings_skipped(self):
        """Coverage: exposed port with no host binding (value is None)."""
        container = _make_minimal_container(
            ports={"8080/tcp": None, "9090/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9090"}]}
        )
        client = _make_client(container)
        env = collect(client)
        assert len(env.containers[0].ports) == 1
        assert env.containers[0].ports[0].container_port == 9090


class TestMounts:
    def test_mounts_sorted_with_correct_types(self, mock_docker_client):
        env = collect(mock_docker_client)
        nginx = next(c for c in env.containers if c.name == "nginx-proxy")
        assert len(nginx.mounts) == 2
        assert nginx.mounts[0].destination == "/etc/nginx/nginx.conf"
        assert nginx.mounts[0].type == "bind"
        assert nginx.mounts[1].destination == "/var/log/nginx"
        assert nginx.mounts[1].type == "volume"

    def test_empty_mounts(self, mock_docker_client):
        env = collect(mock_docker_client)
        redis = next(c for c in env.containers if c.name == "redis-cache")
        assert redis.mounts == ()


class TestNetworks:
    def test_networks_sorted_by_name(self, mock_docker_client):
        env = collect(mock_docker_client)
        nginx = next(c for c in env.containers if c.name == "nginx-proxy")
        assert len(nginx.networks) == 2
        assert nginx.networks[0].name == "backend"
        assert nginx.networks[1].name == "frontend"

    def test_aliases_present(self, mock_docker_client):
        env = collect(mock_docker_client)
        nginx = next(c for c in env.containers if c.name == "nginx-proxy")
        frontend = next(n for n in nginx.networks if n.name == "frontend")
        assert set(frontend.aliases) == {"nginx", "proxy"}

    def test_null_aliases_become_empty_tuple(self, mock_docker_client):
        env = collect(mock_docker_client)
        nginx = next(c for c in env.containers if c.name == "nginx-proxy")
        backend = next(n for n in nginx.networks if n.name == "backend")
        assert backend.aliases == ()


class TestEnvironmentVars:
    def test_env_parsed_and_sorted(self, mock_docker_client):
        env = collect(mock_docker_client)
        nginx = next(c for c in env.containers if c.name == "nginx-proxy")
        env_dict = dict(nginx.env)
        assert env_dict["NGINX_HOST"] == "example.com"
        assert env_dict["SECRET_KEY"] == "hunter2"
        keys = [k for k, _ in nginx.env]
        assert keys == sorted(keys)

    def test_equals_in_value_preserved(self):
        """Partition on first = so values with = are kept intact."""
        container = _make_minimal_container(env=["CONNECTION=host=db;port=5432;password=secret"])
        client = _make_client(container)
        result = collect(client)
        assert dict(result.containers[0].env)["CONNECTION"] == "host=db;port=5432;password=secret"

    def test_env_entry_without_equals(self):
        """Coverage: malformed env entry with no = sign."""
        container = _make_minimal_container(env=["BARE_FLAG"])
        client = _make_client(container)
        result = collect(client)
        assert ("BARE_FLAG", "") in result.containers[0].env


class TestHealthAndDigestEdgeCases:
    def test_missing_health_key(self, mock_docker_client):
        env = collect(mock_docker_client)
        watchtower = next(c for c in env.containers if c.name == "watchtower")
        assert watchtower.health is None

    def test_empty_repo_digests(self, mock_docker_client):
        env = collect(mock_docker_client)
        watchtower = next(c for c in env.containers if c.name == "watchtower")
        assert watchtower.image_digest is None


class TestComposeLabels:
    def test_compose_metadata_extracted(self, mock_docker_client):
        env = collect(mock_docker_client)
        nginx = next(c for c in env.containers if c.name == "nginx-proxy")
        assert nginx.compose_project == "webstack"
        assert nginx.compose_service == "nginx"
        assert nginx.compose_config_files == "/opt/webstack/docker-compose.yml"

    def test_no_compose_labels(self, mock_docker_client):
        env = collect(mock_docker_client)
        watchtower = next(c for c in env.containers if c.name == "watchtower")
        assert watchtower.compose_project is None
        assert watchtower.compose_service is None
        assert watchtower.compose_config_files is None


class TestOOMKilled:
    def test_oom_killed_true(self, mock_docker_client):
        env = collect(mock_docker_client)
        redis = next(c for c in env.containers if c.name == "redis-cache")
        assert redis.oom_killed is True


class TestDeletedImage:
    """S3: container.image can be None when the image has been deleted."""

    def test_deleted_image_uses_config_fallback(self):
        container = _make_minimal_container(name="/deleted-img")
        container.image = None  # simulate deleted image
        client = _make_client(container)
        env = collect(client)
        c = env.containers[0]
        assert c.image == "img:latest"  # falls back to Config.Image
        assert c.image_id == "unknown"
        assert c.image_digest is None


class TestMalformedPort:
    def test_malformed_port_key_skipped(self):
        container = _make_minimal_container(
            ports={
                "notaport/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9999"}],
                "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
            }
        )
        client = _make_client(container)
        env = collect(client)
        assert len(env.containers[0].ports) == 1
        assert env.containers[0].ports[0].container_port == 80


class TestMalformedHealth:
    def test_health_dict_without_status_key(self):
        container = _make_minimal_container()
        container.attrs["State"]["Health"] = {}  # Health present but no Status
        client = _make_client(container)
        env = collect(client)
        assert env.containers[0].health is None


class TestContainerErrorHandling:
    def test_container_error_skipped_with_warning(self):
        good = _make_minimal_container(name="/good")
        bad = MagicMock()
        bad.name = "bad"
        bad.attrs = None  # will cause AttributeError on .get()

        client = _make_client(good, bad)
        env = collect(client)
        assert len(env.containers) == 1
        assert env.containers[0].name == "good"
        assert len(env.warnings) == 1
        assert "bad" in env.warnings[0]


class TestContainerFilter:
    def test_filter_by_name(self):
        a = _make_minimal_container(name="/alpha")
        b = _make_minimal_container(name="/bravo")
        c = _make_minimal_container(name="/charlie")
        client = _make_client(a, b, c)
        env = collect(client, containers=["alpha", "charlie"])
        names = [c.name for c in env.containers]
        assert names == ["alpha", "charlie"]

    def test_none_collects_all(self):
        a = _make_minimal_container(name="/alpha")
        b = _make_minimal_container(name="/bravo")
        client = _make_client(a, b)
        env = collect(client, containers=None)
        assert len(env.containers) == 2

    def test_empty_list_collects_none(self):
        a = _make_minimal_container(name="/alpha")
        client = _make_client(a)
        env = collect(client, containers=[])
        assert len(env.containers) == 0

    def test_nonexistent_name_ignored(self):
        a = _make_minimal_container(name="/alpha")
        client = _make_client(a)
        env = collect(client, containers=["nonexistent"])
        assert len(env.containers) == 0
