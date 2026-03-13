"""Tests for the compose generator."""

from io import StringIO

from ruamel.yaml import YAML

from roustabout.generator import generate
from roustabout.models import (
    HealthcheckConfig,
    MountInfo,
    NetworkMembership,
    PortBinding,
    make_container,
    make_environment,
)


def _parse_yaml(text: str) -> dict:
    """Parse YAML string into dict for assertions."""
    yaml = YAML()
    return yaml.load(StringIO(text))


def _env(*containers, **kwargs):
    """Build a DockerEnvironment from containers."""
    return make_environment(
        containers=list(containers),
        generated_at="2026-03-12T00:00:00Z",
        docker_version="25.0.3",
        **kwargs,
    )


def _container(**kwargs):
    """Build a container with sensible defaults."""
    defaults = dict(
        name="test-app",
        id="abc123",
        status="running",
        image="nginx:1.25",
        image_id="sha256:abc",
    )
    defaults.update(kwargs)
    return make_container(**defaults)


class TestBasicGeneration:
    def test_single_container(self):
        env = _env(_container())
        result = generate(env)
        doc = _parse_yaml(result)
        assert "services" in doc
        assert "test-app" in doc["services"]
        assert doc["services"]["test-app"]["image"] == "nginx:1.25"

    def test_container_name_preserved(self):
        env = _env(_container(name="my-nginx"))
        doc = _parse_yaml(generate(env))
        svc = doc["services"]["my-nginx"]
        assert svc["container_name"] == "my-nginx"

    def test_empty_environment(self):
        env = _env()
        result = generate(env)
        assert "No running containers" in result

    def test_stopped_containers_excluded_by_default(self):
        env = _env(
            _container(name="running", status="running"),
            _container(name="stopped", status="exited"),
        )
        doc = _parse_yaml(generate(env))
        assert "running" in doc["services"]
        assert "stopped" not in doc["services"]

    def test_stopped_containers_included_with_flag(self):
        env = _env(
            _container(name="running", status="running"),
            _container(name="stopped", status="exited"),
        )
        doc = _parse_yaml(generate(env, include_stopped=True))
        assert "running" in doc["services"]
        assert "stopped" in doc["services"]


class TestPorts:
    def test_basic_port(self):
        env = _env(
            _container(
                ports=[PortBinding(80, "tcp", "0.0.0.0", "8080")],
            )
        )
        doc = _parse_yaml(generate(env))
        assert "8080:80" in doc["services"]["test-app"]["ports"]

    def test_localhost_port(self):
        env = _env(
            _container(
                ports=[PortBinding(5432, "tcp", "127.0.0.1", "5432")],
            )
        )
        doc = _parse_yaml(generate(env))
        assert "127.0.0.1:5432:5432" in doc["services"]["test-app"]["ports"]

    def test_udp_port(self):
        env = _env(
            _container(
                ports=[PortBinding(53, "udp", "0.0.0.0", "53")],
            )
        )
        doc = _parse_yaml(generate(env))
        assert "53:53/udp" in doc["services"]["test-app"]["ports"]

    def test_no_ports_omits_section(self):
        env = _env(_container(ports=[]))
        doc = _parse_yaml(generate(env))
        assert "ports" not in doc["services"]["test-app"]


class TestVolumes:
    def test_bind_mount(self):
        env = _env(
            _container(
                mounts=[MountInfo("/host/path", "/container/path", "rw", "bind")],
            )
        )
        doc = _parse_yaml(generate(env))
        assert "/host/path:/container/path" in doc["services"]["test-app"]["volumes"]

    def test_bind_mount_readonly(self):
        env = _env(
            _container(
                mounts=[MountInfo("/host/conf", "/etc/app.conf", "ro", "bind")],
            )
        )
        doc = _parse_yaml(generate(env))
        assert "/host/conf:/etc/app.conf:ro" in doc["services"]["test-app"]["volumes"]

    def test_named_volume(self):
        env = _env(
            _container(
                mounts=[MountInfo("pgdata", "/var/lib/postgresql/data", "rw", "volume")],
            )
        )
        doc = _parse_yaml(generate(env))
        assert "pgdata:/var/lib/postgresql/data" in doc["services"]["test-app"]["volumes"]
        assert "pgdata" in doc["volumes"]
        assert doc["volumes"]["pgdata"]["external"] is True

    def test_no_volumes_omits_section(self):
        env = _env(_container(mounts=[]))
        doc = _parse_yaml(generate(env))
        assert "volumes" not in doc["services"]["test-app"]
        assert "volumes" not in doc


class TestNetworks:
    def test_custom_network(self):
        env = _env(
            _container(
                networks=[NetworkMembership("frontend", "172.18.0.2", ("web",))],
            )
        )
        doc = _parse_yaml(generate(env))
        assert "frontend" in doc["services"]["test-app"]["networks"]
        assert "frontend" in doc["networks"]
        assert doc["networks"]["frontend"]["external"] is True

    def test_bridge_network_excluded(self):
        env = _env(
            _container(
                networks=[NetworkMembership("bridge", "172.17.0.2", ())],
            )
        )
        doc = _parse_yaml(generate(env))
        assert "networks" not in doc["services"]["test-app"]

    def test_network_aliases(self):
        env = _env(
            _container(
                name="postgres",
                id="abc123",
                networks=[
                    NetworkMembership("backend", "172.18.0.3", ("db", "postgres", "abc123")),
                ],
            )
        )
        doc = _parse_yaml(generate(env))
        net_config = doc["services"]["postgres"]["networks"]["backend"]
        # Should exclude container name and ID from aliases
        assert "db" in net_config["aliases"]
        assert "postgres" not in net_config["aliases"]  # same as container name


class TestEnvironment:
    def test_env_vars(self):
        env = _env(
            _container(
                env=[("DB_HOST", "localhost"), ("DB_PORT", "5432")],
            )
        )
        doc = _parse_yaml(generate(env))
        env_section = doc["services"]["test-app"]["environment"]
        assert env_section["DB_HOST"] == "localhost"
        assert env_section["DB_PORT"] == "5432"

    def test_no_env_omits_section(self):
        env = _env(_container(env=[]))
        doc = _parse_yaml(generate(env))
        assert "environment" not in doc["services"]["test-app"]


class TestRestartPolicy:
    def test_unless_stopped(self):
        env = _env(_container(restart_policy="unless-stopped"))
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["restart"] == "unless-stopped"

    def test_no_restart_omits(self):
        env = _env(_container(restart_policy="no"))
        doc = _parse_yaml(generate(env))
        assert "restart" not in doc["services"]["test-app"]

    def test_none_restart_omits(self):
        env = _env(_container(restart_policy=None))
        doc = _parse_yaml(generate(env))
        assert "restart" not in doc["services"]["test-app"]


class TestPrivileged:
    def test_privileged(self):
        env = _env(_container(privileged=True))
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["privileged"] is True

    def test_not_privileged_omits(self):
        env = _env(_container(privileged=False))
        doc = _parse_yaml(generate(env))
        assert "privileged" not in doc["services"]["test-app"]


class TestNetworkMode:
    def test_host_network(self):
        env = _env(_container(network_mode="host"))
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["network_mode"] == "host"

    def test_container_network_mode(self):
        env = _env(_container(network_mode="container:vpn"))
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["network_mode"] == "service:vpn"

    def test_bridge_omits(self):
        env = _env(_container(network_mode="bridge"))
        doc = _parse_yaml(generate(env))
        assert "network_mode" not in doc["services"]["test-app"]

    def test_compose_default_network_omits_with_matching_project(self):
        env = _env(_container(network_mode="myproject_default", compose_project="myproject"))
        doc = _parse_yaml(generate(env))
        assert "network_mode" not in doc["services"]["test-app"]

    def test_compose_default_network_kept_without_project(self):
        """Without compose_project, _default networks are kept."""
        env = _env(_container(network_mode="myproject_default"))
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["network_mode"] == "myproject_default"


class TestHostname:
    def test_explicit_hostname(self):
        env = _env(_container(hostname="myhost"))
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["hostname"] == "myhost"

    def test_auto_hostname_omits(self):
        # Hostname matches first 12 chars of container ID → auto-generated, omit
        env = _env(_container(id="396477d9ed48abcdef", hostname="396477d9ed48"))
        doc = _parse_yaml(generate(env))
        assert "hostname" not in doc["services"]["test-app"]

    def test_no_hostname_omits(self):
        env = _env(_container())
        doc = _parse_yaml(generate(env))
        assert "hostname" not in doc["services"]["test-app"]


class TestRuntime:
    def test_custom_runtime(self):
        env = _env(_container(runtime="nvidia"))
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["runtime"] == "nvidia"

    def test_runc_runtime_omits(self):
        env = _env(_container(runtime="runc"))
        doc = _parse_yaml(generate(env))
        assert "runtime" not in doc["services"]["test-app"]


class TestHealthcheck:
    def test_healthcheck_config(self):
        hc = HealthcheckConfig(
            test=("CMD-SHELL", "curl -f http://localhost/ || exit 1"),
            interval_ns=30_000_000_000,
            timeout_ns=10_000_000_000,
            retries=3,
            start_period_ns=30_000_000_000,
        )
        env = _env(_container(healthcheck=hc))
        doc = _parse_yaml(generate(env))
        hc_out = doc["services"]["test-app"]["healthcheck"]
        assert hc_out["test"] == "curl -f http://localhost/ || exit 1"
        assert hc_out["interval"] == "30s"
        assert hc_out["timeout"] == "10s"
        assert hc_out["retries"] == 3

    def test_no_healthcheck_omits(self):
        env = _env(_container(healthcheck=None))
        doc = _parse_yaml(generate(env))
        assert "healthcheck" not in doc["services"]["test-app"]


class TestCapabilities:
    def test_cap_add(self):
        env = _env(_container(cap_add=["NET_ADMIN", "SYS_TIME"]))
        doc = _parse_yaml(generate(env))
        assert "NET_ADMIN" in doc["services"]["test-app"]["cap_add"]
        assert "SYS_TIME" in doc["services"]["test-app"]["cap_add"]

    def test_no_caps_omits(self):
        env = _env(_container())
        doc = _parse_yaml(generate(env))
        assert "cap_add" not in doc["services"]["test-app"]


class TestDevices:
    def test_gpu_device(self):
        env = _env(_container(devices=["/dev/dri:/dev/dri:rwm"]))
        doc = _parse_yaml(generate(env))
        assert "/dev/dri:/dev/dri:rwm" in doc["services"]["test-app"]["devices"]


class TestResourceLimits:
    def test_memory_limit(self):
        env = _env(_container(mem_limit=536870912))  # 512MB
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["deploy"]["resources"]["limits"]["memory"] == "512M"

    def test_cpu_limit(self):
        env = _env(_container(cpus=1.5))
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["deploy"]["resources"]["limits"]["cpus"] == "1.5"


class TestLabels:
    def test_user_labels_included(self):
        env = _env(
            _container(
                labels=[("app.custom.version", "1.0")],
            )
        )
        doc = _parse_yaml(generate(env))
        assert doc["services"]["test-app"]["labels"]["app.custom.version"] == "1.0"

    def test_image_metadata_labels_excluded(self):
        """Image metadata labels (OCI, label-schema) are excluded."""
        env = _env(
            _container(
                labels=[
                    ("org.opencontainers.image.version", "1.0"),
                    ("org.label-schema.name", "test"),
                    ("custom.label", "value"),
                ],
            )
        )
        doc = _parse_yaml(generate(env))
        labels = doc["services"]["test-app"]["labels"]
        assert "org.opencontainers.image.version" not in labels
        assert "org.label-schema.name" not in labels
        assert "custom.label" in labels

    def test_compose_labels_excluded(self):
        env = _env(
            _container(
                labels=[
                    ("com.docker.compose.project", "webstack"),
                    ("custom.label", "value"),
                ],
            )
        )
        doc = _parse_yaml(generate(env))
        labels = doc["services"]["test-app"]["labels"]
        assert "com.docker.compose.project" not in labels
        assert "custom.label" in labels


class TestServiceNaming:
    def test_compose_service_name_used(self):
        env = _env(_container(compose_service="web"))
        doc = _parse_yaml(generate(env))
        assert "web" in doc["services"]

    def test_container_name_sanitized(self):
        env = _env(_container(name="my.app.container"))
        doc = _parse_yaml(generate(env))
        assert "my-app-container" in doc["services"]


class TestYamlOutput:
    def test_valid_yaml(self):
        """Generated output should be parseable YAML."""
        env = _env(
            _container(
                name="web",
                ports=[PortBinding(80, "tcp", "0.0.0.0", "8080")],
                mounts=[MountInfo("webdata", "/data", "rw", "volume")],
                networks=[NetworkMembership("frontend", "172.18.0.2", ())],
                env=[("NODE_ENV", "production")],
                restart_policy="unless-stopped",
            )
        )
        result = generate(env)
        doc = _parse_yaml(result)
        assert doc is not None
        assert "services" in doc

    def test_header_comment(self):
        env = _env(_container())
        result = generate(env)
        assert "Generated by roustabout" in result
        assert "WARNING" in result
        assert "secrets" in result.lower()
