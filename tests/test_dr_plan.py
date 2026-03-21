"""Tests for DR plan generation.

Covers E5 S5.1.1-S5.1.2: disaster recovery document from running state,
dependency ordering, external dependency warnings, backup checklist.
"""

from __future__ import annotations

import pytest

from roustabout.models import (
    HealthcheckConfig,
    MountInfo,
    NetworkMembership,
    PortBinding,
    make_container,
    make_environment,
)

# Fixtures


@pytest.fixture
def simple_container():
    return make_container(
        name="nginx",
        id="abc123def456",
        status="running",
        image="nginx:1.25-alpine",
        image_id="sha256:abc123",
        ports=[PortBinding(80, "tcp", "0.0.0.0", "8080")],
        networks=[NetworkMembership("frontend", "172.18.0.2", ())],
        env=[("NGINX_HOST", "example.com"), ("SECRET_KEY", "[REDACTED]")],
        restart_policy="unless-stopped",
    )


@pytest.fixture
def simple_env(simple_container):
    return make_environment(
        containers=[simple_container],
        generated_at="2026-03-17T12:00:00Z",
        docker_version="25.0.3",
    )


@pytest.fixture
def multi_container_env():
    """Environment with dependencies: app depends on db via shared network."""
    db = make_container(
        name="postgres",
        id="db123",
        status="running",
        image="postgres:16",
        image_id="sha256:db123",
        ports=[PortBinding(5432, "tcp", "127.0.0.1", "5432")],
        networks=[NetworkMembership("backend", "172.18.1.2", ())],
        env=[("POSTGRES_PASSWORD", "[REDACTED]"), ("POSTGRES_DB", "myapp")],
        mounts=[
            MountInfo("/var/lib/postgresql/data", "/data/postgres", "rw", "bind"),
        ],
        restart_policy="always",
    )
    redis = make_container(
        name="redis",
        id="redis123",
        status="running",
        image="redis:7-alpine",
        image_id="sha256:redis123",
        networks=[NetworkMembership("backend", "172.18.1.3", ())],
        restart_policy="unless-stopped",
    )
    app = make_container(
        name="myapp",
        id="app123",
        status="running",
        image="ghcr.io/myorg/myapp:v2.1.0",
        image_id="sha256:app123",
        ports=[PortBinding(8000, "tcp", "0.0.0.0", "8000")],
        networks=[
            NetworkMembership("frontend", "172.18.0.3", ()),
            NetworkMembership("backend", "172.18.1.4", ()),
        ],
        env=[
            ("DATABASE_URL", "postgres://myapp:[REDACTED]@postgres:5432/myapp"),
            ("REDIS_URL", "redis://redis:6379"),
        ],
        restart_policy="unless-stopped",
        compose_project="myapp",
        compose_service="web",
    )
    return make_environment(
        containers=[db, redis, app],
        generated_at="2026-03-17T12:00:00Z",
        docker_version="25.0.3",
    )


# Document structure tests


class TestDRPlanStructure:
    """The generated document has the expected sections."""

    def test_has_title(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "# Disaster Recovery Plan" in result

    def test_has_timestamp(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "2026-03-17T12:00:00Z" in result

    def test_has_container_count(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "1 container" in result.lower() or "Containers: 1" in result

    def test_has_prerequisites(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "## Prerequisites" in result

    def test_has_restore_order(self, multi_container_env):
        from roustabout.dr_plan import generate

        result = generate(multi_container_env)
        assert "## Restore Order" in result

    def test_container_section_exists(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "nginx" in result
        assert "nginx:1.25-alpine" in result

    def test_actionable_without_roustabout(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "docker" in result.lower()
        assert "roustabout" not in result.lower()


# Docker run command generation


class TestRunCommand:
    """docker run commands are correct for each container configuration."""

    def test_basic_run_command(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "docker run -d" in result
        assert "--name" in result
        assert "nginx:1.25-alpine" in result

    def test_port_mapping(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "-p 8080:80/tcp" in result or "-p 8080:80" in result

    def test_restart_policy(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "--restart unless-stopped" in result

    def test_env_vars_included(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "NGINX_HOST" in result
        assert "SECRET_KEY" in result

    def test_bind_mount(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="db",
            id="db1",
            status="running",
            image="postgres:16",
            image_id="sha256:db1",
            mounts=[
                MountInfo("/var/lib/postgresql/data", "/data/postgres", "rw", "bind"),
            ],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "-v" in result
        assert "/data/postgres" in result
        assert "/var/lib/postgresql/data" in result

    def test_named_volume(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="db",
            id="db1",
            status="running",
            image="postgres:16",
            image_id="sha256:db1",
            mounts=[
                MountInfo("/var/lib/postgresql/data", "pgdata", "rw", "volume"),
            ],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "pgdata" in result

    def test_network_in_command(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "--network" in result
        assert "frontend" in result

    def test_multi_network_additional_connect(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="app1",
            status="running",
            image="app:latest",
            image_id="sha256:app1",
            networks=[
                NetworkMembership("frontend", "172.18.0.2", ()),
                NetworkMembership("backend", "172.18.1.2", ()),
            ],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "docker network connect" in result

    def test_host_network_mode(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="monitor",
            id="mon1",
            status="running",
            image="prom/node-exporter:latest",
            image_id="sha256:mon1",
            network_mode="host",
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--network host" in result

    def test_container_network_mode(self):
        from roustabout.dr_plan import generate

        sidecar = make_container(
            name="sidecar",
            id="side1",
            status="running",
            image="sidecar:latest",
            image_id="sha256:side1",
            network_mode="container:main123",
        )
        main = make_container(
            name="main",
            id="main123",
            status="running",
            image="main:latest",
            image_id="sha256:main123",
        )
        env = make_environment(
            containers=[sidecar, main], generated_at="now", docker_version="25.0"
        )
        result = generate(env)
        assert "--network container:" in result

    def test_privileged(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="dind",
            id="d1",
            status="running",
            image="docker:dind",
            image_id="sha256:d1",
            privileged=True,
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--privileged" in result

    def test_capabilities(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="net",
            id="n1",
            status="running",
            image="net:latest",
            image_id="sha256:n1",
            cap_add=["NET_ADMIN"],
            cap_drop=["ALL"],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--cap-add NET_ADMIN" in result
        assert "--cap-drop ALL" in result

    def test_read_only(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="secure",
            id="s1",
            status="running",
            image="app:latest",
            image_id="sha256:s1",
            read_only=True,
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--read-only" in result

    def test_user(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            user="1000:1000",
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--user" in result
        assert "1000:1000" in result

    def test_devices(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="gpu",
            id="g1",
            status="running",
            image="nvidia:latest",
            image_id="sha256:g1",
            devices=["/dev/dri:/dev/dri"],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--device" in result
        assert "/dev/dri" in result

    def test_tmpfs(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            tmpfs=["/tmp:size=100m"],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--tmpfs" in result
        assert "/tmp" in result

    def test_dns(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            dns=["8.8.8.8", "1.1.1.1"],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--dns" in result
        assert "8.8.8.8" in result

    def test_init(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            init=True,
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--init" in result

    def test_mem_limit(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            mem_limit=536870912,
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--memory" in result

    def test_hostname(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            hostname="myhost",
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--hostname" in result
        assert "myhost" in result

    def test_pid_mode(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="debug",
            id="d1",
            status="running",
            image="debug:latest",
            image_id="sha256:d1",
            pid_mode="host",
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--pid host" in result

    def test_command_and_entrypoint(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            entrypoint=["/usr/bin/entrypoint.sh"],
            command=["--config", "/etc/app.conf"],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--entrypoint" in result
        assert "/usr/bin/entrypoint.sh" in result
        assert "--config" in result

    def test_multi_element_entrypoint(self):
        """Multi-element entrypoint: first is --entrypoint, rest after image."""
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            entrypoint=["/bin/sh", "-c", "echo hello"],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--entrypoint /bin/sh" in result
        # -c and echo hello should appear AFTER the image
        image_pos = result.index("app:latest")
        assert result.index("-c", image_pos) > image_pos

    def test_runtime(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="gpu",
            id="g1",
            status="running",
            image="nvidia:latest",
            image_id="sha256:g1",
            runtime="nvidia",
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--runtime nvidia" in result

    def test_shm_size(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="browser",
            id="b1",
            status="running",
            image="selenium:latest",
            image_id="sha256:b1",
            shm_size=2147483648,
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--shm-size 2g" in result

    def test_security_opt(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            security_opt=["no-new-privileges"],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--security-opt" in result
        assert "no-new-privileges" in result

    def test_mem_limit_human_readable(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            mem_limit=536870912,
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "--memory 512m" in result


# Shell quoting


class TestShellQuoting:
    """Special characters in names/values are safely quoted."""

    def test_name_with_special_chars(self):
        from roustabout.dr_plan import _shell_quote

        assert "'" in _shell_quote("it's") or "\\" in _shell_quote("it's")

    def test_empty_string(self):
        from roustabout.dr_plan import _shell_quote

        result = _shell_quote("")
        assert result == "''"

    def test_safe_string_unchanged(self):
        from roustabout.dr_plan import _shell_quote

        # Simple safe strings may or may not be quoted
        result = _shell_quote("simple")
        assert "simple" in result


# Dependency ordering


class TestDependencyOrder:
    """Containers are ordered by dependencies for correct restore."""

    def test_container_network_mode_orders_dependency_first(self):
        from roustabout.dr_plan import _resolve_dependency_order

        main = make_container(
            name="main",
            id="main1",
            status="running",
            image="main:latest",
            image_id="sha256:main1",
        )
        sidecar = make_container(
            name="sidecar",
            id="side1",
            status="running",
            image="sidecar:latest",
            image_id="sha256:side1",
            network_mode="container:main1",
        )
        env = make_environment(
            containers=[sidecar, main], generated_at="now", docker_version="25.0"
        )
        ordered = _resolve_dependency_order(env)
        names = [c.name for c in ordered]
        assert names.index("main") < names.index("sidecar")

    def test_standalone_containers_sorted_alphabetically(self):
        from roustabout.dr_plan import _resolve_dependency_order

        b = make_container(
            name="bravo", id="b1", status="running", image="b:1", image_id="sha256:b"
        )
        a = make_container(
            name="alpha", id="a1", status="running", image="a:1", image_id="sha256:a"
        )
        env = make_environment(containers=[b, a], generated_at="now", docker_version="25.0")
        ordered = _resolve_dependency_order(env)
        names = [c.name for c in ordered]
        assert names == ["alpha", "bravo"]

    def test_cycle_does_not_crash(self):
        """Circular dependencies produce output without crashing."""
        from roustabout.dr_plan import _resolve_dependency_order

        a = make_container(
            name="a",
            id="a1",
            status="running",
            image="a:1",
            image_id="sha256:a",
            network_mode="container:b1",
        )
        b = make_container(
            name="b",
            id="b1",
            status="running",
            image="b:1",
            image_id="sha256:b",
            network_mode="container:a1",
        )
        env = make_environment(containers=[a, b], generated_at="now", docker_version="25.0")
        ordered = _resolve_dependency_order(env)
        assert len(ordered) == 2


# Network setup section


class TestNetworkSetup:
    """Networks used by multiple containers are listed for pre-creation."""

    def test_shared_network_in_setup(self, multi_container_env):
        from roustabout.dr_plan import generate

        result = generate(multi_container_env)
        assert "docker network create" in result
        assert "backend" in result

    def test_default_networks_excluded(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            network_mode="host",
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        # Should not tell user to create the "host" network
        lines = result.split("\n")
        create_lines = [ln for ln in lines if "docker network create" in ln and "host" in ln]
        assert len(create_lines) == 0


# External dependency warnings (S5.1.2)


class TestExternalWarnings:
    """DR plan warns about data not captured in Docker inspect."""

    def test_locally_built_image_warning(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="custom",
            id="c1",
            status="running",
            image="sha256:abc123def456789",
            image_id="sha256:abc123def456789",
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "cannot be pulled" in result.lower() or "local" in result.lower()

    def test_compose_working_dir_noted(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            compose_project="myapp",
            labels=[
                ("com.docker.compose.project.working_dir", "/home/user/myapp"),
            ],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "/home/user/myapp" in result

    def test_anonymous_volume_warning(self):
        from roustabout.dr_plan import generate

        anon_hash = "a" * 64
        c = make_container(
            name="db",
            id="db1",
            status="running",
            image="postgres:16",
            image_id="sha256:db1",
            mounts=[
                # source=volume name (64-char hash for anonymous), destination=mount path
                MountInfo(anon_hash, "/var/lib/postgresql/data", "rw", "volume"),
            ],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "anonymous" in result.lower()


# Backup checklist (S5.1.2)


class TestBackupChecklist:
    """Backup checklist lists all host paths that need preservation."""

    def test_bind_mounts_in_checklist(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            mounts=[
                # MountInfo(source, destination, mode, type)
                # source = host path for bind mounts
                MountInfo("/srv/app/data", "/app/data", "rw", "bind"),
                MountInfo("/srv/app/config", "/app/config", "ro", "bind"),
            ],
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "## Backup Checklist" in result
        assert "/srv/app/data" in result
        assert "/srv/app/config" in result

    def test_checklist_deduplicated(self):
        from roustabout.dr_plan import generate

        c1 = make_container(
            name="app1",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            mounts=[MountInfo("/shared/data", "/data", "rw", "bind")],
        )
        c2 = make_container(
            name="app2",
            id="a2",
            status="running",
            image="app:latest",
            image_id="sha256:a2",
            mounts=[MountInfo("/shared/data", "/data", "rw", "bind")],
        )
        env = make_environment(containers=[c1, c2], generated_at="now", docker_version="25.0")
        result = generate(env)
        # Count occurrences of the path in the checklist section only
        checklist_start = result.index("## Backup Checklist")
        checklist = result[checklist_start:]
        assert checklist.count("/shared/data") == 1


# Init container detection (S5.1.1 edge case)


class TestInitContainerDetection:
    """Exited containers with no restart policy are flagged as init containers."""

    def test_init_container_flagged(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="migrate",
            id="m1",
            status="exited",
            image="app:latest",
            image_id="sha256:m1",
            restart_policy=None,
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "ran once" in result.lower() or "init" in result.lower()


# Post-start verification


class TestPostStartVerification:
    """Each container has verification steps."""

    def test_basic_verification(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "docker ps" in result

    def test_healthcheck_verification(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="app:latest",
            image_id="sha256:a1",
            healthcheck=HealthcheckConfig(
                test=("CMD-SHELL", "curl -f http://localhost/health"),
                interval_ns=30_000_000_000,
                timeout_ns=10_000_000_000,
                retries=3,
                start_period_ns=5_000_000_000,
            ),
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "Health" in result or "health" in result


# Empty environment


class TestEmptyEnvironment:
    """Edge case: no containers."""

    def test_empty_env_produces_valid_output(self):
        from roustabout.dr_plan import generate

        env = make_environment(containers=[], generated_at="now", docker_version="25.0")
        result = generate(env)
        assert "# Disaster Recovery Plan" in result
        assert "0 container" in result.lower() or "no containers" in result.lower()


# Strip versions (#9)


class TestStripImageVersion:
    """_strip_image_version removes tags and digests from image references."""

    def test_simple_tag(self):
        from roustabout.dr_plan import _strip_image_version

        assert _strip_image_version("nginx:1.25-alpine") == "nginx"

    def test_registry_with_tag(self):
        from roustabout.dr_plan import _strip_image_version

        assert _strip_image_version("ghcr.io/org/app:v2.1.0") == "ghcr.io/org/app"

    def test_registry_with_port_and_tag(self):
        from roustabout.dr_plan import _strip_image_version

        assert _strip_image_version("localhost:5000/myapp:latest") == "localhost:5000/myapp"

    def test_digest_reference(self):
        from roustabout.dr_plan import _strip_image_version

        result = _strip_image_version("nginx@sha256:abc123def456")
        assert result == "nginx"

    def test_no_tag(self):
        from roustabout.dr_plan import _strip_image_version

        assert _strip_image_version("nginx") == "nginx"

    def test_registry_no_tag(self):
        from roustabout.dr_plan import _strip_image_version

        assert _strip_image_version("ghcr.io/org/app") == "ghcr.io/org/app"

    def test_latest_tag(self):
        from roustabout.dr_plan import _strip_image_version

        assert _strip_image_version("redis:latest") == "redis"


class TestStripVersionsFlag:
    """generate(strip_versions=True) removes version tags from output."""

    def test_image_tags_removed_from_header(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env, strip_versions=True)
        assert "**Image:** nginx" in result
        assert "nginx:1.25-alpine" not in result

    def test_image_tags_removed_from_run_command(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env, strip_versions=True)
        # The docker run command should reference the image without tag
        lines = result.split("\n")
        run_lines = [ln for ln in lines if "docker run" in ln or ln.strip().startswith("nginx")]
        # Should find "nginx" without ":1.25-alpine" in the run command
        for line in run_lines:
            assert "1.25-alpine" not in line

    def test_default_preserves_tags(self, simple_env):
        from roustabout.dr_plan import generate

        result = generate(simple_env)
        assert "nginx:1.25-alpine" in result

    def test_strip_versions_with_registry_port(self):
        from roustabout.dr_plan import generate

        c = make_container(
            name="app",
            id="a1",
            status="running",
            image="localhost:5000/myapp:v3.2.1",
            image_id="sha256:a1",
        )
        env = make_environment(containers=[c], generated_at="now", docker_version="25.0")
        result = generate(env, strip_versions=True)
        assert "localhost:5000/myapp" in result
        assert "v3.2.1" not in result
