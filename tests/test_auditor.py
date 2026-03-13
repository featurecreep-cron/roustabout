"""Tests for the security auditor."""

from roustabout.audit_renderer import render_findings
from roustabout.auditor import (
    Finding,
    Severity,
    audit,
)
from roustabout.models import (
    MountInfo,
    NetworkMembership,
    PortBinding,
    make_container,
    make_environment,
)


def _env(**kwargs):
    """Build a minimal DockerEnvironment with one container."""
    defaults = dict(
        name="test-container",
        id="abc123",
        status="running",
        image="nginx:1.25",
        image_id="sha256:abc",
    )
    defaults.update(kwargs)
    container = make_container(**defaults)
    return make_environment(
        containers=[container],
        generated_at="2026-03-09T00:00:00Z",
        docker_version="25.0.3",
    )


def _find(findings, category):
    """Find first finding by category."""
    return next((f for f in findings if f.category == category), None)


def _find_all(findings, category):
    """Find all findings by category."""
    return [f for f in findings if f.category == category]


class TestDockerSocket:
    def test_socket_mount_detected(self):
        env = _env(
            mounts=[
                MountInfo(
                    source="/var/run/docker.sock",
                    destination="/var/run/docker.sock",
                    mode="rw",
                    type="bind",
                )
            ]
        )
        findings = audit(env)
        f = _find(findings, "docker-socket")
        assert f is not None
        assert f.severity == Severity.CRITICAL
        assert "Docker socket" in f.explanation

    def test_no_socket_no_finding(self):
        env = _env(mounts=[])
        findings = audit(env)
        assert _find(findings, "docker-socket") is None


class TestSecretsInEnv:
    def test_password_detected(self):
        env = _env(env=[("DB_PASSWORD", "supersecret"), ("NODE_ENV", "production")])
        findings = audit(env)
        f = _find(findings, "secrets-in-env")
        assert f is not None
        assert f.severity == Severity.WARNING
        assert "DB_PASSWORD" in f.explanation

    def test_empty_value_skipped(self):
        env = _env(env=[("DB_PASSWORD", "")])
        findings = audit(env)
        assert _find(findings, "secrets-in-env") is None

    def test_redacted_value_skipped(self):
        env = _env(env=[("DB_PASSWORD", "[REDACTED]")])
        findings = audit(env)
        assert _find(findings, "secrets-in-env") is None

    def test_url_key_skipped(self):
        env = _env(env=[("DATABASE_URL", "postgresql://localhost/mydb")])
        findings = audit(env)
        assert _find(findings, "secrets-in-env") is None

    def test_nonsensitive_key_clean(self):
        env = _env(env=[("NGINX_HOST", "example.com")])
        findings = audit(env)
        assert _find(findings, "secrets-in-env") is None

    def test_multiple_secrets_found(self):
        env = _env(
            env=[
                ("DB_PASSWORD", "secret1"),
                ("API_KEY", "key123"),
                ("NODE_ENV", "production"),
            ]
        )
        findings = audit(env)
        secrets = _find_all(findings, "secrets-in-env")
        assert len(secrets) == 2


class TestSensitivePortBinding:
    def test_postgres_on_all_interfaces(self):
        env = _env(
            image="postgres:16-alpine",
            ports=[
                PortBinding(
                    container_port=5432, protocol="tcp", host_ip="0.0.0.0", host_port="5432"
                )
            ],
        )
        findings = audit(env)
        f = _find(findings, "exposed-port")
        assert f is not None
        assert f.severity == Severity.INFO
        assert "5432" in f.explanation

    def test_postgres_on_localhost_ok(self):
        env = _env(
            image="postgres:16-alpine",
            ports=[
                PortBinding(
                    container_port=5432, protocol="tcp", host_ip="127.0.0.1", host_port="5432"
                )
            ],
        )
        findings = audit(env)
        assert _find(findings, "exposed-port") is None

    def test_nginx_on_all_interfaces_ok(self):
        env = _env(
            image="nginx:1.25",
            ports=[
                PortBinding(container_port=80, protocol="tcp", host_ip="0.0.0.0", host_port="80")
            ],
        )
        findings = audit(env)
        assert _find(findings, "exposed-port") is None

    def test_phpmyadmin_detected(self):
        env = _env(
            image="phpmyadmin:latest",
            ports=[
                PortBinding(container_port=80, protocol="tcp", host_ip="0.0.0.0", host_port="8080")
            ],
        )
        findings = audit(env)
        f = _find(findings, "exposed-port")
        assert f is not None


class TestNoHealthCheck:
    def test_running_no_health(self):
        env = _env(health=None)
        findings = audit(env)
        f = _find(findings, "no-healthcheck")
        assert f is not None
        assert f.severity == Severity.INFO

    def test_running_with_health(self):
        env = _env(health="healthy")
        findings = audit(env)
        assert _find(findings, "no-healthcheck") is None

    def test_stopped_no_health_skipped(self):
        env = _env(status="exited", health=None)
        findings = audit(env)
        assert _find(findings, "no-healthcheck") is None


class TestRunningAsRoot:
    def test_root_user_detected(self):
        env = _env(user=None)
        findings = audit(env)
        f = _find(findings, "running-as-root")
        assert f is not None
        assert f.severity == Severity.INFO

    def test_nonroot_user_clean(self):
        env = _env(user="1000:1000")
        findings = audit(env)
        assert _find(findings, "running-as-root") is None

    def test_root_with_socket_skipped(self):
        """Docker socket finding is critical and covers root access."""
        env = _env(
            user=None,
            mounts=[
                MountInfo(
                    source="/var/run/docker.sock",
                    destination="/var/run/docker.sock",
                    mode="rw",
                    type="bind",
                )
            ],
        )
        findings = audit(env)
        assert _find(findings, "running-as-root") is None
        assert _find(findings, "docker-socket") is not None

    def test_stopped_root_skipped(self):
        env = _env(status="exited", user=None)
        findings = audit(env)
        assert _find(findings, "running-as-root") is None


class TestRestartLoops:
    def test_high_restart_count(self):
        env = _env(restart_count=30)
        findings = audit(env)
        f = _find(findings, "restart-loop")
        assert f is not None
        assert f.severity == Severity.WARNING
        assert "30" in f.explanation

    def test_normal_restart_count(self):
        env = _env(restart_count=10)
        findings = audit(env)
        assert _find(findings, "restart-loop") is None

    def test_boundary_value_25(self):
        env = _env(restart_count=25)
        findings = audit(env)
        assert _find(findings, "restart-loop") is None

    def test_boundary_value_26(self):
        env = _env(restart_count=26)
        findings = audit(env)
        assert _find(findings, "restart-loop") is not None


class TestOOMKilled:
    def test_oom_killed_detected(self):
        env = _env(oom_killed=True)
        findings = audit(env)
        f = _find(findings, "oom-killed")
        assert f is not None
        assert f.severity == Severity.WARNING

    def test_no_oom_clean(self):
        env = _env(oom_killed=False)
        findings = audit(env)
        assert _find(findings, "oom-killed") is None


class TestFlatNetworking:
    def test_all_on_same_network(self):
        net = [NetworkMembership(name="app-net", ip_address="172.18.0.2", aliases=())]
        containers = [
            make_container(
                name=f"svc-{i}",
                id=f"id{i}",
                status="running",
                image="img:1",
                image_id="sha256:x",
                networks=net,
            )
            for i in range(5)
        ]
        env = make_environment(
            containers=containers,
            generated_at="2026-03-09T00:00:00Z",
            docker_version="25.0.3",
        )
        findings = audit(env)
        f = _find(findings, "flat-network")
        assert f is not None
        assert f.severity == Severity.INFO
        assert "5" in f.explanation

    def test_separate_networks_clean(self):
        c1 = make_container(
            name="web",
            id="id1",
            status="running",
            image="img:1",
            image_id="sha256:x",
            networks=[NetworkMembership(name="frontend", ip_address="172.18.0.2", aliases=())],
        )
        c2 = make_container(
            name="db",
            id="id2",
            status="running",
            image="img:1",
            image_id="sha256:x",
            networks=[NetworkMembership(name="backend", ip_address="172.19.0.2", aliases=())],
        )
        c3 = make_container(
            name="cache",
            id="id3",
            status="running",
            image="img:1",
            image_id="sha256:x",
            networks=[NetworkMembership(name="backend", ip_address="172.19.0.3", aliases=())],
        )
        env = make_environment(
            containers=[c1, c2, c3],
            generated_at="2026-03-09T00:00:00Z",
            docker_version="25.0.3",
        )
        findings = audit(env)
        assert _find(findings, "flat-network") is None

    def test_fewer_than_3_containers_skipped(self):
        net = [NetworkMembership(name="app-net", ip_address="172.18.0.2", aliases=())]
        containers = [
            make_container(
                name=f"svc-{i}",
                id=f"id{i}",
                status="running",
                image="img:1",
                image_id="sha256:x",
                networks=net,
            )
            for i in range(2)
        ]
        env = make_environment(
            containers=containers,
            generated_at="2026-03-09T00:00:00Z",
            docker_version="25.0.3",
        )
        findings = audit(env)
        assert _find(findings, "flat-network") is None


class TestNoRestartPolicy:
    def test_no_policy_detected(self):
        env = _env(restart_policy=None)
        findings = audit(env)
        f = _find(findings, "no-restart-policy")
        assert f is not None
        assert f.severity == Severity.INFO

    def test_policy_no_detected(self):
        env = _env(restart_policy="no")
        findings = audit(env)
        assert _find(findings, "no-restart-policy") is not None

    def test_unless_stopped_clean(self):
        env = _env(restart_policy="unless-stopped")
        findings = audit(env)
        assert _find(findings, "no-restart-policy") is None

    def test_stopped_container_skipped(self):
        env = _env(status="exited", restart_policy=None)
        findings = audit(env)
        assert _find(findings, "no-restart-policy") is None


class TestStaleImages:
    def test_latest_without_digest(self):
        env = _env(image="nginx:latest", image_digest=None)
        findings = audit(env)
        f = _find(findings, "stale-image")
        assert f is not None
        assert f.severity == Severity.INFO

    def test_latest_with_digest_clean(self):
        env = _env(image="nginx:latest", image_digest="nginx@sha256:abc123")
        findings = audit(env)
        assert _find(findings, "stale-image") is None

    def test_pinned_version_clean(self):
        env = _env(image="nginx:1.25-alpine")
        findings = audit(env)
        assert _find(findings, "stale-image") is None

    def test_stopped_latest_skipped(self):
        env = _env(status="exited", image="nginx:latest", image_digest=None)
        findings = audit(env)
        assert _find(findings, "stale-image") is None


class TestPrivilegedMode:
    def test_privileged_detected(self):
        env = _env(privileged=True)
        findings = audit(env)
        f = _find(findings, "privileged-mode")
        assert f is not None
        assert f.severity == Severity.CRITICAL
        assert "privileged mode" in f.explanation

    def test_not_privileged_clean(self):
        env = _env(privileged=False)
        findings = audit(env)
        assert _find(findings, "privileged-mode") is None


class TestSensitiveHostMounts:
    def test_etc_mount_detected(self):
        env = _env(
            mounts=[MountInfo(source="/etc", destination="/host-etc", mode="ro", type="bind")]
        )
        findings = audit(env)
        f = _find(findings, "sensitive-mount")
        assert f is not None
        assert f.severity == Severity.WARNING
        assert "/etc" in f.explanation

    def test_etc_localtime_safe(self):
        """Common timezone mount is excluded — not a security concern."""
        env = _env(
            mounts=[
                MountInfo(
                    source="/etc/localtime", destination="/etc/localtime", mode="ro", type="bind"
                )
            ]
        )
        findings = audit(env)
        assert _find(findings, "sensitive-mount") is None

    def test_etc_subdir_detected(self):
        """Non-safe /etc subdirectory is flagged."""
        env = _env(
            mounts=[
                MountInfo(source="/etc/shadow", destination="/etc/shadow", mode="ro", type="bind")
            ]
        )
        findings = audit(env)
        f = _find(findings, "sensitive-mount")
        assert f is not None

    def test_home_mount_detected(self):
        env = _env(mounts=[MountInfo(source="/home", destination="/data", mode="rw", type="bind")])
        findings = audit(env)
        f = _find(findings, "sensitive-mount")
        assert f is not None

    def test_root_home_detected(self):
        env = _env(mounts=[MountInfo(source="/root", destination="/root", mode="rw", type="bind")])
        findings = audit(env)
        f = _find(findings, "sensitive-mount")
        assert f is not None

    def test_docker_socket_not_duplicated(self):
        """Docker socket is caught by check #1, should not also appear as sensitive-mount."""
        env = _env(
            mounts=[
                MountInfo(
                    source="/var/run/docker.sock",
                    destination="/var/run/docker.sock",
                    mode="rw",
                    type="bind",
                )
            ]
        )
        findings = audit(env)
        assert _find(findings, "sensitive-mount") is None
        assert _find(findings, "docker-socket") is not None

    def test_volume_mount_skipped(self):
        """Named volumes are not bind mounts — should not trigger."""
        env = _env(
            mounts=[MountInfo(source="my_volume", destination="/etc", mode="rw", type="volume")]
        )
        findings = audit(env)
        assert _find(findings, "sensitive-mount") is None

    def test_safe_path_clean(self):
        env = _env(
            mounts=[MountInfo(source="/opt/app/data", destination="/data", mode="rw", type="bind")]
        )
        findings = audit(env)
        assert _find(findings, "sensitive-mount") is None


class TestHostNetwork:
    def test_host_network_detected(self):
        env = _env(network_mode="host")
        findings = audit(env)
        f = _find(findings, "host-network")
        assert f is not None
        assert f.severity == Severity.INFO

    def test_bridge_network_clean(self):
        env = _env(network_mode="bridge")
        findings = audit(env)
        assert _find(findings, "host-network") is None

    def test_stopped_host_network_skipped(self):
        env = _env(status="exited", network_mode="host")
        findings = audit(env)
        assert _find(findings, "host-network") is None

    def test_none_network_clean(self):
        env = _env(network_mode=None)
        findings = audit(env)
        assert _find(findings, "host-network") is None


class TestSortOrder:
    def test_findings_sorted_by_severity_then_name(self):
        c1 = make_container(
            name="alpha",
            id="id1",
            status="running",
            image="postgres:16",
            image_id="sha256:x",
            ports=[
                PortBinding(
                    container_port=5432, protocol="tcp", host_ip="0.0.0.0", host_port="5432"
                )
            ],
            mounts=[
                MountInfo(
                    source="/var/run/docker.sock",
                    destination="/var/run/docker.sock",
                    mode="rw",
                    type="bind",
                )
            ],
        )
        c2 = make_container(
            name="beta",
            id="id2",
            status="running",
            image="nginx:latest",
            image_id="sha256:y",
            image_digest=None,
        )
        env = make_environment(
            containers=[c1, c2],
            generated_at="2026-03-09T00:00:00Z",
            docker_version="25.0.3",
        )
        findings = audit(env)
        severities = [f.severity for f in findings]
        # Critical should come before warning, warning before info
        severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        severity_values = [severity_order[s] for s in severities]
        assert severity_values == sorted(severity_values)


class TestDangerousCapabilities:
    def test_sys_admin_detected(self):
        env = _env(cap_add=["SYS_ADMIN"])
        findings = audit(env)
        f = _find(findings, "dangerous-capability")
        assert f is not None
        assert f.severity == Severity.WARNING
        assert "SYS_ADMIN" in f.explanation

    def test_net_admin_detected(self):
        env = _env(cap_add=["NET_ADMIN"])
        findings = audit(env)
        f = _find(findings, "dangerous-capability")
        assert f is not None

    def test_safe_cap_clean(self):
        env = _env(cap_add=["NET_BIND_SERVICE"])
        findings = audit(env)
        assert _find(findings, "dangerous-capability") is None

    def test_privileged_skips_cap_check(self):
        env = _env(privileged=True, cap_add=["SYS_ADMIN"])
        findings = audit(env)
        assert _find(findings, "dangerous-capability") is None
        assert _find(findings, "privileged-mode") is not None

    def test_multiple_dangerous_caps(self):
        env = _env(cap_add=["SYS_ADMIN", "NET_ADMIN", "NET_BIND_SERVICE"])
        findings = audit(env)
        caps = _find_all(findings, "dangerous-capability")
        assert len(caps) == 2


class TestHostPid:
    def test_host_pid_detected(self):
        env = _env(pid_mode="host")
        findings = audit(env)
        f = _find(findings, "host-pid")
        assert f is not None
        assert f.severity == Severity.WARNING

    def test_no_pid_mode_clean(self):
        env = _env(pid_mode=None)
        findings = audit(env)
        assert _find(findings, "host-pid") is None

    def test_stopped_host_pid_skipped(self):
        env = _env(status="exited", pid_mode="host")
        findings = audit(env)
        assert _find(findings, "host-pid") is None


class TestStaleImagesUntagged:
    def test_untagged_image_detected(self):
        env = _env(image="postgres", image_digest=None)
        findings = audit(env)
        f = _find(findings, "stale-image")
        assert f is not None
        assert "no version tag" in f.explanation

    def test_tagged_image_clean(self):
        env = _env(image="postgres:16-alpine")
        findings = audit(env)
        assert _find(findings, "stale-image") is None


class TestSensitiveMountHomeSubdir:
    def test_home_subdir_not_flagged(self):
        """Standard homelab data paths under /home should NOT be flagged."""
        env = _env(
            mounts=[
                MountInfo(
                    source="/home/user/docker/jellyfin/config",
                    destination="/config",
                    mode="rw",
                    type="bind",
                )
            ]
        )
        findings = audit(env)
        assert _find(findings, "sensitive-mount") is None

    def test_bare_home_still_flagged(self):
        env = _env(mounts=[MountInfo(source="/home", destination="/data", mode="rw", type="bind")])
        findings = audit(env)
        f = _find(findings, "sensitive-mount")
        assert f is not None


class TestRenderFindings:
    def test_no_findings(self):
        result = render_findings([])
        assert "No findings" in result

    def test_renders_findings(self):
        findings = [
            Finding(
                severity=Severity.CRITICAL,
                category="docker-socket",
                container="watchtower",
                explanation="Docker socket is mounted.",
                fix="Use a socket proxy.",
            ),
            Finding(
                severity=Severity.WARNING,
                category="secrets-in-env",
                container="postgres",
                explanation="DB_PASSWORD in env.",
                fix="Use Docker secrets.",
            ),
        ]
        result = render_findings(findings)
        assert "# Security Audit" in result
        assert "2 findings" in result
        assert "1 critical" in result
        assert "1 warning" in result
        assert "## Critical" in result
        assert "## Warning" in result
        assert "watchtower" in result
        assert "postgres" in result

    def test_summary_counts(self):
        findings = [
            Finding(Severity.CRITICAL, "cat", "c1", "exp", "fix"),
            Finding(Severity.WARNING, "cat", "c2", "exp", "fix"),
            Finding(Severity.WARNING, "cat", "c3", "exp", "fix"),
            Finding(Severity.INFO, "cat", "c4", "exp", "fix"),
        ]
        result = render_findings(findings)
        assert "4 findings" in result
        assert "1 critical" in result
        assert "2 warning" in result
        assert "1 info" in result
