"""Shared fixtures for roustabout tests.

Mock Docker API responses that mirror real docker-py structures.
"""

from unittest.mock import MagicMock

import pytest

from roustabout.models import (
    MountInfo,
    NetworkMembership,
    PortBinding,
    make_container,
    make_environment,
)

# ---------------------------------------------------------------------------
# Mock Docker API container attrs — mirrors docker-py's container.attrs
# ---------------------------------------------------------------------------


def _make_mock_container(
    *,
    name="/nginx-proxy",
    short_id="abc123def4",
    status="running",
    image_tags=("nginx:1.25-alpine",),
    image_id="sha256:abcdef1234567890",
    repo_digests=("nginx@sha256:deadbeef1234567890abcdef",),
    ports=None,
    mounts=None,
    networks=None,
    env=("NGINX_HOST=example.com", "SECRET_KEY=hunter2"),
    labels=None,
    health_status="healthy",
    compose_project="webstack",
    compose_service="nginx",
    compose_config="/opt/webstack/docker-compose.yml",
    restart_count=0,
    created="2026-02-01T10:00:00.000000000Z",
    started_at="2026-02-01T10:00:05.000000000Z",
    command=("nginx", "-g", "daemon off;"),
    entrypoint=("/docker-entrypoint.sh",),
    oom_killed=False,
    user="",
    restart_policy_name="always",
    privileged=False,
    network_mode="bridge",
    healthcheck=None,
    devices=None,
    cap_add=None,
    cap_drop=None,
    runtime=None,
    shm_size=67108864,
    tmpfs=None,
    sysctls=None,
    security_opt=None,
    pid_mode="",
    dns=None,
    dns_search=None,
    extra_hosts=None,
    group_add=None,
    hostname=None,
    stop_signal=None,
    stop_timeout=None,
    memory=0,
    nano_cpus=0,
    init=False,
):
    """Build a mock container object matching docker-py's Container interface."""
    if ports is None:
        ports = {
            "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
            "443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8443"}],
        }

    if mounts is None:
        mounts = [
            {
                "Type": "bind",
                "Source": "/opt/webstack/nginx.conf",
                "Destination": "/etc/nginx/nginx.conf",
                "Mode": "ro",
            },
            {
                "Type": "volume",
                "Source": "nginx-logs",
                "Destination": "/var/log/nginx",
                "Mode": "rw",
            },
        ]

    if networks is None:
        networks = {
            "frontend": {
                "IPAddress": "172.18.0.2",
                "Aliases": ["nginx", "proxy"],
            },
            "backend": {
                "IPAddress": "172.18.1.2",
                "Aliases": None,
            },
        }

    all_labels = {}
    if compose_project:
        all_labels["com.docker.compose.project"] = compose_project
    if compose_service:
        all_labels["com.docker.compose.service"] = compose_service
    if compose_config:
        all_labels["com.docker.compose.project.config_files"] = compose_config
    if labels:
        all_labels.update(labels)

    # Build the attrs dict the way docker-py structures it
    state = {
        "Status": status,
        "StartedAt": started_at,
        "OOMKilled": oom_killed,
    }
    if health_status is not None:
        state["Health"] = {"Status": health_status}

    attrs = {
        "Id": short_id + "567890abcdef1234567890abcdef1234567890abcdef12345678",
        "Name": name,
        "State": state,
        "Created": created,
        "Config": {
            "Image": image_tags[0] if image_tags else image_id,
            "Env": list(env),
            "Labels": all_labels,
            "Cmd": list(command) if command else None,
            "Entrypoint": list(entrypoint) if entrypoint else None,
            "User": user,
            "Healthcheck": healthcheck,
            "Hostname": hostname,
            "StopSignal": stop_signal,
            "StopTimeout": stop_timeout,
        },
        "HostConfig": {
            "RestartPolicy": {"Name": restart_policy_name},
            "Privileged": privileged,
            "NetworkMode": network_mode,
            "Devices": devices,
            "CapAdd": cap_add,
            "CapDrop": cap_drop,
            "Runtime": runtime,
            "ShmSize": shm_size,
            "Tmpfs": tmpfs,
            "Sysctls": sysctls,
            "SecurityOpt": security_opt,
            "PidMode": pid_mode,
            "Dns": dns,
            "DnsSearch": dns_search,
            "ExtraHosts": extra_hosts,
            "GroupAdd": group_add,
            "Init": init,
            "Memory": memory,
            "NanoCpus": nano_cpus,
        },
        "NetworkSettings": {
            "Ports": ports,
            "Networks": {
                net_name: {
                    "IPAddress": net_info["IPAddress"],
                    "Aliases": net_info.get("Aliases"),
                }
                for net_name, net_info in networks.items()
            },
        },
        "Mounts": mounts,
        "RestartCount": restart_count,
    }

    container = MagicMock()
    container.attrs = attrs
    container.short_id = short_id
    container.name = name.lstrip("/")
    container.status = status

    # Mock the image object
    container.image.tags = list(image_tags)
    container.image.id = image_id
    container.image.attrs = {"RepoDigests": list(repo_digests)}

    return container


@pytest.fixture
def mock_nginx():
    """A typical nginx reverse proxy container."""
    return _make_mock_container()


@pytest.fixture
def mock_postgres():
    """A postgres container with secrets in env."""
    return _make_mock_container(
        name="/postgres-db",
        short_id="def456abc7",
        status="running",
        image_tags=("postgres:16-alpine",),
        image_id="sha256:postgres1234567890",
        repo_digests=("postgres@sha256:cafebabe1234567890",),
        ports={"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]},
        mounts=[
            {
                "Type": "volume",
                "Source": "pgdata",
                "Destination": "/var/lib/postgresql/data",
                "Mode": "rw",
            }
        ],
        networks={
            "backend": {
                "IPAddress": "172.18.1.3",
                "Aliases": ["db", "postgres"],
            }
        },
        env=(
            "POSTGRES_PASSWORD=supersecret123",
            "POSTGRES_USER=app",
            "POSTGRES_DB=myapp",
            "DATABASE_URL=postgresql://app:supersecret123@localhost:5432/myapp",
        ),
        labels={"org.opencontainers.image.version": "16.2"},
        health_status="healthy",
        compose_project="webstack",
        compose_service="postgres",
        compose_config="/opt/webstack/docker-compose.yml",
        command=("postgres",),
        entrypoint=("docker-entrypoint.sh",),
    )


@pytest.fixture
def mock_standalone():
    """A standalone container not part of any compose project."""
    return _make_mock_container(
        name="/watchtower",
        short_id="789abc0123",
        status="running",
        image_tags=("containrrr/watchtower:latest",),
        image_id="sha256:watchtower1234567890",
        repo_digests=(),
        ports={},
        mounts=[
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "Mode": "rw",
            }
        ],
        networks={
            "bridge": {
                "IPAddress": "172.17.0.2",
                "Aliases": None,
            }
        },
        env=("WATCHTOWER_CLEANUP=true", "WATCHTOWER_POLL_INTERVAL=3600"),
        labels={},
        health_status=None,
        compose_project=None,
        compose_service=None,
        compose_config=None,
        command=("--cleanup", "--poll-interval", "3600"),
        entrypoint=("/watchtower",),
    )


@pytest.fixture
def mock_exited():
    """A stopped container."""
    return _make_mock_container(
        name="/redis-cache",
        short_id="stopped12345",
        status="exited",
        image_tags=("redis:7-alpine",),
        image_id="sha256:redis1234567890",
        repo_digests=("redis@sha256:aabbccdd",),
        ports={},
        mounts=[],
        networks={
            "backend": {
                "IPAddress": "",
                "Aliases": None,
            }
        },
        env=(),
        labels={},
        health_status=None,
        compose_project="webstack",
        compose_service="redis",
        compose_config="/opt/webstack/docker-compose.yml",
        started_at="2026-01-15T08:00:00.000000000Z",
        command=("redis-server",),
        entrypoint=("docker-entrypoint.sh",),
        oom_killed=True,
    )


@pytest.fixture
def mock_docker_client(mock_nginx, mock_postgres, mock_standalone, mock_exited):
    """A mock docker.DockerClient with several containers."""
    client = MagicMock()
    client.containers.list.return_value = [
        mock_nginx,
        mock_postgres,
        mock_standalone,
        mock_exited,
    ]
    client.version.return_value = {
        "Version": "25.0.3",
        "ApiVersion": "1.44",
    }
    return client


# ---------------------------------------------------------------------------
# Pre-built model fixtures for renderer / redactor tests
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_container_info():
    """A ContainerInfo built through the model layer."""
    return make_container(
        name="nginx-proxy",
        id="abc123def4",
        status="running",
        image="nginx:1.25-alpine",
        image_id="sha256:abcdef1234567890",
        image_digest="nginx@sha256:deadbeef1234567890abcdef",
        ports=[
            PortBinding(container_port=443, protocol="tcp", host_ip="0.0.0.0", host_port="8443"),
            PortBinding(container_port=80, protocol="tcp", host_ip="0.0.0.0", host_port="8080"),
        ],
        mounts=[
            MountInfo(
                source="nginx-logs",
                destination="/var/log/nginx",
                mode="rw",
                type="volume",
            ),
            MountInfo(
                source="/opt/webstack/nginx.conf",
                destination="/etc/nginx/nginx.conf",
                mode="ro",
                type="bind",
            ),
        ],
        networks=[
            NetworkMembership(
                name="frontend", ip_address="172.18.0.2", aliases=("nginx", "proxy")
            ),
            NetworkMembership(name="backend", ip_address="172.18.1.2", aliases=()),
        ],
        env=[
            ("SECRET_KEY", "hunter2"),
            ("NGINX_HOST", "example.com"),
        ],
        labels=[
            ("com.docker.compose.project", "webstack"),
            ("com.docker.compose.service", "nginx"),
        ],
        health="healthy",
        compose_project="webstack",
        compose_service="nginx",
        compose_config_files="/opt/webstack/docker-compose.yml",
        created="2026-02-01T10:00:00.000000000Z",
        started_at="2026-02-01T10:00:05.000000000Z",
        command=["nginx", "-g", "daemon off;"],
        entrypoint=["/docker-entrypoint.sh"],
    )


@pytest.fixture
def sample_environment(sample_container_info):
    """A DockerEnvironment with one container."""
    return make_environment(
        containers=[sample_container_info],
        generated_at="2026-02-28T12:00:00Z",
        docker_version="25.0.3",
    )
