"""Multi-host Docker session management via SSH/TCP/Unix socket.

Extends DockerSession to connect to remote Docker daemons.
Manages a connection pool per host with idle eviction and health checks.

LLD: docs/roustabout/designs/027-multi-host.md
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

import docker
import docker.errors
import docker.tls

logger = logging.getLogger(__name__)

# Pool configuration
IDLE_TIMEOUT = 300  # 5 minutes
MAX_PER_HOST = 2


# Data types


@dataclass(frozen=True)
class HostConfig:
    """Configuration for a Docker host."""

    name: str
    url: str  # ssh://, tcp://, unix://
    label: str = ""
    ssh_key: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    tls_ca: str | None = None  # None disables server cert verification
    default: bool = False


@dataclass(frozen=True)
class HostHealth:
    """Health check result for a Docker host."""

    name: str
    reachable: bool
    docker_version: str | None = None
    containers_count: int | None = None
    error: str | None = None
    latency_ms: float | None = None


# Exceptions


class HostNotFound(Exception):
    """Host name not in configuration."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"Host {name!r} not found in configuration")


class HostUnreachable(Exception):
    """Cannot connect to Docker daemon on host."""

    def __init__(self, name: str, url: str, reason: str) -> None:
        self.name = name
        self.url = url
        self.reason = reason
        super().__init__(f"Host {name!r} ({url}) unreachable: {reason}")


# Connection creation


def _create_client(config: HostConfig) -> docker.DockerClient:
    """Create a Docker client for the given host config."""
    if config.url.startswith("ssh://"):
        kwargs: dict[str, Any] = {"base_url": config.url, "use_ssh_client": True}
        if config.ssh_key:
            kwargs["ssh_key"] = config.ssh_key
        return docker.DockerClient(**kwargs)

    elif config.url.startswith("tcp://"):
        if not (config.tls_cert and config.tls_key):
            raise ValueError(f"TCP host {config.name!r} requires tls_cert and tls_key")
        tls_config = docker.tls.TLSConfig(
            client_cert=(config.tls_cert, config.tls_key),
            ca_cert=config.tls_ca,
            verify=config.tls_ca is not None,
        )
        return docker.DockerClient(
            base_url=config.url.replace("tcp://", "https://"),
            tls=tls_config,
        )

    elif config.url.startswith("unix://"):
        return docker.DockerClient(base_url=config.url)

    else:
        raise ValueError(f"Unsupported transport in URL: {config.url}")


def _safe_close(client: docker.DockerClient) -> None:
    try:
        client.close()
    except Exception:  # noqa: broad-except — best-effort close
        pass


# Connection pooling


@dataclass
class _PoolEntry:
    client: docker.DockerClient
    last_used: float
    in_use: bool = False


class HostPool:
    """Manages Docker client connections to multiple hosts."""

    def __init__(self, hosts: dict[str, HostConfig]) -> None:
        self._hosts = dict(hosts)
        self._pools: dict[str, list[_PoolEntry]] = {}
        self._locks: dict[str, threading.Lock] = {name: threading.Lock() for name in hosts}
        self._global_lock = threading.Lock()

    def connect(self, host_name: str) -> docker.DockerClient:
        """Get or create a Docker client for the named host.

        Returns a healthy client from the pool, or creates a new one.
        Raises HostNotFound if the host name isn't in config.
        Raises HostUnreachable if connection fails.
        """
        config = self._hosts.get(host_name)
        if not config:
            raise HostNotFound(host_name)

        lock = self._locks.get(host_name)
        if lock is None:
            with self._global_lock:
                lock = self._locks.setdefault(host_name, threading.Lock())

        with lock:
            pool = self._pools.setdefault(host_name, [])

            # Try to reuse an idle, healthy connection
            for entry in list(pool):
                if not entry.in_use:
                    try:
                        entry.client.ping()
                        entry.in_use = True
                        entry.last_used = time.monotonic()
                        return entry.client
                    except Exception:  # noqa: broad-except — stale connection, reconnect
                        pool.remove(entry)
                        _safe_close(entry.client)

            # Create new connection if under limit
            if len(pool) < MAX_PER_HOST:
                try:
                    client = _create_client(config)
                    client.ping()
                except Exception as e:  # noqa: broad-except — wrap as HostUnreachable
                    raise HostUnreachable(host_name, config.url, str(e)) from e
                entry = _PoolEntry(client=client, last_used=time.monotonic(), in_use=True)
                pool.append(entry)
                return entry.client

            raise HostUnreachable(host_name, config.url, "Connection pool exhausted")

    def release(self, host_name: str, client: docker.DockerClient) -> None:
        """Return a client to the pool after use."""
        lock = self._locks.get(host_name)
        if lock is None:
            return
        with lock:
            for entry in self._pools.get(host_name, []):
                if entry.client is client:
                    entry.in_use = False
                    entry.last_used = time.monotonic()
                    return

    def disconnect(self, host_name: str) -> None:
        """Close all connections to a host."""
        lock = self._locks.get(host_name)
        if lock is None:
            return
        with lock:
            pool = self._pools.pop(host_name, [])
            for entry in pool:
                _safe_close(entry.client)

    def disconnect_all(self) -> None:
        """Close all connections. Called on server shutdown."""
        for host_name in list(self._pools):
            self.disconnect(host_name)

    def health(self, host_name: str) -> HostHealth:
        """Check connectivity to a host without caching the result."""
        config = self._hosts.get(host_name)
        if not config:
            raise HostNotFound(host_name)

        start = time.monotonic()
        try:
            client = _create_client(config)
            try:
                client.ping()
                version = client.version()
                containers = client.containers.list()
                latency = (time.monotonic() - start) * 1000
                return HostHealth(
                    name=host_name,
                    reachable=True,
                    docker_version=version.get("Version"),
                    containers_count=len(containers),
                    latency_ms=round(latency, 1),
                )
            finally:
                _safe_close(client)
        except Exception as e:  # noqa: broad-except — connection or ping failure
            latency = (time.monotonic() - start) * 1000
            return HostHealth(
                name=host_name,
                reachable=False,
                error=str(e),
                latency_ms=round(latency, 1),
            )

    def list_hosts(self) -> tuple[HostConfig, ...]:
        """Return all configured hosts."""
        return tuple(self._hosts.values())

    def default_host(self) -> str | None:
        """Return the name of the default host, or None."""
        for config in self._hosts.values():
            if config.default:
                return config.name
        return None

    def _evict_idle(self) -> None:
        """Close connections idle longer than IDLE_TIMEOUT."""
        now = time.monotonic()
        for host_name in list(self._pools):
            lock = self._locks.get(host_name)
            if lock is None:
                continue
            with lock:
                pool = self._pools.get(host_name, [])
                expired = [e for e in pool if not e.in_use and now - e.last_used > IDLE_TIMEOUT]
                for entry in expired:
                    pool.remove(entry)
                    _safe_close(entry.client)


def hosts_from_config(config: dict[str, Any]) -> dict[str, HostConfig]:
    """Parse host configurations from roustabout.toml [hosts] section."""
    hosts: dict[str, HostConfig] = {}
    raw_hosts = config.get("hosts", {})

    for name, host_dict in raw_hosts.items():
        if not isinstance(host_dict, dict):
            continue
        url = host_dict.get("url", "")
        if not url:
            continue
        hosts[name] = HostConfig(
            name=name,
            url=url,
            label=host_dict.get("label", ""),
            ssh_key=host_dict.get("ssh_key"),
            tls_cert=host_dict.get("tls_cert"),
            tls_key=host_dict.get("tls_key"),
            tls_ca=host_dict.get("tls_ca"),
            default=host_dict.get("default", False),
        )

    return hosts
