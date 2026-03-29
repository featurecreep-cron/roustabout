"""Backend protocol and factory for CLI operation.

All CLI commands go through the REST API via HTTPBackend.
No direct Docker access — the API server is the sole chokepoint.
"""

from __future__ import annotations

import os
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Backend(Protocol):
    """Interface for CLI command execution backends."""

    def snapshot(self, *, redact: bool = True, fmt: str = "json") -> dict[str, Any] | str: ...
    def audit(self, *, fmt: str = "json") -> dict[str, Any] | str: ...
    def health(self, name: str | None = None) -> dict[str, Any]: ...
    def logs(
        self,
        name: str,
        tail: int = 100,
        since: str | None = None,
        grep: str | None = None,
    ) -> dict[str, Any]: ...
    def dr_plan(self) -> dict[str, Any]: ...
    def mutate(self, name: str, action: str, dry_run: bool = False) -> dict[str, Any]: ...
    def capabilities(self) -> dict[str, Any]: ...
    def generate(
        self,
        *,
        project: str | None = None,
        include_stopped: bool = False,
        services: str | None = None,
    ) -> str: ...
    def deep_health(self, name: str | None = None) -> dict[str, Any]: ...
    def net_check(
        self, source: str | None = None, target: str | None = None
    ) -> dict[str, Any]: ...
    def container_network(self, name: str) -> dict[str, Any]: ...
    def inspect_network(self, name: str) -> dict[str, Any]: ...
    def ports(self, name: str) -> dict[str, Any]: ...
    def probe_dns(self, container: str, hostname: str) -> dict[str, Any]: ...
    def probe_connect(
        self, container: str, target_host: str, port: int
    ) -> dict[str, Any]: ...
    def exec(
        self,
        container: str,
        command: list[str],
        *,
        user: str | None = None,
        workdir: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]: ...
    def file_read(self, path: str, *, read_root: str = "/") -> dict[str, Any]: ...
    def file_write(
        self,
        path: str,
        content: str,
        *,
        write_root: str = "/",
        direct: bool = False,
        session_id: str = "cli",
    ) -> dict[str, Any]: ...
    def stats(self, container: str | None = None) -> dict[str, Any]: ...
    def migrate(
        self,
        output_dir: str,
        *,
        services: str | None = None,
        include_stopped: bool = False,
        dry_run: bool = True,
    ) -> dict[str, Any]: ...


_UNIX_SOCKET_PATH = "/var/run/roustabout.sock"


def get_backend(command_is_mutation: bool = False) -> Backend:  # noqa: ARG001
    """Return HTTPBackend. The API server is the sole Docker gateway.

    Raises RuntimeError if no server URL is configured or discoverable.
    """
    from roustabout.cli.http import HTTPBackend

    url = os.environ.get("ROUSTABOUT_URL")

    if url:
        api_key = os.environ.get("ROUSTABOUT_API_KEY")
        return HTTPBackend(base_url=url, api_key=api_key)

    # Auto-discover unix socket
    if os.path.exists(_UNIX_SOCKET_PATH):
        return HTTPBackend(
            base_url=f"http+unix://{_UNIX_SOCKET_PATH}",
            api_key=os.environ.get("ROUSTABOUT_API_KEY"),
        )

    raise RuntimeError(
        "No roustabout server found. Set ROUSTABOUT_URL or ensure the server is running.\n"
        "The CLI requires a running roustabout API server — it does not access Docker directly."
    )
