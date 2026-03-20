"""Backend protocol and factory for CLI dual-mode operation.

Selection logic:
  1. ROUSTABOUT_URL set → HTTPBackend for everything
  2. Mutation command → HTTPBackend (auto-discover socket or error)
  3. Read command → DirectBackend (local Docker, no server)
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable


@runtime_checkable
class Backend(Protocol):
    """Interface for CLI command execution backends."""

    def snapshot(self, *, redact: bool = True) -> dict: ...
    def audit(self) -> dict: ...
    def health(self, name: str | None = None) -> dict: ...
    def logs(self, name: str, tail: int = 100, since: str | None = None, grep: str | None = None) -> dict: ...
    def dr_plan(self) -> dict: ...
    def mutate(self, name: str, action: str, dry_run: bool = False) -> dict: ...
    def capabilities(self) -> dict: ...


_UNIX_SOCKET_PATH = "/var/run/roustabout.sock"


def get_backend(command_is_mutation: bool) -> Backend:
    """Select the appropriate backend based on environment and command type."""
    url = os.environ.get("ROUSTABOUT_URL")

    if url:
        from roustabout.cli.http import HTTPBackend

        api_key = os.environ.get("ROUSTABOUT_API_KEY")
        return HTTPBackend(base_url=url, api_key=api_key)

    if command_is_mutation:
        from roustabout.cli.http import HTTPBackend

        # Auto-discover unix socket
        if os.path.exists(_UNIX_SOCKET_PATH):
            return HTTPBackend(
                base_url=f"http+unix://{_UNIX_SOCKET_PATH}",
                api_key=os.environ.get("ROUSTABOUT_API_KEY"),
            )

        raise RuntimeError(
            "No roustabout server found. Set ROUSTABOUT_URL or ensure the server is running."
        )

    from roustabout.cli.direct import DirectBackend

    return DirectBackend()
