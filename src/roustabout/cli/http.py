"""HTTPBackend — calls roustabout REST API via httpx.

Used for mutations (always) and all operations when ROUSTABOUT_URL is set.
"""

from __future__ import annotations

import sys
from typing import Any

import httpx


class HTTPBackend:
    """Executes roustabout operations via the REST API."""

    def __init__(self, base_url: str, api_key: str | None = None) -> None:
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=30.0,
        )
        self.server_version: str | None = None
        self._check_server_version()

    def _check_server_version(self) -> None:
        """Check server version on connect and warn if mismatched."""
        from roustabout import __version__

        try:
            resp = self._client.get("/health")
            if resp.is_success:
                data = resp.json()
                self.server_version = data.get("version")
                if self.server_version and self.server_version != __version__:
                    msg = (
                        f"Warning: server is v{self.server_version}, "
                        f"CLI is v{__version__}. "
                        f"Some features may not work. Update the server: "
                        f"docker pull ghcr.io/featurecreep-cron/roustabout:latest"
                    )
                    print(msg, file=sys.stderr)
        except Exception:
            pass  # Connection errors will surface on the actual command

    def _get(self, path: str, **params: str | int) -> dict[str, Any]:
        resp = self._client.get(path, params=params or None)
        self._check_response(resp)
        return resp.json()  # type: ignore[no-any-return]

    def _get_text(self, path: str, **params: str | int) -> str:
        resp = self._client.get(path, params=params or None)
        self._check_response(resp)
        return resp.text

    def _post(self, path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self._client.post(path, json=json)
        self._check_response(resp)
        return resp.json()  # type: ignore[no-any-return]

    def _check_response(self, resp: httpx.Response) -> None:
        if resp.is_success:
            return
        status = resp.status_code
        try:
            body = resp.json()
            detail = body.get("error", body.get("detail", resp.text))
        except Exception:
            detail = resp.text

        messages = {
            401: "Authentication failed. Check ROUSTABOUT_API_KEY.",
            403: f"Permission denied: {detail}",
            404: f"Not found: {detail}",
            409: "Conflict: concurrent mutation in progress. Try again.",
            429: "Rate limit exceeded. Try again later.",
            503: f"Server unavailable: {detail}",
        }
        msg = messages.get(status, f"Server error ({status}): {detail}")
        raise RuntimeError(msg)

    def snapshot(self, *, redact: bool = True, fmt: str = "json") -> dict[str, Any] | str:
        if fmt == "markdown":
            return self._get_text("/v1/snapshot", format="markdown")
        return self._get("/v1/snapshot", format=fmt)

    def audit(self, *, fmt: str = "json") -> dict[str, Any] | str:
        if fmt == "markdown":
            return self._get_text("/v1/audit", format="markdown")
        return self._get("/v1/audit", format=fmt)

    def health(self, name: str | None = None) -> dict[str, Any]:
        if name:
            entry = self._get(f"/v1/health/{name}")
            return {"entries": [entry]}
        # No bulk health endpoint via API — return empty
        return {"entries": []}

    def logs(
        self,
        name: str,
        tail: int = 100,
        since: str | None = None,
        grep: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, str | int] = {"tail": tail}
        if since:
            params["since"] = since
        if grep:
            params["grep"] = grep
        return self._get(f"/v1/logs/{name}", **params)

    def dr_plan(self) -> dict[str, Any]:
        return self._get("/v1/dr-plan")

    def mutate(self, name: str, action: str, dry_run: bool = False) -> dict[str, Any]:
        return self._post(f"/v1/containers/{name}/{action}")

    def capabilities(self) -> dict[str, Any]:
        return self._get("/v1/capabilities")

    def generate(
        self,
        *,
        project: str | None = None,
        include_stopped: bool = False,
        services: str | None = None,
    ) -> str:
        params: dict[str, str | int] = {}
        if project:
            params["project"] = project
        if include_stopped:
            params["include_stopped"] = "true"
        if services:
            params["services"] = services
        return self._get_text("/v1/generate", **params)

    def deep_health(self, name: str | None = None) -> dict[str, Any]:
        if name:
            return self._get(f"/v1/deep-health/{name}")
        return self._get("/v1/deep-health")

    def net_check(self, source: str | None = None, target: str | None = None) -> dict[str, Any]:
        params: dict[str, str | int] = {}
        if source:
            params["source"] = source
        if target:
            params["target"] = target
        return self._get("/v1/net-check", **params)

    def container_network(self, name: str) -> dict[str, Any]:
        return self._get(f"/v1/containers/{name}/network")

    def inspect_network(self, name: str) -> dict[str, Any]:
        return self._get(f"/v1/networks/{name}")

    def ports(self, name: str) -> dict[str, Any]:
        return self._get(f"/v1/containers/{name}/ports")

    def probe_dns(self, container: str, hostname: str) -> dict[str, Any]:
        return self._post(
            f"/v1/containers/{container}/probe/dns",
            json={"hostname": hostname},
        )

    def probe_connect(self, container: str, target_host: str, port: int) -> dict[str, Any]:
        return self._post(
            f"/v1/containers/{container}/probe/connect",
            json={"target_host": target_host, "port": port},
        )

    def exec(
        self,
        container: str,
        command: list[str],
        *,
        user: str | None = None,
        workdir: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"command": command, "timeout": timeout}
        if user:
            body["user"] = user
        if workdir:
            body["workdir"] = workdir
        return self._post(f"/v1/containers/{container}/exec", json=body)

    def file_read(self, path: str) -> dict[str, Any]:
        return self._post("/v1/files/read", json={"path": path})

    def file_write(
        self,
        path: str,
        content: str,
        *,
        direct: bool = False,
        session_id: str = "cli",
    ) -> dict[str, Any]:
        return self._post(
            "/v1/files/write",
            json={
                "path": path,
                "content": content,
                "direct": direct,
                "session_id": session_id,
            },
        )

    def stats(self, container: str | None = None) -> dict[str, Any]:
        if container:
            return self._get("/v1/stats", container=container)
        return self._get("/v1/stats")

    def migrate(
        self,
        output_dir: str,
        *,
        services: str | None = None,
        include_stopped: bool = False,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "output_dir": output_dir,
            "dry_run": dry_run,
            "include_stopped": include_stopped,
        }
        if services:
            body["services"] = services.split(",")
        return self._post("/v1/supply-chain/migrate", json=body)
