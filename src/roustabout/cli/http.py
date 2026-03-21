"""HTTPBackend — calls roustabout REST API via httpx.

Used for mutations (always) and all operations when ROUSTABOUT_URL is set.
"""

from __future__ import annotations

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

    def _get(self, path: str, **params: str | int) -> dict[str, Any]:
        resp = self._client.get(path, params=params or None)
        self._check_response(resp)
        return resp.json()  # type: ignore[no-any-return]

    def _get_text(self, path: str, **params: str | int) -> str:
        resp = self._client.get(path, params=params or None)
        self._check_response(resp)
        return resp.text

    def _post(self, path: str) -> dict[str, Any]:
        resp = self._client.post(path)
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
        return self._get("/v1/snapshot")

    def audit(self, *, fmt: str = "json") -> dict[str, Any] | str:
        if fmt == "markdown":
            return self._get_text("/v1/audit", format="markdown")
        return self._get("/v1/audit")

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
