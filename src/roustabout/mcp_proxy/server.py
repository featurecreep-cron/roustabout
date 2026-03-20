"""MCP proxy server — translates MCP tool calls to REST API HTTP requests.

This module imports ZERO roustabout core packages. It is a pure HTTP client
with MCP tool wrappers. All logic lives in the REST API server.
"""

from __future__ import annotations

import json
import os
import sys

import httpx
from mcp.server.fastmcp import FastMCP

_RESPONSE_ENVELOPE = "[roustabout]"


def _format_result(data: dict) -> str:
    return f"{_RESPONSE_ENVELOPE}\n{json.dumps(data, indent=2)}"


def _format_error(status: int, resp: httpx.Response) -> str:
    try:
        body = resp.json()
        detail = body.get("error", body.get("detail", resp.text))
    except Exception:
        detail = resp.text

    messages = {
        401: "Authentication failed. Check MCP proxy API key configuration.",
        403: f"Permission denied: {detail}",
        404: f"Not found: {detail}",
        409: "Conflict: concurrent mutation in progress",
        429: "Rate limit exceeded. Try again later.",
        503: f"Service unavailable: {detail}",
    }
    return messages.get(status, f"Unexpected error ({status}): {detail}")


def create_mcp_server(api_url: str, api_key: str) -> FastMCP:
    """Create MCP server that proxies all calls to the REST API."""
    client = httpx.AsyncClient(
        base_url=api_url,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30.0,
    )

    mcp = FastMCP("roustabout")

    async def _get(path: str) -> str:
        resp = await client.get(path)
        if resp.is_success:
            return _format_result(resp.json())
        return _format_error(resp.status_code, resp)

    async def _post(path: str) -> str:
        resp = await client.post(path)
        if resp.is_success:
            return _format_result(resp.json())
        return _format_error(resp.status_code, resp)

    # Read tools (Observe tier)

    @mcp.tool()
    async def docker_snapshot() -> str:
        """Get a redacted snapshot of all Docker containers."""
        return await _get("/v1/snapshot")

    @mcp.tool()
    async def docker_audit() -> str:
        """Run security audit checks against the Docker environment."""
        return await _get("/v1/audit")

    @mcp.tool()
    async def docker_health(name: str) -> str:
        """Get health status for a specific container."""
        return await _get(f"/v1/health/{name}")

    @mcp.tool()
    async def docker_logs(name: str, tail: int = 100) -> str:
        """Get recent logs for a specific container."""
        resp = await client.get(f"/v1/logs/{name}", params={"tail": tail})
        if resp.is_success:
            return _format_result(resp.json())
        return _format_error(resp.status_code, resp)

    @mcp.tool()
    async def docker_dr_plan() -> str:
        """Generate a disaster recovery plan from running containers."""
        return await _get("/v1/dr-plan")

    @mcp.tool()
    async def docker_capabilities() -> str:
        """List available capabilities for the configured API key."""
        return await _get("/v1/capabilities")

    # Mutation tools (Operate tier)

    @mcp.tool()
    async def docker_start(name: str) -> str:
        """Start a stopped Docker container through the safety gateway."""
        return await _post(f"/v1/containers/{name}/start")

    @mcp.tool()
    async def docker_stop(name: str) -> str:
        """Stop a running Docker container through the safety gateway."""
        return await _post(f"/v1/containers/{name}/stop")

    @mcp.tool()
    async def docker_restart(name: str) -> str:
        """Restart a Docker container through the safety gateway."""
        return await _post(f"/v1/containers/{name}/restart")

    @mcp.tool()
    async def docker_recreate(name: str) -> str:
        """Recreate a Docker container through the safety gateway."""
        return await _post(f"/v1/containers/{name}/recreate")

    return mcp


def main() -> None:
    """Entry point. Reads ROUSTABOUT_URL and ROUSTABOUT_API_KEY from env."""
    api_url = os.environ.get("ROUSTABOUT_URL", "http://localhost:8077")
    api_key = os.environ.get("ROUSTABOUT_API_KEY", "")
    if not api_key:
        print("ROUSTABOUT_API_KEY required", file=sys.stderr)
        sys.exit(1)
    server = create_mcp_server(api_url, api_key)
    server.run(transport="stdio")
