"""Tests for api/discovery module."""

from unittest.mock import MagicMock

from roustabout.api.discovery import (
    _get_route_tier,
    get_api_info,
)

# --- Tier derivation ---


class TestGetRouteTier:
    def test_tier_from_tag(self):
        route = MagicMock()
        route.tags = ["elevate"]
        route.dependencies = []
        assert _get_route_tier(route) == "elevate"

    def test_tier_from_discovery_tag(self):
        route = MagicMock()
        route.tags = ["discovery"]
        route.dependencies = []
        assert _get_route_tier(route) == "none"

    def test_tier_from_dependency(self):
        dep = MagicMock()
        dep.dependency.__name__ = "require_operate"
        route = MagicMock()
        route.tags = []
        route.dependencies = [dep]
        assert _get_route_tier(route) == "operate"

    def test_default_observe(self):
        route = MagicMock()
        route.tags = []
        route.dependencies = []
        assert _get_route_tier(route) == "observe"

    def test_tag_takes_priority(self):
        dep = MagicMock()
        dep.dependency.__name__ = "require_elevate"
        route = MagicMock()
        route.tags = ["operate"]
        route.dependencies = [dep]
        assert _get_route_tier(route) == "operate"

    def test_none_tag(self):
        route = MagicMock()
        route.tags = ["none"]
        route.dependencies = []
        assert _get_route_tier(route) == "none"


# --- API info ---


class TestGetAPIInfo:
    def test_collects_routes(self):
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/v1/snapshot", tags=["observe"])
        async def snapshot():
            pass

        @app.post("/v1/containers/{name}/restart", tags=["operate"])
        async def restart(name: str):
            pass

        info = get_api_info(app, {})
        assert info.api_version == "v1"
        assert info.host_count == 1
        assert len(info.routes) >= 2

        # Find our routes (FastAPI may add others like /openapi.json)
        paths = {r.path for r in info.routes}
        assert "/v1/snapshot" in paths
        assert "/v1/containers/{name}/restart" in paths

    def test_host_count_from_config(self):
        from fastapi import FastAPI

        app = FastAPI()
        config = {"hosts": {"a": {}, "b": {}, "c": {}}}
        info = get_api_info(app, config)
        assert info.host_count == 3

    def test_routes_sorted(self):
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/v1/z")
        async def z():
            pass

        @app.get("/v1/a")
        async def a():
            pass

        info = get_api_info(app, {})
        route_paths = [r.path for r in info.routes if r.path.startswith("/v1/")]
        assert route_paths == sorted(route_paths)

    def test_capabilities_present(self):
        from fastapi import FastAPI

        app = FastAPI()
        info = get_api_info(app, {})
        assert "observe" in info.capabilities
        assert "operate" in info.capabilities
        assert "elevate" in info.capabilities
