"""FastAPI application factory with auth middleware."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from roustabout.api.auth import AuthConfig, AuthError, resolve_api_key
from roustabout.api.routes import router

audit_log = logging.getLogger("roustabout.audit")


def create_app(auth_config: AuthConfig | None = None) -> FastAPI:
    """Create the FastAPI application with auth middleware.

    Args:
        auth_config: API key configuration. If None, creates empty config
                     (all requests will fail auth).
    """
    if auth_config is None:
        auth_config = AuthConfig(keys={})

    from roustabout import __version__

    app = FastAPI(
        title="Roustabout",
        description="Docker environment management API",
        version=__version__,
    )

    # Paths that don't require authentication
    _PUBLIC_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            audit_log.warning(
                "%s %s auth=missing status=401",
                request.method,
                request.url.path,
            )
            return JSONResponse(
                status_code=401,
                content={"error": "missing or malformed Authorization header"},
            )

        token = auth_header[len("Bearer ") :]
        try:
            key_info = resolve_api_key(token, auth_config)
        except AuthError:
            audit_log.warning(
                "%s %s auth=invalid status=401",
                request.method,
                request.url.path,
            )
            return JSONResponse(
                status_code=401,
                content={"error": "invalid API key"},
            )

        request.state.key_info = key_info
        response = await call_next(request)
        audit_log.info(
            "%s %s key=%s tier=%s status=%d",
            request.method,
            request.url.path,
            key_info.label,
            key_info.tier,
            response.status_code,
        )
        return response

    @app.get("/health")
    async def health() -> dict[str, str]:
        from roustabout import __version__

        return {"status": "ok", "version": __version__}

    app.include_router(router)

    return app
