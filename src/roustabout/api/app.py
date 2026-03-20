"""FastAPI application factory with auth middleware."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from roustabout.api.auth import AuthConfig, AuthError, resolve_api_key
from roustabout.api.routes import router


def create_app(auth_config: AuthConfig | None = None) -> FastAPI:
    """Create the FastAPI application with auth middleware.

    Args:
        auth_config: API key configuration. If None, creates empty config
                     (all requests will fail auth).
    """
    if auth_config is None:
        auth_config = AuthConfig(keys={})

    app = FastAPI(
        title="Roustabout",
        description="Docker environment management API",
        version="0.8.0",
    )

    # Paths that don't require authentication
    _PUBLIC_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        if request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "missing or malformed Authorization header"},
            )

        token = auth_header[len("Bearer "):]
        try:
            key_info = resolve_api_key(token, auth_config)
        except AuthError:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid API key"},
            )

        request.state.key_info = key_info
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    app.include_router(router)

    return app
