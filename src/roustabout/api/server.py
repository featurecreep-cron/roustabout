"""Server entry point — starts uvicorn with the roustabout API."""

from __future__ import annotations

import os
import sys


def main() -> None:
    """Start the roustabout API server."""
    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn not installed. Install with: pip install roustabout[server]",
            file=sys.stderr,
        )
        sys.exit(1)

    from roustabout.api.app import create_app
    from roustabout.api.auth import AuthConfig
    from roustabout.api.routes import set_rate_limiter
    from roustabout.config import load_config
    from roustabout.session import RateLimiter

    config = load_config()

    # Auth: env vars take priority, TOML provides additional keys
    env_auth = AuthConfig.from_env()
    toml_auth = AuthConfig.from_dict(config.raw.get("auth", {}))
    auth_config = toml_auth.merge(env_auth)

    # Server-wide rate limiter — shared across all API requests
    rate_limiter = RateLimiter(
        max_tokens=config.rate_limit_per_container,
        window_seconds=float(config.rate_limit_window_seconds),
        global_max_tokens=config.rate_limit_global,
    )
    set_rate_limiter(rate_limiter)

    app = create_app(auth_config=auth_config)

    host = os.environ.get("ROUSTABOUT_HOST", "127.0.0.1")
    port = int(os.environ.get("ROUSTABOUT_PORT", "8077"))

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
