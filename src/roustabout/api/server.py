"""Server entry point — starts uvicorn with the roustabout API."""

from __future__ import annotations

import logging
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
    from roustabout.api.routes import set_audit_db, set_exec_rate_limiter, set_rate_limiter
    from roustabout.config import load_config
    from roustabout.session import RateLimiter

    # Audit log — structured output for all API requests
    logging.basicConfig(
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        level=logging.WARNING,
    )
    logging.getLogger("roustabout.audit").setLevel(logging.INFO)

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

    # Exec: same limits, separate budget — exec must not be able to exhaust
    # the tokens that container mutations need.
    set_exec_rate_limiter(
        RateLimiter(
            max_tokens=config.rate_limit_per_container,
            window_seconds=float(config.rate_limit_window_seconds),
            global_max_tokens=config.rate_limit_global,
        )
    )

    # Hash-chained audit trail. Exec refuses to run without it, so a database
    # that cannot be opened disables exec rather than the whole server.
    from pathlib import Path

    from roustabout.state_db import open_db

    db_path = os.environ.get("ROUSTABOUT_STATE_DB") or config.state_db
    try:
        set_audit_db(open_db(Path(db_path) if db_path else None))
    except Exception as exc:  # noqa: BLE001 — sqlite, permissions, bad path: all mean "no trail"
        logging.getLogger("roustabout.audit").error(
            "state database unavailable (%s: %s); exec is disabled until it can be opened",
            type(exc).__name__,
            exc,
        )

    app = create_app(auth_config=auth_config)

    host = os.environ.get("ROUSTABOUT_HOST", "127.0.0.1")
    port = int(os.environ.get("ROUSTABOUT_PORT", "8077"))

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
