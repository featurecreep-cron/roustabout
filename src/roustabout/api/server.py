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
    from roustabout.config import load_config

    config = load_config()

    # Load auth config from roustabout.toml [auth] section
    auth_raw = {}
    if hasattr(config, "raw") and isinstance(config.raw, dict):
        auth_raw = config.raw.get("auth", {})

    auth_config = AuthConfig.from_dict(auth_raw)

    app = create_app(auth_config=auth_config)

    host = os.environ.get("ROUSTABOUT_HOST", "127.0.0.1")
    port = int(os.environ.get("ROUSTABOUT_PORT", "8077"))

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
