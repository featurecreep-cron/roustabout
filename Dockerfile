# Multi-stage build for roustabout
# Produces a slim image with Docker socket access for container management.

# --- Build stage ---
FROM python:3.13-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install .
RUN pip install --no-cache-dir --prefix=/install ".[mcp]"

# --- Runtime stage ---
FROM python:3.13-slim

# Create non-root user with a GID that can be overridden at runtime
# to match the host's docker group GID.
RUN groupadd -g 999 docker && \
    useradd -r -u 1000 -g docker roustabout && \
    mkdir -p /etc/roustabout /data && \
    chown roustabout:docker /data

COPY --from=builder /install /usr/local

# Default config and state paths
ENV ROUSTABOUT_CONFIG=/etc/roustabout/config.toml
ENV ROUSTABOUT_STATE_DB=/data/roustabout.db

USER roustabout
WORKDIR /data

# Health check — verify the CLI is functional
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["roustabout", "version"]

ENTRYPOINT ["roustabout"]
CMD ["--help"]
