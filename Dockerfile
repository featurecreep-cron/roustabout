# Multi-stage build for roustabout server.
# Produces a hardened image with Docker socket access for container management.

# --- Build stage ---
FROM python:3.13-slim@sha256:739e7213785e88c0f702dcdc12c0973afcbd606dbf021a589cab77d6b00b579d AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install ".[server,mcp]"

# --- Runtime stage ---
FROM python:3.13-slim@sha256:739e7213785e88c0f702dcdc12c0973afcbd606dbf021a589cab77d6b00b579d

RUN mkdir -p /data

COPY --from=builder /install /usr/local

ENV ROUSTABOUT_STATE_DB=/data/roustabout.db
ENV ROUSTABOUT_HOST=0.0.0.0
ENV ROUSTABOUT_PORT=8077

WORKDIR /data

EXPOSE 8077

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8077/health')"

ENTRYPOINT ["roustabout-server"]
