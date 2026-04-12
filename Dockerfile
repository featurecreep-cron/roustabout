# Multi-stage build for roustabout server.
# Produces a hardened image with Docker socket access for container management.

# --- Build stage ---
FROM python:3.14-slim@sha256:bc389f7dfcb21413e72a28f491985326994795e34d2b86c8ae2f417b4e7818aa AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install ".[server,mcp]"

# --- Runtime stage ---
FROM python:3.14-slim@sha256:bc389f7dfcb21413e72a28f491985326994795e34d2b86c8ae2f417b4e7818aa

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
