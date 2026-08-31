# Multi-stage build for roustabout server.
# Produces a hardened image with Docker socket access for container management.

# --- Build stage ---
FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5 AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/

# setuptools-scm reads the version from git, and this base image has no git binary.
# Rather than apt-install one (expensive under QEMU for the arm64 leg), the caller
# computes the version and passes it in. Required, not defaulted: a silent
# fallback would publish an image labelled with a version that isn't real.
ARG SETUPTOOLS_SCM_PRETEND_VERSION_FOR_ROUSTABOUT
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_ROUSTABOUT=${SETUPTOOLS_SCM_PRETEND_VERSION_FOR_ROUSTABOUT}
RUN test -n "$SETUPTOOLS_SCM_PRETEND_VERSION_FOR_ROUSTABOUT" || { \
        echo "build-arg SETUPTOOLS_SCM_PRETEND_VERSION_FOR_ROUSTABOUT is required" >&2; \
        echo "e.g. docker build --build-arg SETUPTOOLS_SCM_PRETEND_VERSION_FOR_ROUSTABOUT=\$(python -m setuptools_scm) ." >&2; \
        exit 1; }

RUN pip install --no-cache-dir --prefix=/install ".[server,mcp]"

# --- Runtime stage ---
FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

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
