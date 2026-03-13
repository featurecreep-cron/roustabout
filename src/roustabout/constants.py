"""Shared constants for roustabout modules."""

# Labels managed by compose or baked into images — exclude from user-facing output
COMPOSE_LABEL_PREFIXES = (
    "com.docker.compose.",
    "com.docker.desktop.",
)

# Image metadata labels — always baked in, never user-set
IMAGE_LABEL_PREFIXES = (
    "org.opencontainers.image.",
    "org.label-schema.",
)
