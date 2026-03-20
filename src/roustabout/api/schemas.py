"""Pydantic request/response models for the REST API.

These wrap core frozen dataclasses for HTTP serialization — they don't replace them.
"""

from __future__ import annotations

from pydantic import BaseModel


class ContainerSummary(BaseModel):
    """Subset of ContainerInfo for snapshot responses."""

    name: str
    image: str
    status: str


class SnapshotResponse(BaseModel):
    """Full environment snapshot."""

    containers: list[ContainerSummary]


class FindingResponse(BaseModel):
    """Single audit finding."""

    check: str
    severity: str
    container: str | None
    message: str


class AuditResponse(BaseModel):
    """Audit results."""

    findings: list[FindingResponse]


class MutationResponse(BaseModel):
    """Result of a container mutation."""

    result: str
    container: str
    action: str
    pre_hash: str | None = None
    post_hash: str | None = None
    error: str | None = None


class HealthEntry(BaseModel):
    """Container health status."""

    name: str
    status: str
    health: str | None
    restart_count: int
    oom_killed: bool


class LogResponse(BaseModel):
    """Container log output."""

    container: str
    lines: str


class CapabilitiesResponse(BaseModel):
    """Capabilities for the authenticated API key."""

    tier: str
    label: str
    capabilities: list[str]


class ErrorResponse(BaseModel):
    """Standard error envelope."""

    error: str
    detail: str | None = None
