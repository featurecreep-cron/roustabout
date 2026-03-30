"""First-seen digest tracking and pre-deploy compose audit.

Two primitives: digest state persistence (when did I first see this image
digest?) and static compose analysis (what security issues exist in a
compose file before deployment?). Callers compose these into safety gates.

LLD: docs/roustabout/designs/039-digest-tracking-predeploy-audit.md
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog
from ruamel.yaml import YAML

from roustabout.state_db import (
    DigestRow,
    StateDB,
    query_digest_age,
    query_digests,
    upsert_digest,
)

logger = structlog.get_logger()

_yaml = YAML()
_yaml.preserve_quotes = True

_SECRET_KEY_PATTERN = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AUTH_KEY"
    r"|CREDENTIAL|DB_PASS|MYSQL_ROOT|POSTGRES_PASSWORD"
    r"|REDIS_PASSWORD|SMTP_PASS|MAIL_PASSWORD|ENCRYPTION_KEY"
    r"|JWT_SECRET|AWS_SECRET|AZURE_KEY|GCP_KEY"
    r"|OAUTH_SECRET|OAUTH_CLIENT)",
    re.IGNORECASE,
)


# --- Data types ---


@dataclass(frozen=True)
class DigestRecord:
    """Digest observation with computed age."""

    image: str
    digest: str
    first_seen: datetime
    last_seen: datetime
    source: str
    age_hours: float


@dataclass(frozen=True)
class ComposeService:
    """Parsed service from a compose file."""

    name: str
    image: str
    privileged: bool
    cap_add: tuple[str, ...]
    volumes: tuple[str, ...]
    ports: tuple[str, ...]
    environment: dict[str, str]
    network_mode: str | None
    pid: str | None
    user: str | None
    restart: str | None
    healthcheck: bool
    mem_limit: str | None


@dataclass(frozen=True)
class PreDeployFinding:
    """Security finding from static compose analysis."""

    severity: str
    category: str
    service: str
    explanation: str
    detail: str = ""


@dataclass(frozen=True)
class DigestCheckResult:
    """Per-image digest cooldown check result."""

    service: str
    image: str
    digest: str | None
    first_seen: datetime | None
    age_hours: float | None
    meets_cooldown: bool


@dataclass(frozen=True)
class PreDeployReport:
    """Combined pre-deploy audit result."""

    findings: tuple[PreDeployFinding, ...]
    digest_results: tuple[DigestCheckResult, ...]
    passed: bool


# --- Digest tracking ---


def _row_to_record(row: DigestRow) -> DigestRecord:
    first = datetime.fromisoformat(row.first_seen)
    last = datetime.fromisoformat(row.last_seen)
    from datetime import UTC

    age = (datetime.now(UTC) - first).total_seconds() / 3600.0
    return DigestRecord(
        image=row.image,
        digest=row.digest,
        first_seen=first,
        last_seen=last,
        source=row.source,
        age_hours=age,
    )


def record_digest(
    db: StateDB,
    image: str,
    digest: str,
    *,
    host: str = "localhost",
    source: str = "registry",
) -> DigestRecord:
    """Record an observed digest. INSERT on first sight, UPDATE last_seen on repeat."""
    row = upsert_digest(db, image=image, digest=digest, host=host, source=source)
    return _row_to_record(row)


def get_digests(
    db: StateDB,
    image: str,
    *,
    host: str = "localhost",
) -> list[DigestRecord]:
    """Get all known digests for an image, newest first."""
    rows = query_digests(db, image=image, host=host)
    return [_row_to_record(r) for r in rows]


def digest_age(
    db: StateDB,
    image: str,
    digest: str,
    *,
    host: str = "localhost",
) -> float | None:
    """Hours since first seen. None if never seen."""
    return query_digest_age(db, image=image, digest=digest, host=host)


def check_digest_cooldown(
    db: StateDB,
    image: str,
    digest: str,
    *,
    min_hours: float = 24.0,
    host: str = "localhost",
) -> bool:
    """True if digest has been known for at least min_hours. False if new or too recent."""
    age = query_digest_age(db, image=image, digest=digest, host=host)
    if age is None:
        return False
    return age >= min_hours


# --- Compose parsing ---


def _parse_environment(raw: Any) -> dict[str, str]:
    """Parse compose environment in dict or list form."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        result: dict[str, str] = {}
        for item in raw:
            item_str = str(item)
            if "=" in item_str:
                key, _, value = item_str.partition("=")
                result[key] = value
            else:
                result[item_str] = ""
        return result
    return {}


def parse_compose_services(compose_path: Path) -> list[ComposeService]:
    """Parse a compose file into structured service definitions."""
    with open(compose_path) as f:
        content = _yaml.load(f)

    if not content or not isinstance(content.get("services"), dict):
        return []

    services = []
    for name, svc in content["services"].items():
        if not isinstance(svc, dict):
            continue

        deploy = svc.get("deploy", {}) or {}
        resources = deploy.get("resources", {}) or {}
        limits = resources.get("limits", {}) or {}

        services.append(
            ComposeService(
                name=str(name),
                image=str(svc.get("image", "")),
                privileged=bool(svc.get("privileged", False)),
                cap_add=tuple(str(c) for c in (svc.get("cap_add") or [])),
                volumes=tuple(str(v) for v in (svc.get("volumes") or [])),
                ports=tuple(str(p) for p in (svc.get("ports") or [])),
                environment=_parse_environment(svc.get("environment")),
                network_mode=svc.get("network_mode"),
                pid=svc.get("pid"),
                user=svc.get("user"),
                restart=svc.get("restart") or deploy.get("restart_policy", {}).get("condition"),
                healthcheck="healthcheck" in svc,
                mem_limit=str(limits.get("memory", svc.get("mem_limit", ""))) or None,
            )
        )
    return services


# --- Static compose checks ---

_DANGEROUS_CAPS = frozenset(
    {
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "NET_ADMIN",
        "NET_RAW",
        "DAC_READ_SEARCH",
        "LINUX_IMMUTABLE",
        "SYS_MODULE",
        "SYS_BOOT",
    }
)

_SENSITIVE_MOUNTS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/proc",
    "/sys",
    "/dev",
    "/etc/shadow",
    "/etc/passwd",
    "/root",
)


def _check_service_static(svc: ComposeService) -> list[PreDeployFinding]:
    """Run all static checks against a single compose service."""
    findings: list[PreDeployFinding] = []

    # Docker socket
    for vol in svc.volumes:
        vol_src = vol.split(":")[0] if ":" in vol else vol
        if "docker.sock" in vol_src:
            findings.append(
                PreDeployFinding(
                    severity="critical",
                    category="docker-socket",
                    service=svc.name,
                    explanation="Docker socket mounted — grants full host control",
                    detail=vol,
                )
            )

    # Privileged mode
    if svc.privileged:
        findings.append(
            PreDeployFinding(
                severity="critical",
                category="privileged",
                service=svc.name,
                explanation="Privileged mode — container has full host kernel access",
            )
        )

    # Dangerous capabilities
    for cap in svc.cap_add:
        if cap in _DANGEROUS_CAPS:
            findings.append(
                PreDeployFinding(
                    severity="warning",
                    category="dangerous-capability",
                    service=svc.name,
                    explanation=f"Dangerous capability {cap}",
                    detail=cap,
                )
            )

    # Sensitive host mounts
    for vol in svc.volumes:
        vol_src = vol.split(":")[0] if ":" in vol else vol
        for sensitive in _SENSITIVE_MOUNTS:
            if vol_src == sensitive or vol_src.startswith(sensitive + "/"):
                if "docker.sock" in vol_src:
                    continue  # already flagged above
                findings.append(
                    PreDeployFinding(
                        severity="warning",
                        category="sensitive-mount",
                        service=svc.name,
                        explanation=f"Sensitive host path mounted: {sensitive}",
                        detail=vol,
                    )
                )

    # Host network mode
    if svc.network_mode == "host":
        findings.append(
            PreDeployFinding(
                severity="warning",
                category="host-network",
                service=svc.name,
                explanation="Host network mode — container shares host network stack",
            )
        )

    # Host PID mode
    if svc.pid == "host":
        findings.append(
            PreDeployFinding(
                severity="warning",
                category="host-pid",
                service=svc.name,
                explanation="Host PID namespace — container can see all host processes",
            )
        )

    # Secrets in environment
    for key, value in svc.environment.items():
        if _SECRET_KEY_PATTERN.search(key) and value and not re.match(r"^\$\{.+\}$", value):
            findings.append(
                PreDeployFinding(
                    severity="warning",
                    category="secrets-in-env",
                    service=svc.name,
                    explanation=f"Potential secret in environment variable {key}",
                    detail=key,
                )
            )

    # No health check
    if not svc.healthcheck:
        findings.append(
            PreDeployFinding(
                severity="info",
                category="no-healthcheck",
                service=svc.name,
                explanation="No health check configured",
            )
        )

    # No restart policy
    if not svc.restart:
        findings.append(
            PreDeployFinding(
                severity="info",
                category="no-restart-policy",
                service=svc.name,
                explanation="No restart policy — container won't recover from crashes",
            )
        )

    # Stale image (latest or no tag)
    if svc.image:
        tag = svc.image.rsplit(":", 1)[-1] if ":" in svc.image else ""
        if tag == "latest" or (not tag and "@sha256:" not in svc.image):
            findings.append(
                PreDeployFinding(
                    severity="info",
                    category="stale-image",
                    service=svc.name,
                    explanation="Image uses :latest or no tag — not pinned to a specific version",
                    detail=svc.image,
                )
            )

    # No resource limits
    if not svc.mem_limit:
        findings.append(
            PreDeployFinding(
                severity="info",
                category="no-resource-limits",
                service=svc.name,
                explanation="No memory limit — container can consume all host memory",
            )
        )

    return findings


def check_compose_static(compose_path: Path) -> list[PreDeployFinding]:
    """Run static security checks against a compose file."""
    services = parse_compose_services(compose_path)
    findings: list[PreDeployFinding] = []
    for svc in services:
        findings.extend(_check_service_static(svc))
    return findings


# --- Registry digest resolution ---


def _resolve_service_digest(
    image: str,
    timeout: int = 30,
) -> tuple[str | None, int | None]:
    """Resolve current digest for an image from the registry."""
    from roustabout.supply_chain import _query_registry_digest

    return _query_registry_digest(image, timeout)


# --- Pre-deploy audit orchestration ---


def audit_predeploy(
    compose_path: Path,
    db: StateDB,
    *,
    cooldown_hours: float = 24.0,
    registry_timeout: int = 30,
    host: str = "localhost",
) -> PreDeployReport:
    """Audit a compose file before deployment.

    1. Parse compose YAML
    2. Run static checks
    3. Resolve digests from registry
    4. Record digests in state_db
    5. Check cooldown for each digest
    6. Return combined report
    """
    # Static checks
    findings = check_compose_static(compose_path)

    # Digest checks — skip services without images (build-only)
    services = parse_compose_services(compose_path)
    digest_results: list[DigestCheckResult] = []

    for svc in services:
        if not svc.image:
            continue

        try:
            resolved_digest, _age = _resolve_service_digest(svc.image, timeout=registry_timeout)
        except Exception:  # noqa: BLE001
            logger.warning("digest_resolution_failed", image=svc.image)
            resolved_digest = None

        if resolved_digest:
            record = record_digest(db, svc.image, resolved_digest, host=host, source="registry")
            meets = check_digest_cooldown(
                db, svc.image, resolved_digest, min_hours=cooldown_hours, host=host
            )
            digest_results.append(
                DigestCheckResult(
                    service=svc.name,
                    image=svc.image,
                    digest=resolved_digest,
                    first_seen=record.first_seen,
                    age_hours=record.age_hours,
                    meets_cooldown=meets,
                )
            )
        else:
            digest_results.append(
                DigestCheckResult(
                    service=svc.name,
                    image=svc.image,
                    digest=None,
                    first_seen=None,
                    age_hours=None,
                    meets_cooldown=False,
                )
            )

    has_critical = any(f.severity == "critical" for f in findings)
    all_digests_pass = all(r.meets_cooldown for r in digest_results)
    passed = not has_critical and all_digests_pass

    return PreDeployReport(
        findings=tuple(findings),
        digest_results=tuple(digest_results),
        passed=passed,
    )
