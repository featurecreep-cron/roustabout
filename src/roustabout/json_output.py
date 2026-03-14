"""JSON serialization for roustabout data models.

Converts frozen dataclasses to JSON-safe dicts. Used for `--format json`
output, snapshot saving, and diff comparison.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from roustabout.auditor import Finding
from roustabout.models import DockerEnvironment


def environment_to_dict(env: DockerEnvironment) -> dict[str, Any]:
    """Convert a DockerEnvironment to a JSON-serializable dict."""
    d: dict[str, Any] = {
        "generated_at": env.generated_at,
        "docker_version": env.docker_version,
        "containers": [_container_to_dict(c) for c in env.containers],
        "warnings": list(env.warnings),
    }
    if env.daemon is not None:
        daemon = dataclasses.asdict(env.daemon)
        daemon["default_log_opts"] = dict(daemon["default_log_opts"])
        d["daemon"] = daemon
    return d


def environment_to_json(env: DockerEnvironment, indent: int = 2) -> str:
    """Serialize a DockerEnvironment to a JSON string."""
    return json.dumps(environment_to_dict(env), indent=indent)


def findings_to_json(findings: list[Finding], indent: int = 2) -> str:
    """Serialize audit findings to a JSON string."""
    return json.dumps(
        {
            "findings": [_finding_to_dict(f) for f in findings],
            "summary": _findings_summary(findings),
        },
        indent=indent,
    )


def _container_to_dict(c: Any) -> dict[str, Any]:
    """Convert a ContainerInfo to a JSON-serializable dict."""
    d = dataclasses.asdict(c)
    # Convert nested tuples of tuples back to dicts for readability
    d["env"] = dict(d["env"])
    d["labels"] = dict(d["labels"])
    d["sysctls"] = dict(d["sysctls"])
    d["log_opts"] = dict(d["log_opts"])
    # Convert port/mount/network tuples to lists of dicts (already done by asdict)
    return d


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    """Convert a Finding to a JSON-serializable dict."""
    return {
        "severity": f.severity.value,
        "category": f.category,
        "container": f.container,
        "explanation": f.explanation,
        "fix": f.fix,
        "detail": f.detail,
        "key": f.key,
    }


def _findings_summary(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts = {"critical": 0, "warning": 0, "info": 0, "total": len(findings)}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
