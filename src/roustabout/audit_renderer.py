"""Render audit findings as structured markdown.

Separated from auditor.py (analysis) to keep presentation concerns
independent from audit logic.

Design principle: each check type's explanation and fix appear exactly once.
Affected containers are listed compactly. Detail varies only where it adds
information (e.g., which env vars are exposed, which ports are bound).
"""

from __future__ import annotations

from roustabout.auditor import Finding, Severity
from roustabout.state import FindingState, StateEntry, apply_state

# Categories where the detail field carries per-container information
# worth showing in a table (env var name, mount path, port, capability).
_DETAIL_CATEGORIES = {
    "secrets-in-env",
    "sensitive-mount",
    "exposed-port",
    "stale-image",
    "dangerous-capability",
}


def render_findings(
    findings: list[Finding],
    state_entries: dict[str, StateEntry] | None = None,
    hide_accepted: bool = False,
) -> str:
    """Render audit findings as structured markdown.

    Groups findings by (severity, category). Each category's explanation
    and fix text appear once. Affected containers listed compactly.

    Args:
        findings: List of findings from audit().
        state_entries: Optional dict mapping finding keys to StateEntry objects.
        hide_accepted: If True, suppress accepted and false-positive findings.
    """
    if state_entries is None:
        state_entries = {}

    annotated = apply_state(findings, state_entries)

    suppressed_states = {FindingState.ACCEPTED, FindingState.FALSE_POSITIVE}
    if hide_accepted:
        annotated = [(f, s) for f, s in annotated if s is None or s.state not in suppressed_states]

    if not annotated:
        return "# Security Audit\n\nNo findings.\n"

    actionable = [(f, s) for f, s in annotated if s is None or s.state not in suppressed_states]
    dismissed = [(f, s) for f, s in annotated if s is not None and s.state in suppressed_states]

    lines = ["# Security Audit", ""]

    # Summary line
    all_findings = [f for f, _ in annotated]
    by_sev = _count_by_severity(all_findings)

    summary = f"**{len(all_findings)} findings:** "
    parts = []
    for sev in (Severity.CRITICAL, Severity.WARNING, Severity.INFO):
        if by_sev[sev]:
            label = sev.value
            parts.append(f"**{by_sev[sev]} {label}**")
    summary += ", ".join(parts)
    if dismissed:
        summary += f" ({len(actionable)} actionable, {len(dismissed)} accepted)"
    lines.append(summary)
    lines.append("")

    # Summary table — one row per (severity, category) group, not per finding
    lines.append("| Severity | Check | Count | Containers |")
    lines.append("|----------|-------|-------|------------|")

    groups = _group_findings(annotated)
    for (severity, category), group in groups.items():
        containers = sorted({f.container for f, _ in group})
        container_str = ", ".join(containers[:5])
        if len(containers) > 5:
            container_str += f", +{len(containers) - 5} more"
        lines.append(f"| {severity.value.title()} | {category} | {len(group)} | {container_str} |")
    lines.append("")

    # Detailed sections by severity
    current_severity = None
    for (severity, category), group in groups.items():
        if severity != current_severity:
            current_severity = severity
            lines.append("---")
            lines.append("")
            lines.append(f"## {current_severity.value.title()}")
            lines.append("")

        _render_group(lines, category, group, suppressed_states)

    return "\n".join(lines) + "\n"


def _render_group(
    lines: list[str],
    category: str,
    group: list[tuple[Finding, StateEntry | None]],
    suppressed_states: set[FindingState],
) -> None:
    """Render a single (severity, category) group.

    Explanation and fix appear once. Container listing adapts to detail level.
    """
    sample = group[0][0]
    containers = sorted({f.container for f, _ in group})
    count_label = f"{len(containers)} container{'s' if len(containers) != 1 else ''}"

    if category in _DETAIL_CATEGORIES:
        detail_count = len(group)
        if detail_count != len(containers):
            count_label += f", {detail_count} findings"

    lines.append(f"### {category} — {count_label}")
    lines.append("")
    lines.append(sample.explanation)
    lines.append("")

    # Adaptive detail rendering
    if category in _DETAIL_CATEGORIES:
        _render_detail_table(lines, category, group)
    elif len(containers) == 1 and containers[0] == "(all)":
        pass  # explanation already covers it
    elif len(containers) <= 8:
        lines.append(", ".join(containers))
        lines.append("")
    else:
        # Wrap long lists
        lines.append(", ".join(containers))
        lines.append("")

    # State annotations for suppressed findings
    suppressed = [(f, s) for f, s in group if s is not None and s.state in suppressed_states]
    if suppressed:
        for finding, state in suppressed:
            state_label = "Accepted" if state.state == FindingState.ACCEPTED else "False positive"
            lines.append(f"*{state_label} ({finding.container}):* {state.reason}")
        lines.append("")

    lines.append(f"**Fix:** {sample.fix}")
    lines.append("")


def _render_detail_table(
    lines: list[str],
    category: str,
    group: list[tuple[Finding, StateEntry | None]],
) -> None:
    """Render a table with per-finding detail for categories that have it."""
    if category == "secrets-in-env":
        # Group by container, list env vars per container
        by_container: dict[str, list[str]] = {}
        for finding, _ in group:
            by_container.setdefault(finding.container, []).append(f"`{finding.detail}`")

        lines.append("| Container | Exposed Variables |")
        lines.append("|-----------|-------------------|")
        for container in sorted(by_container):
            vars_str = ", ".join(sorted(by_container[container]))
            lines.append(f"| {container} | {vars_str} |")
        lines.append("")

    elif category == "sensitive-mount":
        lines.append("| Container | Host Path |")
        lines.append("|-----------|-----------|")
        for finding, _ in group:
            lines.append(f"| {finding.container} | `{finding.detail}` |")
        lines.append("")

    elif category == "exposed-port":
        lines.append("| Container | Port |")
        lines.append("|-----------|------|")
        for finding, _ in group:
            lines.append(f"| {finding.container} | {finding.detail} |")
        lines.append("")

    elif category == "stale-image":
        # Extract image from explanation
        lines.append("| Container |")
        lines.append("|-----------|")
        for finding, _ in group:
            lines.append(f"| {finding.container} |")
        lines.append("")

    elif category == "dangerous-capability":
        # Group by container, list capabilities
        by_container: dict[str, list[str]] = {}
        for finding, _ in group:
            by_container.setdefault(finding.container, []).append(f"`{finding.detail}`")

        lines.append("| Container | Capabilities |")
        lines.append("|-----------|-------------|")
        for container in sorted(by_container):
            caps_str = ", ".join(sorted(by_container[container]))
            lines.append(f"| {container} | {caps_str} |")
        lines.append("")

    else:
        # Fallback: simple container list
        containers = sorted({f.container for f, _ in group})
        lines.append(", ".join(containers))
        lines.append("")


def _group_findings(
    annotated: list[tuple[Finding, StateEntry | None]],
) -> dict[tuple[Severity, str], list[tuple[Finding, StateEntry | None]]]:
    """Group findings by (severity, category), preserving severity order."""
    groups: dict[tuple[Severity, str], list[tuple[Finding, StateEntry | None]]] = {}
    for finding, state in annotated:
        key = (finding.severity, finding.category)
        groups.setdefault(key, []).append((finding, state))
    return groups


def _count_by_severity(findings: list[Finding]) -> dict[Severity, int]:
    """Count findings per severity level."""
    counts = {Severity.CRITICAL: 0, Severity.WARNING: 0, Severity.INFO: 0}
    for f in findings:
        counts[f.severity] += 1
    return counts
