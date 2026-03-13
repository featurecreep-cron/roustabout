"""Render audit findings as structured markdown.

Separated from auditor.py (analysis) to keep presentation concerns
independent from audit logic.
"""

from __future__ import annotations

from roustabout.auditor import Finding, Severity
from roustabout.state import FindingState, StateEntry, apply_state


def render_findings(
    findings: list[Finding],
    state_entries: dict[str, StateEntry] | None = None,
    hide_accepted: bool = False,
) -> str:
    """Render audit findings as structured markdown.

    Groups findings by category across containers to reduce repetition.
    Each category appears once with its explanation, listing affected containers.

    Args:
        findings: List of findings from audit().
        state_entries: Optional dict mapping finding keys to StateEntry objects.
        hide_accepted: If True, suppress accepted and false-positive findings.
    """
    if state_entries is None:
        state_entries = {}

    annotated = apply_state(findings, state_entries)

    _suppressed_states = {FindingState.ACCEPTED, FindingState.FALSE_POSITIVE}
    if hide_accepted:
        annotated = [
            (f, s) for f, s in annotated if s is None or s.state not in _suppressed_states
        ]

    if not annotated:
        return "# Security Audit\n\nNo findings.\n"

    actionable = [(f, s) for f, s in annotated if s is None or s.state not in _suppressed_states]
    dismissed = [(f, s) for f, s in annotated if s is not None and s.state in _suppressed_states]

    lines = ["# Security Audit", ""]

    # Summary counts
    all_findings = [f for f, _ in annotated]
    critical = [f for f in all_findings if f.severity == Severity.CRITICAL]
    warnings = [f for f in all_findings if f.severity == Severity.WARNING]
    infos = [f for f in all_findings if f.severity == Severity.INFO]

    summary = (
        f"**{len(all_findings)} findings:** "
        f"{len(critical)} critical, {len(warnings)} warning, {len(infos)} info"
    )
    if dismissed:
        summary += f" ({len(actionable)} actionable, {len(dismissed)} accepted)"
    lines.append(summary)
    lines.append("")

    # Table of contents
    for sev_label in ("Critical", "Warning", "Info"):
        sev_findings = [f for f in all_findings if f.severity.value.title() == sev_label]
        if sev_findings:
            categories = sorted({f.category for f in sev_findings})
            lines.append(f"- **{sev_label} ({len(sev_findings)}):** {', '.join(categories)}")
    lines.append("")

    # Group findings by (severity, category) for compact output
    _render_grouped_findings(lines, annotated, _suppressed_states)

    return "\n".join(lines) + "\n"


def _render_grouped_findings(
    lines: list[str],
    annotated: list[tuple[Finding, StateEntry | None]],
    suppressed_states: set[FindingState],
) -> None:
    """Render findings grouped by severity then category.

    Instead of one heading per finding, groups findings by category
    and lists affected containers. Reduces repetition significantly
    for environments with many containers sharing the same issue.
    """
    current_severity = None

    # Group by (severity, category)
    groups: dict[tuple[Severity, str], list[tuple[Finding, StateEntry | None]]] = {}
    for finding, state in annotated:
        key = (finding.severity, finding.category)
        groups.setdefault(key, []).append((finding, state))

    for (severity, category), group in groups.items():
        if severity != current_severity:
            current_severity = severity
            lines.append(f"## {current_severity.value.title()}")
            lines.append("")

        # All findings in a group share the same explanation and fix
        sample = group[0][0]

        # Collect containers and their states
        containers: list[str] = []
        has_suppressed = False
        for finding, state in group:
            label = finding.container
            if finding.detail:
                label += f" ({finding.detail})"
            if state is not None and state.state in suppressed_states:
                state_label = state.state.value.upper()
                label += f" [{state_label}]"
                has_suppressed = True
            containers.append(label)

        lines.append(f"### {category}")
        lines.append("")

        # Container list
        if len(containers) == 1 and containers[0] == "(all)":
            lines.append("**Scope:** all running containers")
        else:
            lines.append(f"**Containers ({len(containers)}):** {', '.join(containers)}")
        lines.append("")

        lines.append(sample.explanation)
        lines.append("")

        # Show fix for actionable findings, or suppression info
        if has_suppressed:
            for finding, state in group:
                if state is not None and state.state in suppressed_states:
                    state_label = (
                        "Accepted" if state.state == FindingState.ACCEPTED else "False positive"
                    )
                    lines.append(f"**{state_label} ({finding.container}):** {state.reason}")
            lines.append("")

        lines.append(f"**Fix:** {sample.fix}")
        lines.append("")
