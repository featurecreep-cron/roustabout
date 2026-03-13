"""Finding state tracking for roustabout.

Persists user decisions about findings (accepted, false-positive, resolved)
across audit runs. State is stored in TOML files, separate from config.

State is applied at render time, not audit time. The auditor always
produces all findings. This module annotates them with user decisions.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


DEFAULT_STATE_PATHS = (
    Path("roustabout.state.toml"),
    Path.home() / ".config" / "roustabout" / "state.toml",
)


class FindingState(Enum):
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false-positive"
    RESOLVED = "resolved"


@dataclass(frozen=True)
class StateEntry:
    """A user decision about a specific finding."""

    state: FindingState
    reason: str
    timestamp: str


def load_state(path: Path | None = None) -> dict[str, StateEntry]:
    """Load finding state from a TOML file.

    Args:
        path: Explicit state file path. If None, searches default locations.

    Returns:
        Dict mapping finding keys to their state entries.
    """
    if path is not None:
        if not path.exists():
            return {}
        return _parse_state(path)

    for candidate in DEFAULT_STATE_PATHS:
        if candidate.exists():
            return _parse_state(candidate)

    return {}


def save_state(
    entries: dict[str, StateEntry],
    path: Path | None = None,
) -> Path:
    """Write finding state to a TOML file.

    Args:
        entries: Finding key -> state entry mapping.
        path: Where to write. Defaults to ./roustabout.state.toml.

    Returns:
        The path written to.
    """
    if path is None:
        path = DEFAULT_STATE_PATHS[0]

    lines = [
        "# Roustabout finding state — tracks user decisions about audit findings.",
        "# Edit manually or use `roustabout accept` / `roustabout false-positive`.",
        "",
    ]

    for key in sorted(entries.keys()):
        entry = entries[key]
        lines.append(f'[findings."{key}"]')
        lines.append(f'state = "{entry.state.value}"')
        # Escape any quotes in reason
        escaped_reason = entry.reason.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'reason = "{escaped_reason}"')
        lines.append(f'timestamp = "{entry.timestamp}"')
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))
    return path


def set_finding_state(
    finding_key: str,
    state: FindingState,
    reason: str,
    state_path: Path | None = None,
) -> Path:
    """Set or update the state of a single finding.

    Loads existing state, updates the entry, and saves back.
    """
    entries = load_state(state_path)
    entries[finding_key] = StateEntry(
        state=state,
        reason=reason,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    return save_state(entries, state_path)


def apply_state(
    findings: list[object],
    state_entries: dict[str, StateEntry],
) -> list[tuple[object, StateEntry | None]]:
    """Annotate findings with their state.

    Returns list of (finding, state_entry_or_none) tuples.
    Findings with state=RESOLVED whose issue has reappeared
    have their state cleared (returned as None with a warning).
    """
    result = []
    for finding in findings:
        entry = state_entries.get(finding.key)
        if entry and entry.state == FindingState.RESOLVED:
            # Finding reappeared after being marked resolved — regression
            entry = None
        result.append((finding, entry))
    return result


def _parse_state(path: Path) -> dict[str, StateEntry]:
    """Parse a state TOML file into StateEntry dict."""
    with open(path, "rb") as f:
        data = tomllib.load(f)

    findings_data = data.get("findings", {})
    entries: dict[str, StateEntry] = {}

    for key, value in findings_data.items():
        if not isinstance(value, dict):
            continue
        state_str = value.get("state", "")
        reason = value.get("reason", "")
        timestamp = value.get("timestamp", "")

        try:
            state = FindingState(state_str)
        except ValueError:
            continue  # skip invalid state entries

        entries[key] = StateEntry(state=state, reason=reason, timestamp=timestamp)

    return entries
