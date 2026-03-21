"""DirectBackend — calls roustabout core inline, no server required.

Used for read operations when no ROUSTABOUT_URL is configured.
"""

from __future__ import annotations

from typing import Any


class DirectBackend:
    """Executes roustabout operations by importing core directly."""

    def snapshot(self, *, redact: bool = True, fmt: str = "json") -> dict[str, Any] | str:
        from roustabout.collector import collect
        from roustabout.config import load_config
        from roustabout.connection import connect
        from roustabout.json_output import environment_to_dict
        from roustabout.redactor import redact as redact_env
        from roustabout.redactor import resolve_patterns
        from roustabout.renderer import render

        config = load_config()
        client = connect(config.docker_host)
        try:
            env = collect(client)
            if redact:
                patterns = resolve_patterns(config.redact_patterns)
                env = redact_env(env, patterns)
            if fmt == "markdown":
                return render(env, show_env=config.show_env, show_labels=config.show_labels)
            return environment_to_dict(env)
        finally:
            client.close()

    def audit(self) -> dict[str, Any]:
        from roustabout.auditor import audit as run_audit
        from roustabout.collector import collect
        from roustabout.config import load_config
        from roustabout.connection import connect
        from roustabout.redactor import resolve_patterns

        config = load_config()
        client = connect(config.docker_host)
        try:
            env = collect(client)
            patterns = resolve_patterns(config.redact_patterns)
            findings = run_audit(env, patterns)
            return {
                "findings": [
                    {
                        "check": f.category,
                        "severity": f.severity.value,
                        "container": f.container,
                        "message": f.explanation,
                    }
                    for f in findings
                ],
            }
        finally:
            client.close()

    def health(self, name: str | None = None) -> dict[str, Any]:
        from roustabout.config import load_config
        from roustabout.connection import connect
        from roustabout.health_stats import collect_health

        config = load_config()
        client = connect(config.docker_host)
        try:
            healths = collect_health(client)
            if name:
                healths = [h for h in healths if h.name == name]
            return {
                "entries": [
                    {
                        "name": h.name,
                        "status": h.status,
                        "health": h.health,
                        "restart_count": h.restart_count,
                        "oom_killed": h.oom_killed,
                    }
                    for h in healths
                ],
            }
        finally:
            client.close()

    def logs(
        self,
        name: str,
        tail: int = 100,
        since: str | None = None,
        grep: str | None = None,
    ) -> dict[str, Any]:
        from roustabout.config import load_config
        from roustabout.connection import connect
        from roustabout.log_access import collect_logs

        config = load_config()
        client = connect(config.docker_host)
        try:
            text = collect_logs(client, name, tail=tail, since=since, grep=grep)
            return {"container": name, "lines": text}
        finally:
            client.close()

    def dr_plan(self) -> dict[str, Any]:
        from roustabout.collector import collect
        from roustabout.config import load_config
        from roustabout.connection import connect
        from roustabout.dr_plan import generate
        from roustabout.redactor import redact as redact_env
        from roustabout.redactor import resolve_patterns, sanitize_environment

        config = load_config()
        client = connect(config.docker_host)
        try:
            env = collect(client)
            env = sanitize_environment(env)
            patterns = resolve_patterns(config.redact_patterns)
            env = redact_env(env, patterns)
            plan = generate(env)
            return {"plan": plan}
        finally:
            client.close()

    def mutate(self, name: str, action: str, dry_run: bool = False) -> dict[str, Any]:
        raise RuntimeError("DirectBackend cannot execute mutations — server required")

    def capabilities(self) -> dict[str, Any]:
        raise RuntimeError("DirectBackend has no auth context — server required")
