"""Tests for finding state tracking."""

from roustabout.auditor import Finding, Severity
from roustabout.state import (
    FindingState,
    StateEntry,
    apply_state,
    load_state,
    save_state,
    set_finding_state,
)


class TestFindingKey:
    def test_simple_key(self):
        f = Finding(Severity.CRITICAL, "docker-socket", "portainer", "exp", "fix")
        assert f.key == "portainer|docker-socket"

    def test_key_with_detail(self):
        f = Finding(Severity.WARNING, "secrets-in-env", "app", "exp", "fix", detail="DB_PASSWORD")
        assert f.key == "app|secrets-in-env|DB_PASSWORD"

    def test_key_no_detail(self):
        f = Finding(Severity.INFO, "no-healthcheck", "nginx", "exp", "fix")
        assert f.key == "nginx|no-healthcheck"


class TestLoadState:
    def test_load_from_file(self, tmp_path):
        state_file = tmp_path / "state.toml"
        state_file.write_text(
            '[findings."portainer|docker-socket"]\n'
            'state = "accepted"\n'
            'reason = "Portainer needs it"\n'
            'timestamp = "2026-03-12T00:00:00Z"\n'
        )
        entries = load_state(state_file)
        assert "portainer|docker-socket" in entries
        entry = entries["portainer|docker-socket"]
        assert entry.state == FindingState.ACCEPTED
        assert entry.reason == "Portainer needs it"

    def test_load_nonexistent_returns_empty(self, tmp_path):
        entries = load_state(tmp_path / "nope.toml")
        assert entries == {}

    def test_load_default_returns_empty_if_no_file(self):
        entries = load_state()
        assert isinstance(entries, dict)

    def test_invalid_state_value_skipped(self, tmp_path):
        state_file = tmp_path / "state.toml"
        state_file.write_text(
            '[findings."x|y"]\n'
            'state = "bogus"\n'
            'reason = "test"\n'
            'timestamp = "2026-03-12T00:00:00Z"\n'
        )
        entries = load_state(state_file)
        assert len(entries) == 0


class TestSaveState:
    def test_roundtrip(self, tmp_path):
        state_file = tmp_path / "state.toml"
        entries = {
            "portainer|docker-socket": StateEntry(
                state=FindingState.ACCEPTED,
                reason="Portainer needs it",
                timestamp="2026-03-12T00:00:00Z",
            ),
            "app|secrets-in-env|DB_PASSWORD": StateEntry(
                state=FindingState.FALSE_POSITIVE,
                reason="Not a real secret",
                timestamp="2026-03-12T01:00:00Z",
            ),
        }
        save_state(entries, state_file)
        loaded = load_state(state_file)
        assert len(loaded) == 2
        assert loaded["portainer|docker-socket"].state == FindingState.ACCEPTED
        assert loaded["app|secrets-in-env|DB_PASSWORD"].state == FindingState.FALSE_POSITIVE

    def test_creates_parent_dirs(self, tmp_path):
        state_file = tmp_path / "sub" / "dir" / "state.toml"
        save_state({}, state_file)
        assert state_file.exists()


class TestSetFindingState:
    def test_creates_new_entry(self, tmp_path):
        state_file = tmp_path / "state.toml"
        set_finding_state("nginx|no-healthcheck", FindingState.ACCEPTED, "Don't care", state_file)
        entries = load_state(state_file)
        assert "nginx|no-healthcheck" in entries
        assert entries["nginx|no-healthcheck"].state == FindingState.ACCEPTED

    def test_updates_existing_entry(self, tmp_path):
        state_file = tmp_path / "state.toml"
        set_finding_state("x|y", FindingState.ACCEPTED, "first", state_file)
        set_finding_state("x|y", FindingState.RESOLVED, "fixed now", state_file)
        entries = load_state(state_file)
        assert entries["x|y"].state == FindingState.RESOLVED
        assert entries["x|y"].reason == "fixed now"


class TestApplyState:
    def _finding(self, container, category, detail=""):
        return Finding(Severity.WARNING, category, container, "exp", "fix", detail=detail)

    def test_no_state_returns_none(self):
        findings = [self._finding("nginx", "no-healthcheck")]
        result = apply_state(findings, {})
        assert result == [(findings[0], None)]

    def test_accepted_state_applied(self):
        findings = [self._finding("portainer", "docker-socket")]
        state = {
            "portainer|docker-socket": StateEntry(FindingState.ACCEPTED, "needs it", "2026-03-12"),
        }
        result = apply_state(findings, state)
        assert result[0][1].state == FindingState.ACCEPTED

    def test_resolved_clears_on_reappearance(self):
        """If a finding was resolved but reappears, clear the resolved state."""
        findings = [self._finding("nginx", "no-healthcheck")]
        state = {
            "nginx|no-healthcheck": StateEntry(
                FindingState.RESOLVED, "added healthcheck", "2026-03-12"
            ),
        }
        result = apply_state(findings, state)
        assert result[0][1] is None  # state cleared — finding is back

    def test_false_positive_persists(self):
        findings = [self._finding("app", "secrets-in-env", "AUTHOR_NAME")]
        state = {
            "app|secrets-in-env|AUTHOR_NAME": StateEntry(
                FindingState.FALSE_POSITIVE, "Not a secret", "2026-03-12"
            ),
        }
        result = apply_state(findings, state)
        assert result[0][1].state == FindingState.FALSE_POSITIVE


class TestSeverityOverrides:
    def test_override_changes_severity(self):
        from roustabout.auditor import audit
        from roustabout.models import make_container, make_environment

        env = make_environment(
            containers=[
                make_container(
                    name="test",
                    id="abc",
                    status="running",
                    image="nginx:1.25",
                    image_id="sha256:abc",
                    health=None,
                )
            ],
            generated_at="2026-03-12T00:00:00Z",
            docker_version="25.0.3",
        )
        findings = audit(env, severity_overrides={"no-healthcheck": "warning"})
        healthcheck = next(f for f in findings if f.category == "no-healthcheck")
        assert healthcheck.severity == Severity.WARNING

    def test_override_unknown_category_ignored(self):
        from roustabout.auditor import audit
        from roustabout.models import make_container, make_environment

        env = make_environment(
            containers=[
                make_container(
                    name="test",
                    id="abc",
                    status="running",
                    image="nginx:1.25",
                    image_id="sha256:abc",
                )
            ],
            generated_at="2026-03-12T00:00:00Z",
            docker_version="25.0.3",
        )
        # Should not crash
        findings = audit(env, severity_overrides={"nonexistent-check": "critical"})
        assert isinstance(findings, list)
