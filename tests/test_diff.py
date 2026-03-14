"""Tests for snapshot diff."""

import json

from roustabout.diff import diff_dicts, render_diff


def _snapshot(*containers, generated_at="2026-03-13T00:00:00Z"):
    """Build a minimal snapshot dict."""
    return {
        "generated_at": generated_at,
        "docker_version": "25.0.3",
        "containers": list(containers),
        "warnings": [],
    }


def _container(name="test", image="nginx:1.25", **kwargs):
    """Build a minimal container dict."""
    c = {
        "name": name,
        "id": "abc123",
        "status": "running",
        "image": image,
        "image_id": "sha256:abc",
        "ports": [],
        "mounts": [],
        "networks": [],
        "env": {},
        "labels": {},
        **kwargs,
    }
    return c


class TestDiffContainers:
    def test_no_changes(self):
        old = _snapshot(_container())
        new = _snapshot(_container(), generated_at="2026-03-14T00:00:00Z")
        result = diff_dicts(old, new)
        assert len(result.added) == 0
        assert len(result.removed) == 0
        assert len(result.changed) == 0

    def test_added_container(self):
        old = _snapshot(_container(name="web"))
        new = _snapshot(_container(name="web"), _container(name="db"))
        result = diff_dicts(old, new)
        assert result.added == ("db",)
        assert len(result.removed) == 0

    def test_removed_container(self):
        old = _snapshot(_container(name="web"), _container(name="db"))
        new = _snapshot(_container(name="web"))
        result = diff_dicts(old, new)
        assert result.removed == ("db",)
        assert len(result.added) == 0

    def test_changed_image(self):
        old = _snapshot(_container(name="web", image="nginx:1.24"))
        new = _snapshot(_container(name="web", image="nginx:1.25"))
        result = diff_dicts(old, new)
        assert len(result.changed) == 1
        assert result.changed[0].name == "web"
        changes = {c.field: c for c in result.changed[0].changes}
        assert "image" in changes
        assert changes["image"].old == "nginx:1.24"
        assert changes["image"].new == "nginx:1.25"

    def test_changed_env(self):
        old = _snapshot(_container(env={"FOO": "bar"}))
        new = _snapshot(_container(env={"FOO": "baz", "NEW": "val"}))
        result = diff_dicts(old, new)
        assert len(result.changed) == 1
        changes = {c.field: c for c in result.changed[0].changes}
        assert "env" in changes
        assert "added: NEW" in changes["env"].new
        assert "changed: FOO" in changes["env"].new

    def test_changed_ports(self):
        port_80 = {
            "host_ip": "0.0.0.0",
            "host_port": "80",
            "container_port": 80,
            "protocol": "tcp",
        }
        port_8080 = {
            "host_ip": "0.0.0.0",
            "host_port": "8080",
            "container_port": 80,
            "protocol": "tcp",
        }
        old = _snapshot(_container(ports=[port_80]))
        new = _snapshot(_container(ports=[port_8080]))
        result = diff_dicts(old, new)
        assert len(result.changed) == 1
        changes = {c.field: c for c in result.changed[0].changes}
        assert "ports" in changes


class TestDiffFiles:
    def test_diff_from_files(self, tmp_path):
        old = _snapshot(_container(name="web"))
        new = _snapshot(_container(name="web"), _container(name="db"))

        old_path = tmp_path / "old.json"
        new_path = tmp_path / "new.json"
        old_path.write_text(json.dumps(old))
        new_path.write_text(json.dumps(new))

        from roustabout.diff import diff_snapshots

        result = diff_snapshots(old_path, new_path)
        assert result.added == ("db",)


class TestRenderDiff:
    def test_no_changes(self):
        old = _snapshot(_container())
        new = _snapshot(_container())
        result = diff_dicts(old, new)
        md = render_diff(result)
        assert "No changes detected" in md

    def test_renders_added_removed_changed(self):
        old = _snapshot(_container(name="web"), _container(name="old-svc", image="old:1"))
        new = _snapshot(
            _container(name="web", image="nginx:1.26"),
            _container(name="new-svc"),
        )
        result = diff_dicts(old, new)
        md = render_diff(result)
        assert "## Added" in md
        assert "new-svc" in md
        assert "## Removed" in md
        assert "old-svc" in md
        assert "## Changed" in md
        assert "### web" in md
