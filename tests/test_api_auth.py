"""Tests for API authentication layer.

Covers: API key resolution, tier mapping, auth failure responses.
"""

from __future__ import annotations

import pytest

from roustabout.api.auth import AuthConfig, AuthError, resolve_api_key


class TestResolveApiKey:
    """API key → tier resolution."""

    def test_valid_key_returns_tier(self):
        config = AuthConfig(
            keys={
                "sk-test-123": {"tier": "observe", "label": "test-key"},
            }
        )
        result = resolve_api_key("sk-test-123", config)
        assert result.tier == "observe"
        assert result.label == "test-key"

    def test_operate_tier_key(self):
        config = AuthConfig(
            keys={
                "sk-op-456": {"tier": "operate", "label": "mcp-proxy"},
            }
        )
        result = resolve_api_key("sk-op-456", config)
        assert result.tier == "operate"

    def test_elevate_tier_key(self):
        config = AuthConfig(
            keys={
                "sk-admin-789": {"tier": "elevate", "label": "admin"},
            }
        )
        result = resolve_api_key("sk-admin-789", config)
        assert result.tier == "elevate"

    def test_unknown_key_raises_auth_error(self):
        config = AuthConfig(
            keys={
                "sk-test-123": {"tier": "observe", "label": "test"},
            }
        )
        with pytest.raises(AuthError, match="invalid"):
            resolve_api_key("sk-wrong-key", config)

    def test_empty_key_raises_auth_error(self):
        config = AuthConfig(keys={})
        with pytest.raises(AuthError, match="invalid"):
            resolve_api_key("", config)

    def test_none_key_raises_auth_error(self):
        config = AuthConfig(keys={})
        with pytest.raises(AuthError, match="missing"):
            resolve_api_key(None, config)

    def test_key_without_label_uses_default(self):
        config = AuthConfig(
            keys={
                "sk-nolabel": {"tier": "observe"},
            }
        )
        result = resolve_api_key("sk-nolabel", config)
        assert result.label == "unknown"

    def test_invalid_tier_in_config_raises(self):
        config = AuthConfig(
            keys={
                "sk-bad": {"tier": "superadmin", "label": "bad"},
            }
        )
        with pytest.raises(AuthError, match="tier"):
            resolve_api_key("sk-bad", config)


class TestAuthConfig:
    """AuthConfig construction and validation."""

    def test_empty_keys_allowed(self):
        config = AuthConfig(keys={})
        assert len(config.keys) == 0

    def test_from_dict(self):
        raw = {
            "keys": {
                "sk-a": {"tier": "observe", "label": "a"},
                "sk-b": {"tier": "operate", "label": "b"},
            }
        }
        config = AuthConfig.from_dict(raw)
        assert len(config.keys) == 2

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("ROUSTABOUT_API_KEY", "sk-env-test")
        monkeypatch.setenv("ROUSTABOUT_API_TIER", "elevate")
        monkeypatch.setenv("ROUSTABOUT_API_LABEL", "docker")
        config = AuthConfig.from_env()
        assert "sk-env-test" in config.keys
        assert config.keys["sk-env-test"]["tier"] == "elevate"
        assert config.keys["sk-env-test"]["label"] == "docker"

    def test_from_env_defaults(self, monkeypatch):
        monkeypatch.setenv("ROUSTABOUT_API_KEY", "sk-default")
        monkeypatch.delenv("ROUSTABOUT_API_TIER", raising=False)
        monkeypatch.delenv("ROUSTABOUT_API_LABEL", raising=False)
        config = AuthConfig.from_env()
        assert config.keys["sk-default"]["tier"] == "observe"
        assert config.keys["sk-default"]["label"] == "env-key"

    def test_from_env_no_key_returns_empty(self, monkeypatch):
        monkeypatch.delenv("ROUSTABOUT_API_KEY", raising=False)
        config = AuthConfig.from_env()
        assert len(config.keys) == 0

    def test_merge_env_overrides_toml(self):
        toml = AuthConfig(keys={"sk-a": {"tier": "observe", "label": "toml"}})
        env = AuthConfig(keys={"sk-a": {"tier": "operate", "label": "env"}})
        merged = toml.merge(env)
        assert merged.keys["sk-a"]["tier"] == "operate"

    def test_merge_combines_keys(self):
        toml = AuthConfig(keys={"sk-a": {"tier": "observe", "label": "a"}})
        env = AuthConfig(keys={"sk-b": {"tier": "operate", "label": "b"}})
        merged = toml.merge(env)
        assert len(merged.keys) == 2


class TestExecGrants:
    """A key may carry exec grants: container names it may exec into,
    limited to that container's allowlist."""

    def _resolve(self, entry):
        from roustabout.api.auth import AuthConfig, resolve_api_key

        return resolve_api_key("sk-k", AuthConfig(keys={"sk-k": entry}))

    def test_key_without_grants_has_none(self):
        assert self._resolve({"tier": "observe", "label": "x"}).exec_grants == ()

    def test_grants_are_resolved(self):
        info = self._resolve({"tier": "observe", "label": "x", "exec": ["airflow", "nginx"]})
        assert info.exec_grants == ("airflow", "nginx")

    @pytest.mark.parametrize("bad", ["airflow", [1], [""], {"airflow": True}, [["airflow"]]])
    def test_malformed_grants_reject_the_key(self, bad):
        """A grant list that cannot be read must not resolve to a working key."""
        from roustabout.api.auth import AuthError

        with pytest.raises(AuthError):
            self._resolve({"tier": "observe", "label": "x", "exec": bad})

    def test_from_dict_preserves_grants(self):
        from roustabout.api.auth import AuthConfig, resolve_api_key

        config = AuthConfig.from_dict(
            {"keys": {"sk-k": {"tier": "observe", "label": "x", "exec": ["airflow"]}}}
        )
        assert resolve_api_key("sk-k", config).exec_grants == ("airflow",)
