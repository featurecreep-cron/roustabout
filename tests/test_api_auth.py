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
