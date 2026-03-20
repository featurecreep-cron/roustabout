"""Tests for configuration loading."""

import pytest

from roustabout.config import Config, load_config


class TestConfigDefaults:
    def test_default_values(self):
        cfg = Config()
        assert cfg.redact_patterns == ()
        assert cfg.show_env is False
        assert cfg.show_labels is True
        assert cfg.output is None
        assert cfg.docker_host is None

    def test_frozen(self):
        cfg = Config()
        with pytest.raises(AttributeError):
            cfg.show_env = True


class TestConfigMerge:
    def test_merge_overrides_specified_fields(self):
        cfg = Config(show_env=False, show_labels=True)
        merged = cfg.merge(show_env=True)
        assert merged.show_env is True
        assert merged.show_labels is True

    def test_merge_preserves_unspecified_fields(self):
        cfg = Config(output="/tmp/out.md", docker_host="tcp://host:2375")
        merged = cfg.merge(show_env=True)
        assert merged.output == "/tmp/out.md"
        assert merged.docker_host == "tcp://host:2375"

    def test_merge_with_no_overrides(self):
        cfg = Config(show_env=True)
        merged = cfg.merge()
        assert merged.show_env is True

    def test_merge_returns_new_instance(self):
        cfg = Config()
        merged = cfg.merge(show_env=True)
        assert cfg is not merged
        assert cfg.show_env is False
        assert merged.show_env is True


class TestLoadConfig:
    def test_no_config_file_returns_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg == Config()

    def test_explicit_path_loads(self, tmp_path):
        config_file = tmp_path / "custom.toml"
        config_file.write_text('show_env = true\noutput = "snapshot.md"\n')
        cfg = load_config(config_file)
        assert cfg.show_env is True
        assert cfg.output == "snapshot.md"
        assert cfg.show_labels is True  # default preserved

    def test_explicit_path_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            load_config(tmp_path / "missing.toml")

    def test_cwd_config_found(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "roustabout.toml"
        config_file.write_text("show_labels = false\n")
        cfg = load_config()
        assert cfg.show_labels is False

    def test_redact_patterns(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('redact_patterns = ["password", "api_key", "my_custom"]\n')
        cfg = load_config(config_file)
        assert cfg.redact_patterns == ("password", "api_key", "my_custom")

    def test_docker_host(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('docker_host = "tcp://192.168.1.120:2375"\n')
        cfg = load_config(config_file)
        assert cfg.docker_host == "tcp://192.168.1.120:2375"

    def test_all_fields(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            'redact_patterns = ["secret"]\n'
            "show_env = true\n"
            "show_labels = false\n"
            'output = "/tmp/env.md"\n'
            'docker_host = "unix:///var/run/docker.sock"\n'
        )
        cfg = load_config(config_file)
        assert cfg.redact_patterns == ("secret",)
        assert cfg.show_env is True
        assert cfg.show_labels is False
        assert cfg.output == "/tmp/env.md"
        assert cfg.docker_host == "unix:///var/run/docker.sock"


class TestSeverityOverrides:
    def test_severity_table_parsed(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            '[severity]\nno-healthcheck = "warning"\nrunning-as-root = "warning"\n'
        )
        cfg = load_config(config_file)
        assert cfg.severity_overrides == {
            "no-healthcheck": "warning",
            "running-as-root": "warning",
        }

    def test_severity_case_insensitive(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('[severity]\nno-healthcheck = "WARNING"\n')
        cfg = load_config(config_file)
        assert cfg.severity_overrides["no-healthcheck"] == "warning"

    def test_invalid_severity_value_raises(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('[severity]\nno-healthcheck = "extreme"\n')
        with pytest.raises(ValueError, match="severity.no-healthcheck must be one of"):
            load_config(config_file)

    def test_severity_not_table_raises(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('severity = "not a table"\n')
        with pytest.raises(ValueError, match="severity must be a table"):
            load_config(config_file)

    def test_default_empty(self):
        cfg = Config()
        assert cfg.severity_overrides == {}


class TestLoadConfigValidation:
    def test_redact_patterns_not_list_raises(self, tmp_path):
        config_file = tmp_path / "bad.toml"
        config_file.write_text('redact_patterns = "not a list"\n')
        with pytest.raises(ValueError, match="redact_patterns must be a list"):
            load_config(config_file)

    def test_redact_patterns_non_string_items_raises(self, tmp_path):
        config_file = tmp_path / "bad.toml"
        config_file.write_text("redact_patterns = [1, 2, 3]\n")
        with pytest.raises(ValueError, match="redact_patterns must be a list of strings"):
            load_config(config_file)

    def test_show_env_not_bool_raises(self, tmp_path):
        config_file = tmp_path / "bad.toml"
        config_file.write_text('show_env = "yes"\n')
        with pytest.raises(ValueError, match="show_env must be a boolean"):
            load_config(config_file)

    def test_show_labels_not_bool_raises(self, tmp_path):
        config_file = tmp_path / "bad.toml"
        config_file.write_text("show_labels = 1\n")
        with pytest.raises(ValueError, match="show_labels must be a boolean"):
            load_config(config_file)

    def test_output_not_string_raises(self, tmp_path):
        config_file = tmp_path / "bad.toml"
        config_file.write_text("output = 42\n")
        with pytest.raises(ValueError, match="output must be a string"):
            load_config(config_file)

    def test_docker_host_not_string_raises(self, tmp_path):
        config_file = tmp_path / "bad.toml"
        config_file.write_text("docker_host = true\n")
        with pytest.raises(ValueError, match="docker_host must be a string"):
            load_config(config_file)

    def test_unknown_keys_ignored(self, tmp_path):
        config_file = tmp_path / "extra.toml"
        config_file.write_text("unknown_key = true\nshow_env = true\n")
        cfg = load_config(config_file)
        assert cfg.show_env is True


class TestConfigPriority:
    def test_cwd_takes_precedence_over_home(self, tmp_path, monkeypatch):
        """CWD config should be found first in the search order."""
        monkeypatch.chdir(tmp_path)
        cwd_config = tmp_path / "roustabout.toml"
        cwd_config.write_text("show_env = true\n")
        # Home config would be at ~/.config/roustabout/config.toml
        # but CWD should win when both exist
        cfg = load_config()
        assert cfg.show_env is True

    def test_env_var_override(self, tmp_path, monkeypatch):
        config_file = tmp_path / "custom.toml"
        config_file.write_text("show_env = true\n")
        monkeypatch.setenv("ROUSTABOUT_CONFIG", str(config_file))
        cfg = load_config()
        assert cfg.show_env is True


# Phase 1 config fields


class TestPhase1ConfigFields:
    """S1.3.1: Phase 1 configuration fields."""

    def test_phase1_defaults(self):
        cfg = Config()
        assert cfg.rate_limit_per_container == 3
        assert cfg.rate_limit_window_seconds == 300
        assert cfg.rate_limit_global == 10
        assert cfg.blast_radius_cap == 5
        assert cfg.ntfy_url is None
        assert cfg.apprise_urls == ()
        assert cfg.notification_routing == {}
        assert cfg.default_tier == "operate"
        assert len(cfg.elevate_only_images) > 0
        assert "postgres" in cfg.elevate_only_images
        assert cfg.allowlist_patterns == ()
        assert cfg.log_tail_default == 100
        assert cfg.response_size_cap == 262144
        assert cfg.state_db is None

    def test_rate_limit_config(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            "rate_limit_per_container = 5\n"
            "rate_limit_window_seconds = 600\n"
            "rate_limit_global = 20\n"
        )
        cfg = load_config(config_file)
        assert cfg.rate_limit_per_container == 5
        assert cfg.rate_limit_window_seconds == 600
        assert cfg.rate_limit_global == 20

    def test_negative_rate_limit_raises(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text("rate_limit_per_container = -1\n")
        with pytest.raises(ValueError, match="rate_limit_per_container must be a positive"):
            load_config(config_file)

    def test_blast_radius_cap(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text("blast_radius_cap = 10\n")
        cfg = load_config(config_file)
        assert cfg.blast_radius_cap == 10

    def test_notification_config(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            'ntfy_url = "https://ntfy.example.com/roustabout"\n'
            'apprise_urls = ["discord://webhook", "tgram://token/chat"]\n'
        )
        cfg = load_config(config_file)
        assert cfg.ntfy_url == "https://ntfy.example.com/roustabout"
        assert cfg.apprise_urls == ("discord://webhook", "tgram://token/chat")

    def test_default_tier(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('default_tier = "observe"\n')
        cfg = load_config(config_file)
        assert cfg.default_tier == "observe"

    def test_invalid_default_tier(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('default_tier = "admin"\n')
        with pytest.raises(ValueError, match="default_tier must be one of"):
            load_config(config_file)

    def test_custom_elevate_only_images(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('elevate_only_images = ["postgres", "custom-db"]\n')
        cfg = load_config(config_file)
        assert cfg.elevate_only_images == ("postgres", "custom-db")

    def test_allowlist_patterns(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('allowlist_patterns = ["app-*", "web-*"]\n')
        cfg = load_config(config_file)
        assert cfg.allowlist_patterns == ("app-*", "web-*")

    def test_unknown_sections_ignored(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            "show_env = true\n"
            "[phase2_feature]\n"
            "some_setting = true\n"
        )
        cfg = load_config(config_file)
        assert cfg.show_env is True

    def test_state_db_path(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('state_db = "/data/roustabout.db"\n')
        cfg = load_config(config_file)
        assert cfg.state_db == "/data/roustabout.db"

    def test_raw_preserves_full_toml(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            "show_env = true\n"
            "[auth]\n"
            "[auth.keys]\n"
            '"sk-test" = { tier = "observe", label = "test" }\n'
        )
        cfg = load_config(config_file)
        assert cfg.show_env is True
        assert "auth" in cfg.raw
        assert "keys" in cfg.raw["auth"]
        assert "sk-test" in cfg.raw["auth"]["keys"]

    def test_raw_empty_for_defaults(self):
        cfg = Config()
        assert cfg.raw == {}


class TestFirstRun:
    """S1.3.2: Zero-config first run."""

    def test_zero_config_produces_valid_config(self):
        cfg = Config()
        # Should be usable without any config file
        assert cfg.default_tier == "operate"
        assert cfg.rate_limit_per_container > 0
        assert cfg.blast_radius_cap > 0

    def test_default_tier_is_operate(self):
        """Operate tier means mutations work out of the box."""
        cfg = Config()
        assert cfg.default_tier == "operate"

    def test_default_deny_list_present(self):
        """Databases, auth, proxies are elevate-only by default."""
        cfg = Config()
        assert "postgres" in cfg.elevate_only_images
        assert "mysql" in cfg.elevate_only_images
        assert "authentik" in cfg.elevate_only_images
        assert "traefik" in cfg.elevate_only_images
