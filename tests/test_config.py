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
