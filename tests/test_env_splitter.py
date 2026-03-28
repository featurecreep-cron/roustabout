"""Tests for env_splitter module — general-purpose .env parsing and splitting."""

import pytest

from roustabout.env_splitter import (
    match_service_prefix,
    parse_env,
    split_env,
)


class TestParseEnv:
    def test_shared_vars_classified(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("HOST=0.0.0.0\nPORT=8080\nDEBUG=true\n")
        result = parse_env(env_file, shared_vars=frozenset({"HOST", "PORT"}))
        assert len(result.shared_vars) == 2
        assert all(v.is_shared for v in result.shared_vars)
        assert len(result.unmapped_vars) == 1

    def test_prefix_match_without_shared(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("APP_PORT=3000\nDB_HOST=localhost\n")
        result = parse_env(env_file, service_names=("app", "db"))
        assert "app" in result.per_service_vars
        assert "db" in result.per_service_vars

    def test_custom_var_to_service_callback(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("MYSQL_ROOT_PASSWORD=secret\nPOSTGRES_DB=mydb\n")

        def classify(key, services):
            if key.startswith("MYSQL"):
                return "mysql"
            if key.startswith("POSTGRES"):
                return "postgres"
            return None

        result = parse_env(
            env_file,
            service_names=("mysql", "postgres"),
            var_to_service=classify,
        )
        assert "mysql" in result.per_service_vars
        assert "postgres" in result.per_service_vars

    def test_callback_falls_through_to_prefix(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("APP_PORT=3000\nSPECIAL=val\n")

        def classify(key, services):
            if key == "SPECIAL":
                return "app"
            return None  # fall through to prefix match

        result = parse_env(
            env_file,
            service_names=("app",),
            var_to_service=classify,
        )
        assert "app" in result.per_service_vars
        keys = [v.key for v in result.per_service_vars["app"]]
        assert "APP_PORT" in keys
        assert "SPECIAL" in keys

    def test_empty_shared_vars_default(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("FOO=bar\n")
        result = parse_env(env_file)
        assert len(result.shared_vars) == 0
        assert len(result.unmapped_vars) == 1

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="not found"):
            parse_env(tmp_path / "nonexistent.env")

    def test_shared_takes_priority_over_prefix(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("APP_PORT=3000\n")
        result = parse_env(
            env_file,
            shared_vars=frozenset({"APP_PORT"}),
            service_names=("app",),
        )
        assert len(result.shared_vars) == 1
        assert len(result.per_service_vars) == 0

    def test_handles_export_quotes_comments(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text('# comment\nexport FOO="bar"\n\nBAZ=\'qux\'\n')
        result = parse_env(env_file)
        vals = {v.key: v.value for v in result.unmapped_vars}
        assert vals["FOO"] == "bar"
        assert vals["BAZ"] == "qux"


class TestSplitEnv:
    def test_basic_split(self, tmp_path):
        env_file = tmp_path / "source.env"
        env_file.write_text("SHARED=yes\nAPP_PORT=3000\nDB_PORT=5432\n")
        parsed = parse_env(
            env_file,
            shared_vars=frozenset({"SHARED"}),
            service_names=("app", "db"),
        )
        output = tmp_path / "out"
        result = split_env(parsed, {"app": "web", "db": "data"}, output)
        assert result.stacks_written == 2
        assert result.vars_mapped == 2

        web_env = (output / "web" / ".env").read_text()
        assert "APP_PORT=3000" in web_env
        assert "SHARED=yes" in web_env

    def test_dry_run_no_files(self, tmp_path):
        env_file = tmp_path / "source.env"
        env_file.write_text("APP_PORT=3000\n")
        parsed = parse_env(env_file, service_names=("app",))
        output = tmp_path / "out"
        result = split_env(parsed, {"app": "web"}, output, dry_run=True)
        assert result.dry_run is True
        assert not (output / "web").exists()

    def test_unmapped_service_warning(self, tmp_path):
        env_file = tmp_path / "source.env"
        env_file.write_text("APP_PORT=3000\n")
        parsed = parse_env(env_file, service_names=("app",))
        result = split_env(parsed, {}, tmp_path / "out", dry_run=True)
        assert any("app" in w for w in result.warnings)
        assert "APP_PORT" in result.unmapped_vars


class TestMatchServicePrefix:
    def test_longest_match(self):
        assert match_service_prefix("PLEXPY_PORT", ("plex", "plexpy")) == "plexpy"

    def test_double_underscore(self):
        assert match_service_prefix("APP__NESTED__KEY", ("app",)) == "app"

    def test_no_match(self):
        assert match_service_prefix("RANDOM", ("app",)) is None
