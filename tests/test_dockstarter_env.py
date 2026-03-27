"""Tests for dockstarter_env module (LLD-037)."""

import pytest

from roustabout.dockstarter_env import (
    _match_service_prefix,
    map_env_to_stacks,
    parse_dockstarter_env,
)


class TestParseDockStarterEnv:
    def test_globals_classified(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("PUID=1000\nPGID=1000\nTZ=America/Chicago\n")
        result = parse_dockstarter_env(env_file)
        assert len(result.shared_vars) == 3
        assert all(v.is_shared for v in result.shared_vars)
        assert {v.key for v in result.shared_vars} == {"PUID", "PGID", "TZ"}

    def test_prefix_matching(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SONARR_PORT=8989\nRADARR_PORT=7878\n")
        result = parse_dockstarter_env(env_file, service_names=("sonarr", "radarr"))
        assert "sonarr" in result.per_service_vars
        assert "radarr" in result.per_service_vars
        assert result.per_service_vars["sonarr"][0].key == "SONARR_PORT"

    def test_longest_prefix_wins(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("PLEXPY_PORT=8181\nPLEX_CLAIM=claim-abc\n")
        result = parse_dockstarter_env(env_file, service_names=("plex", "plexpy"))
        # PLEXPY_PORT should match plexpy (longer prefix), not plex
        assert "plexpy" in result.per_service_vars
        assert result.per_service_vars["plexpy"][0].key == "PLEXPY_PORT"
        # PLEX_CLAIM should match plex
        assert "plex" in result.per_service_vars
        assert result.per_service_vars["plex"][0].key == "PLEX_CLAIM"

    def test_globals_before_prefix(self, tmp_path):
        """DOCKERCONFDIR should be global even if 'docker' is a service name."""
        env_file = tmp_path / ".env"
        env_file.write_text("DOCKERCONFDIR=/home/user/.config\n")
        result = parse_dockstarter_env(env_file, service_names=("docker",))
        assert len(result.shared_vars) == 1
        assert result.shared_vars[0].key == "DOCKERCONFDIR"
        assert "docker" not in result.per_service_vars

    def test_no_service_names_all_unmapped(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SONARR_PORT=8989\nRANDOM_VAR=hello\n")
        result = parse_dockstarter_env(env_file)
        assert len(result.per_service_vars) == 0
        assert len(result.unmapped_vars) == 2

    def test_handles_quotes(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("PUID=\"1000\"\nTZ='US/Eastern'\n")
        result = parse_dockstarter_env(env_file)
        assert result.shared_vars[0].value == "1000"
        assert result.shared_vars[1].value == "US/Eastern"

    def test_handles_comments(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("# This is a comment\nPUID=1000\n# Another\n\nPGID=1000\n")
        result = parse_dockstarter_env(env_file)
        assert len(result.shared_vars) == 2

    def test_handles_export_prefix(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("export PUID=1000\nexport TZ=UTC\n")
        result = parse_dockstarter_env(env_file)
        assert len(result.shared_vars) == 2

    def test_secret_detection(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("GRAFANA_ADMIN_PASSWORD=supersecret\nGRAFANA_PORT=3000\n")
        result = parse_dockstarter_env(env_file, service_names=("grafana",))
        vars_list = result.per_service_vars["grafana"]
        secret_vars = [v for v in vars_list if v.is_secret]
        non_secret_vars = [v for v in vars_list if not v.is_secret]
        assert len(secret_vars) == 1
        assert secret_vars[0].key == "GRAFANA_ADMIN_PASSWORD"
        assert len(non_secret_vars) == 1

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="not found"):
            parse_dockstarter_env(tmp_path / "nonexistent.env")

    def test_double_underscore_nesting(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SONARR__AUTH__APIKEY=abc123\n")
        result = parse_dockstarter_env(env_file, service_names=("sonarr",))
        assert "sonarr" in result.per_service_vars
        assert result.per_service_vars["sonarr"][0].key == "SONARR__AUTH__APIKEY"


class TestMatchServicePrefix:
    def test_case_insensitive(self):
        assert _match_service_prefix("SONARR_PORT", ("sonarr",)) == "sonarr"

    def test_longest_match(self):
        assert _match_service_prefix("PLEXPY_PORT", ("plex", "plexpy")) == "plexpy"

    def test_no_match(self):
        assert _match_service_prefix("RANDOM_VAR", ("sonarr", "radarr")) is None

    def test_underscore_in_service_name(self):
        assert _match_service_prefix("MY_APP_PORT", ("my_app",)) == "my_app"

    def test_double_underscore(self):
        assert _match_service_prefix("SONARR__AUTH__KEY", ("sonarr",)) == "sonarr"


class TestMapEnvToStacks:
    def test_basic_mapping(self, tmp_path):
        env_file = tmp_path / "source.env"
        env_file.write_text(
            "PUID=1000\nPGID=1000\nTZ=UTC\nSONARR_PORT=8989\nRADARR_PORT=7878\nGRAFANA_PORT=3000\n"
        )
        parsed = parse_dockstarter_env(env_file, service_names=("sonarr", "radarr", "grafana"))
        mapping = {"sonarr": "media", "radarr": "media", "grafana": "monitoring"}
        output = tmp_path / "stacks"

        result = map_env_to_stacks(parsed, mapping, output)
        assert result.stacks_written == 2
        assert result.vars_mapped == 3  # 3 per-service vars

        # Shared vars duplicated into each stack
        assert result.vars_duplicated == 6  # 3 globals × 2 stacks

        # Check media stack .env
        media_env = (output / "media" / ".env").read_text()
        assert "SONARR_PORT=8989" in media_env
        assert "RADARR_PORT=7878" in media_env
        assert "PUID=1000" in media_env
        assert "TZ=UTC" in media_env

        # Check monitoring stack .env
        mon_env = (output / "monitoring" / ".env").read_text()
        assert "GRAFANA_PORT=3000" in mon_env
        assert "PUID=1000" in mon_env

    def test_dry_run(self, tmp_path):
        env_file = tmp_path / "source.env"
        env_file.write_text("PUID=1000\nSONARR_PORT=8989\n")
        parsed = parse_dockstarter_env(env_file, service_names=("sonarr",))
        mapping = {"sonarr": "media"}
        output = tmp_path / "stacks"

        result = map_env_to_stacks(parsed, mapping, output, dry_run=True)
        assert result.dry_run is True
        assert result.stacks_written == 1
        assert not (output / "media").exists()

    def test_unmapped_service_warning(self, tmp_path):
        env_file = tmp_path / "source.env"
        env_file.write_text("SONARR_PORT=8989\nMYSTERY_VAR=hello\n")
        parsed = parse_dockstarter_env(env_file, service_names=("sonarr",))
        mapping = {}  # sonarr not mapped
        output = tmp_path / "stacks"

        result = map_env_to_stacks(parsed, mapping, output, dry_run=True)
        assert any("sonarr" in w for w in result.warnings)
        assert "SONARR_PORT" in result.unmapped_vars

    def test_env_file_permissions(self, tmp_path):
        env_file = tmp_path / "source.env"
        env_file.write_text("PUID=1000\nSONARR_PORT=8989\n")
        parsed = parse_dockstarter_env(env_file, service_names=("sonarr",))
        mapping = {"sonarr": "media"}
        output = tmp_path / "stacks"

        map_env_to_stacks(parsed, mapping, output)
        env_out = output / "media" / ".env"
        assert oct(env_out.stat().st_mode)[-3:] == "600"

    def test_merges_with_existing_env(self, tmp_path):
        env_file = tmp_path / "source.env"
        env_file.write_text("SONARR_PORT=8989\n")
        parsed = parse_dockstarter_env(env_file, service_names=("sonarr",))
        mapping = {"sonarr": "media"}
        output = tmp_path / "stacks"

        # Pre-existing .env
        (output / "media").mkdir(parents=True)
        (output / "media" / ".env").write_text("EXISTING=keep\n")

        map_env_to_stacks(parsed, mapping, output)
        content = (output / "media" / ".env").read_text()
        assert "EXISTING=keep" in content
        assert "SONARR_PORT=8989" in content

    def test_unmapped_env_vars_in_result(self, tmp_path):
        env_file = tmp_path / "source.env"
        env_file.write_text("RANDOM_THING=hello\nOTHER=world\n")
        parsed = parse_dockstarter_env(env_file)  # no service_names
        mapping = {}
        output = tmp_path / "stacks"

        result = map_env_to_stacks(parsed, mapping, output, dry_run=True)
        assert "RANDOM_THING" in result.unmapped_vars
        assert "OTHER" in result.unmapped_vars
