"""Tests for integrations module."""

from unittest.mock import MagicMock, patch

from roustabout.integrations.grafana import GrafanaAdapter
from roustabout.integrations.manager import (
    IntegrationManager,
    ServiceHealth,
    _CircuitBreaker,
)
from roustabout.integrations.traefik import TraefikAdapter, _matches_container
from roustabout.integrations.uptime_kuma import UptimeKumaAdapter

# --- Circuit breaker ---


class TestCircuitBreaker:
    def test_closed_initially(self):
        cb = _CircuitBreaker()
        assert cb.open is False

    def test_opens_after_max_failures(self):
        cb = _CircuitBreaker()
        for _ in range(3):
            cb.record_failure()
        assert cb.open is True

    def test_success_resets(self):
        cb = _CircuitBreaker()
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.consecutive_failures == 0
        assert cb.open is False


# --- Traefik adapter ---


class TestTraefikAdapter:
    def test_configured_when_url_set(self):
        adapter = TraefikAdapter(url="http://traefik:8080")
        assert adapter.configured is True

    def test_not_configured_when_empty(self):
        adapter = TraefikAdapter(url="")
        assert adapter.configured is False

    def test_matches_container(self):
        assert _matches_container({"service": "morsl-app@docker"}, "morsl-app") is True
        assert _matches_container({"service": "other@docker"}, "morsl-app") is False

    @patch("roustabout.integrations.traefik.httpx.get")
    def test_health_check(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"version": "2.10"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        adapter = TraefikAdapter(url="http://traefik:8080")
        health = adapter.health_check()
        assert health.healthy is True
        assert health.version == "2.10"

    @patch("roustabout.integrations.traefik.httpx.get")
    def test_enrich_container_match(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {
                "rule": "Host(`app.local`)",
                "service": "morsl-app@docker",
                "entryPoints": ["websecure"],
                "tls": True,
            }
        ]
        mock_get.return_value = mock_resp

        adapter = TraefikAdapter(url="http://traefik:8080")
        result = adapter.enrich_container("morsl-app")
        assert "traefik.routes" in result
        assert "Host(`app.local`)" in result["traefik.routes"]

    @patch("roustabout.integrations.traefik.httpx.get")
    def test_enrich_container_no_match(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp

        adapter = TraefikAdapter(url="http://traefik:8080")
        result = adapter.enrich_container("unknown")
        assert result == {}


# --- Uptime Kuma adapter ---


class TestUptimeKumaAdapter:
    def test_configured(self):
        adapter = UptimeKumaAdapter(url="http://kuma:3001", api_key="key")
        assert adapter.configured is True

    def test_not_configured_without_key(self):
        adapter = UptimeKumaAdapter(url="http://kuma:3001", api_key="")
        assert adapter.configured is False

    @patch("roustabout.integrations.uptime_kuma.httpx.get")
    def test_enrich_exact_match(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {
                "name": "morsl-app",
                "active": True,
                "uptime24": 99.9,
                "avgPing": 5.0,
                "url": "http://morsl",
            }
        ]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        adapter = UptimeKumaAdapter(url="http://kuma:3001", api_key="key")
        result = adapter.enrich_container("morsl-app")
        assert result["uptime.status"] == "up"

    @patch("roustabout.integrations.uptime_kuma.httpx.get")
    def test_enrich_no_match(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {
                "name": "Other",
                "active": True,
                "uptime24": 99.9,
                "avgPing": 5.0,
                "url": "http://other",
            }
        ]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        adapter = UptimeKumaAdapter(url="http://kuma:3001", api_key="key")
        result = adapter.enrich_container("morsl-app")
        assert result == {}


# --- Grafana adapter ---


class TestGrafanaAdapter:
    def test_configured(self):
        adapter = GrafanaAdapter(url="http://grafana:3000", api_key="key")
        assert adapter.configured is True

    @patch("roustabout.integrations.grafana.httpx.get")
    def test_enrich_with_match(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"uid": "abc", "title": "App Dashboard", "url": "/d/abc/app", "tags": ["morsl"]}
        ]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        adapter = GrafanaAdapter(url="http://grafana:3000", api_key="key")
        result = adapter.enrich_container("morsl")
        assert "grafana.dashboard" in result


# --- Integration manager ---


class TestIntegrationManager:
    def test_enrich_aggregates(self):
        adapter1 = MagicMock()
        adapter1.configured = True
        adapter1.enrich_container.return_value = {"a": "1"}

        adapter2 = MagicMock()
        adapter2.configured = True
        adapter2.enrich_container.return_value = {"b": "2"}

        manager = IntegrationManager(adapters={"a": adapter1, "b": adapter2})
        result = manager.enrich_container("app")
        assert result == {"a": "1", "b": "2"}

    def test_skips_unconfigured(self):
        adapter = MagicMock()
        adapter.configured = False

        manager = IntegrationManager(adapters={"a": adapter})
        result = manager.enrich_container("app")
        assert result == {}
        adapter.enrich_container.assert_not_called()

    def test_adapter_failure_skipped(self):
        adapter1 = MagicMock()
        adapter1.configured = True
        adapter1.enrich_container.side_effect = Exception("network error")

        adapter2 = MagicMock()
        adapter2.configured = True
        adapter2.enrich_container.return_value = {"ok": "true"}

        manager = IntegrationManager(adapters={"bad": adapter1, "good": adapter2})
        result = manager.enrich_container("app")
        assert result == {"ok": "true"}

    def test_circuit_breaker_skips_after_failures(self):
        adapter = MagicMock()
        adapter.configured = True
        adapter.name = "test"
        adapter.enrich_container.side_effect = Exception("fail")

        manager = IntegrationManager(adapters={"test": adapter})

        # Trigger 3 failures
        for _ in range(3):
            manager.enrich_container("app")

        # 4th call should skip (circuit open)
        adapter.enrich_container.reset_mock()
        manager.enrich_container("app")
        adapter.enrich_container.assert_not_called()

    def test_health_check_all(self):
        adapter = MagicMock()
        adapter.configured = True
        adapter.health_check.return_value = ServiceHealth(name="test", healthy=True)

        manager = IntegrationManager(adapters={"test": adapter})
        results = manager.health_check_all()
        assert "test" in results
        assert results["test"].healthy is True

    def test_from_config(self):
        config = {
            "integrations": {
                "traefik": {"url": "http://traefik:8080"},
            }
        }
        manager = IntegrationManager.from_config(config)
        assert "traefik" in manager.adapters
