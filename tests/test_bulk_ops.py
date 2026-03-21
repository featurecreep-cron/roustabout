"""Tests for bulk operations — compose project and label selector ops.

Covers E3 F3.1: bulk operations with blast radius cap.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from roustabout.bulk_ops import (
    BulkResult,
    bulk_manage,
    select_by_label,
    select_by_project,
)
from roustabout.session import (
    DockerSession,
    PermissionTier,
    RateLimiter,
    Session,
    capabilities_for_tier,
)

# Helpers


def _make_session() -> Session:
    docker = DockerSession(client=MagicMock(), host="localhost")
    return Session(
        id="test",
        docker=docker,
        tier=PermissionTier.OPERATE,
        capabilities=capabilities_for_tier(PermissionTier.OPERATE),
        rate_limiter=RateLimiter(),
        created_at="",
    )


def _mock_container(name: str, project: str | None = None, labels=None):
    c = MagicMock()
    c.name = name
    c.labels = labels or {}
    if project:
        c.labels["com.docker.compose.project"] = project
    return c


# Selection


class TestSelectByProject:
    def test_selects_matching_project(self):
        containers = [
            _mock_container("web", project="myapp"),
            _mock_container("db", project="myapp"),
            _mock_container("unrelated", project="other"),
        ]
        selected = select_by_project(containers, "myapp")
        assert len(selected) == 2
        assert all(c.name in ("web", "db") for c in selected)

    def test_empty_result(self):
        containers = [_mock_container("web", project="other")]
        selected = select_by_project(containers, "myapp")
        assert len(selected) == 0


class TestSelectByLabel:
    def test_selects_matching_label(self):
        containers = [
            _mock_container("web", labels={"env": "prod"}),
            _mock_container("db", labels={"env": "prod"}),
            _mock_container("dev", labels={"env": "dev"}),
        ]
        selected = select_by_label(containers, "env=prod")
        assert len(selected) == 2

    def test_key_only_selector(self):
        containers = [
            _mock_container("web", labels={"monitored": "true"}),
            _mock_container("db", labels={}),
        ]
        selected = select_by_label(containers, "monitored")
        assert len(selected) == 1

    def test_no_match(self):
        containers = [_mock_container("web", labels={"env": "dev"})]
        selected = select_by_label(containers, "env=prod")
        assert len(selected) == 0


# Bulk manage


class TestBulkManage:
    def test_blast_radius_cap(self):
        """Too many containers should be denied."""
        containers = [f"c{i}" for i in range(10)]
        session = _make_session()

        result = bulk_manage(
            action="restart",
            targets=containers,
            session=session,
            blast_radius_cap=5,
        )

        assert isinstance(result, BulkResult)
        assert result.success is False
        assert "blast radius" in (result.error or "").lower()

    def test_dry_run(self):
        session = _make_session()
        result = bulk_manage(
            action="restart",
            targets=["web", "api"],
            session=session,
            dry_run=True,
        )

        assert result.success is True
        assert len(result.per_container) == 2
        assert all(r["result"] == "dry-run" for r in result.per_container)

    def test_within_cap(self):
        session = _make_session()

        with patch("roustabout.bulk_ops._execute_single") as mock_exec:
            mock_exec.return_value = {
                "target": "web",
                "success": True,
                "result": "success",
            }
            result = bulk_manage(
                action="restart",
                targets=["web", "api"],
                session=session,
            )

        assert result.success is True
        assert len(result.per_container) == 2
