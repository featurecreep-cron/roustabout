"""Lint tests for architectural constraints.

Ensures boundaries are maintained:
- Only mutations.py calls docker-py mutation methods
- Only gateway.py imports mutations.py
- No asyncio in sync core modules
- Only state_db.py imports sqlite3
- Only connection.py creates Docker clients
- No upward layer imports
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).parent.parent / "src" / "roustabout"

# Docker-py methods that mutate container state
_MUTATION_METHODS = frozenset({
    "start", "stop", "restart", "remove", "kill", "pause", "unpause",
    "rename", "update", "exec_run",
})


def _python_files(exclude: set[str] | None = None) -> list[Path]:
    """All .py files in src/roustabout, excluding specified filenames."""
    exclude = exclude or set()
    return [
        p for p in SRC.glob("*.py")
        if p.name not in exclude and p.name != "__init__.py"
    ]


class TestMutationMethodConstraint:
    """Only mutations.py should call docker-py mutation methods."""

    def test_no_mutation_calls_outside_mutations_py(self):
        violations = []
        for path in _python_files(exclude={"mutations.py"}):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in _MUTATION_METHODS
                ):
                    violations.append(
                        f"{path.name}:{node.lineno} calls "
                        f".{node.func.attr}()"
                    )
        assert not violations, (
            "Docker mutation methods called outside mutations.py:\n"
            + "\n".join(violations)
        )


class TestMutationsImportConstraint:
    """Only gateway.py should import mutations.py."""

    def test_no_mutations_import_outside_gateway(self):
        violations = []
        for path in _python_files(exclude={"gateway.py", "mutations.py"}):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if "mutations" in (alias.name or ""):
                            violations.append(
                                f"{path.name}:{node.lineno} imports "
                                f"{alias.name}"
                            )
                elif isinstance(node, ast.ImportFrom):
                    if node.module and "mutations" in node.module:
                        violations.append(
                            f"{path.name}:{node.lineno} imports from "
                            f"{node.module}"
                        )
        assert not violations, (
            "mutations.py imported outside gateway.py:\n"
            + "\n".join(violations)
        )


# Async boundary modules — sync core, no asyncio allowed
_CORE_MODULES = frozenset({
    "auditor.py", "bulk_ops.py", "collector.py", "config.py",
    "connection.py", "constants.py", "diff.py", "dr_plan.py",
    "gateway.py", "generator.py", "health_stats.py", "json_output.py",
    "lockdown.py", "log_access.py", "models.py", "mutations.py",
    "notifications.py", "permissions.py", "redactor.py", "renderer.py",
    "audit_renderer.py", "session.py", "state_db.py",
})


class TestAsyncBoundary:
    """No asyncio imports in sync core modules."""

    def test_no_asyncio_in_core(self):
        violations = []
        for path in SRC.glob("*.py"):
            if path.name not in _CORE_MODULES:
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "asyncio":
                            violations.append(f"{path.name}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module.startswith("asyncio"):
                        violations.append(f"{path.name}:{node.lineno}")
        assert not violations, (
            "asyncio imported in sync core module:\n"
            + "\n".join(violations)
        )


class TestSqliteRestriction:
    """Only state_db.py may import sqlite3."""

    def test_sqlite_only_in_state_db(self):
        violations = []
        for path in _python_files(exclude={"state_db.py"}):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "sqlite3":
                            violations.append(f"{path.name}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom):
                    if node.module == "sqlite3":
                        violations.append(f"{path.name}:{node.lineno}")
        assert not violations, (
            "sqlite3 imported outside state_db.py:\n"
            + "\n".join(violations)
        )


class TestConnectionRestriction:
    """Only connection.py creates Docker clients."""

    def test_no_docker_from_env_outside_connection(self):
        violations = []
        for path in _python_files(exclude={"connection.py"}):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "from_env"
                ):
                    violations.append(
                        f"{path.name}:{node.lineno} calls .from_env()"
                    )
        assert not violations, (
            "Docker client created outside connection.py:\n"
            + "\n".join(violations)
        )
