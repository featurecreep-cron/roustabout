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


class TestLayerViolation:
    """No upward layer imports.

    Layer hierarchy (top to bottom):
    - Interface: cli.py, mcp_server.py
    - Gateway: gateway.py, permissions.py, lockdown.py, mutations.py, state_db.py
    - Logic: collector.py, auditor.py, diff.py, redactor.py, generator.py,
             dr_plan.py, audit_renderer.py, notifications.py, session.py,
             health_stats.py, log_access.py, bulk_ops.py
    - Output: renderer.py, json_output.py
    - Foundation: models.py, config.py, connection.py, constants.py
    """

    _LAYERS: dict[str, int] = {
        # Foundation = 0
        "models.py": 0, "config.py": 0, "connection.py": 0, "constants.py": 0,
        # Output = 1
        "renderer.py": 1,
        # Logic = 2
        "collector.py": 2, "auditor.py": 2, "diff.py": 2, "redactor.py": 2,
        "generator.py": 2, "dr_plan.py": 2, "audit_renderer.py": 2,
        "notifications.py": 2, "session.py": 2, "health_stats.py": 2,
        "log_access.py": 2, "json_output.py": 2,
        # Gateway = 3
        "gateway.py": 3, "permissions.py": 3, "lockdown.py": 3,
        "mutations.py": 3, "state_db.py": 3,
        # Gateway consumers — import gateway to route operations
        "bulk_ops.py": 3,
        # Interface = 4
        "cli.py": 4, "mcp_server.py": 4,
    }

    def test_no_upward_imports(self):
        """Modules must not import from a layer above them."""
        # Build reverse map: module_name -> set of roustabout modules it imports
        violations = []
        for path in _python_files():
            src_layer = self._LAYERS.get(path.name)
            if src_layer is None:
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                imported_module = None
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.startswith("roustabout."):
                        imported_module = node.module.split(".")[-1] + ".py"
                    elif node.module == "roustabout":
                        # `from roustabout import X` — check each imported name
                        for alias in node.names:
                            target = alias.name + ".py"
                            target_layer = self._LAYERS.get(target)
                            if target_layer is not None and target_layer > src_layer:
                                violations.append(
                                    f"{path.name}:{node.lineno} imports "
                                    f"{alias.name} (layer {target_layer}) "
                                    f"from layer {src_layer}"
                                )
                        continue
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("roustabout."):
                            imported_module = alias.name.split(".")[-1] + ".py"
                if imported_module:
                    target_layer = self._LAYERS.get(imported_module)
                    if target_layer is not None and target_layer > src_layer:
                        violations.append(
                            f"{path.name}:{node.lineno} imports "
                            f"{imported_module[:-3]} (layer {target_layer}) "
                            f"from layer {src_layer}"
                        )
        assert not violations, (
            "Upward layer imports detected:\n"
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
