"""Lint tests for import constraints.

Ensures architectural boundaries are maintained:
- Only mutations.py calls docker-py mutation methods
- Only gateway.py imports mutations.py
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
