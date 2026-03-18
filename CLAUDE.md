# Roustabout

Docker environment documentation, security auditing, and safe MCP server.

## Before Writing Code

Read the relevant section from the conventions docs before starting work on a module. Don't read the whole thing — read what applies to your current task.

**Conventions location:** `~/featurecreep/docs/roustabout/development/`

| When you're about to... | Read this section |
|------------------------|-------------------|
| Create a new module | `coding-conventions.md` → Module Rules, Naming, Imports |
| Write a new function | `coding-conventions.md` → Naming (functions), Type Annotations |
| Add error handling | `coding-conventions.md` → Error Handling |
| Add/modify data models | `coding-conventions.md` → Data Modeling |
| Touch async/MCP code | `coding-conventions.md` → Async Boundary |
| Add logging | `coding-conventions.md` → Logging |
| Handle secrets/output | `coding-conventions.md` → Redaction |
| Write or modify tests | `testing-patterns.md` → relevant section |

## Architecture Constraints (always in effect)

These are non-negotiable. Violations break the system.

- **Layer invariant:** dependencies flow downward only (Interface → Logic → Output → Foundation)
- **Sync core:** core modules never import `asyncio`. Async is only in `mcp_server.py`.
- **Session owns Docker client.** No other module creates `DockerClient` instances.
- **All mutations through gateway.** No direct `container.stop()` calls.
- **Lockdown has zero internal dependencies.** It reads a file. That's it.
- **State DB is the sole SQLite consumer.** No other module imports `sqlite3`.
- **Frozen models.** All dataclasses are `frozen=True`. No mutation after construction.
- **Redact all output paths.** If it leaves the process and could contain secrets, redact it.

## Code Style Rules (enforced by lint tests — will fail CI)

These rules are tested in `tests/test_import_constraints.py`. Don't violate them.

**No section dividers.** Use `# Section name` with a blank line above. Never `# -----------`.

**Catch specific exceptions.** Never write `except Exception:` — catch the actual error types. If you must catch broadly, add `# noqa: broad-except` with a comment explaining why.
```python
# WRONG
except Exception as exc:

# RIGHT
except (ConnectionError, OSError, docker.errors.DockerException) as exc:
```

**No stdlib logging in new modules.** Existing modules are grandfathered. New code should not add `import logging` or `logging.getLogger`. When structlog is added as a dependency, migrate all modules.

**All dataclasses frozen.** Exception subclasses (which need mutable `args`) must be listed in `_MUTABLE_ALLOWED` in the lint test with a justification comment.

## After Writing Code

Run `/code-review src/roustabout/{module}` on every module after completing a phase. The review includes a conventions compliance check.

## Dev Commands

```bash
# Lint + type check + test
ruff format --check . && ruff check . && mypy src/ && pytest

# Test with coverage
pytest --cov=roustabout --cov-branch --cov-report=term-missing

# Single module
pytest tests/test_{module}.py
```

## Key Files

- `pyproject.toml` — dependencies, tool config, entry points
- `src/roustabout/models.py` — all data models (start here to understand the domain)
- `src/roustabout/auditor.py` — 18 security checks (pattern for new checks)
- `tests/conftest.py` — shared mock Docker fixtures
- `~/featurecreep/docs/roustabout/` — architecture, BRD, LLDs, dev guidelines (private)
